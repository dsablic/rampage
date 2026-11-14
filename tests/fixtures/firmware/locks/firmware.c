/* SPDX-License-Identifier: Apache-2.0 */
/* Owned synthetic Cortex-M3 firmware for lock_mechanisms. It runs on the made-up device described by
 * tests/fixtures/svd/lock-device.svd and holds one example of each lock-mechanism category plus negative controls
 * (see truth.json): ordinary integrity checks, identity reads, a fault handler's debugger check and crypto that
 * gates nothing must not be reported as locks. All keys are synthetic (test_keys.c and service_key below). */
#include "crypto.h"

#define REG(address) (*(volatile uint32_t *)(address))

/* ARMv7-M architectural registers */
#define SCB_CPUID REG(0xE000ED00u)
#define SCB_AIRCR REG(0xE000ED0Cu)
#define DHCSR REG(0xE000EDF0u)

/* The synthetic device */
#define FLASHC_OPTKEYR REG(0x40022008u)
#define FLASHC_SR REG(0x4002200Cu)
#define FLASHC_CR REG(0x40022010u)
#define FLASHC_OPTR REG(0x40022020u)
#define UID_WORD(i) REG(0x1FFF7A10u + 4u * (i))
#define OTP_VERCNT(i) REG(0x1FFF7800u + 4u * (i))
#define OTP_FEATURES REG(0x1FFF7810u)
#define RNG_SR REG(0x50060804u)
#define RNG_DR REG(0x50060808u)
#define SPI1_SR REG(0x40013008u)
#define SPI1_DR REG(0x4001300Cu)

struct app_header {
    uint32_t magic, version, size, reserved;
    uint8_t signature[64];
};
#define APP_SLOT 0x08020000u
#define APP_HEADER ((const struct app_header *)APP_SLOT)
#define APP_BODY ((const uint8_t *)(APP_SLOT + 0x100u))

struct pairing_record {
    uint32_t uid[3];
    uint32_t motor_serial;
};
#define PAIRING ((const struct pairing_record *)0x0801F000u)

struct config {
    uint8_t data[60];
    uint32_t crc;
};
#define CONFIG ((const struct config *)0x0801F800u)

extern const uint8_t test_p256_public_key[64];
static const uint8_t service_key[32] = "synthetic service key, tests!!";

/* A mailbox the host side of the (imaginary) service link fills before raising an interrupt. */
struct mailbox {
    uint32_t command, argument, status;
    uint8_t data[32];
};
volatile struct mailbox mailbox;
volatile uint32_t service_unlocked;
volatile uint32_t degraded_mode;
volatile uint32_t sensor_fault;
volatile uint32_t use_defaults;
volatile uint32_t calibration;
static uint8_t challenge[16];
static uint8_t log_buffer[128];
uint8_t log_digest[32];
char serial_text[25];

__attribute__((noreturn, noinline)) static void system_reset(void) {
    SCB_AIRCR = 0x05FA0004u;
    for (;;) {
    }
}

__attribute__((noreturn, noinline)) static void halt(void) {
    for (;;) {
        __asm__ volatile("wfi");
    }
}

/* Signature verification: the application slot's SHA-256, signed with ECDSA P-256. */
__attribute__((noinline)) int verify_application(void) {
    uint8_t digest[32];
    if (APP_HEADER->magic != 0x41505031u || APP_HEADER->size > 0x10000u) {
        return -1;
    }
    sha256(APP_BODY, APP_HEADER->size, digest);
    if (!p256_verify(test_p256_public_key, digest, APP_HEADER->signature)) {
        return -2;
    }
    return 0;
}

/* Anti-rollback: a thermometer-coded OTP counter with one programmed (cleared) bit per release. */
__attribute__((noinline)) int version_allowed(uint32_t version) {
    uint32_t minimum = 0;
    for (uint32_t i = 0; i < 4; i++) {
        uint32_t word = ~OTP_VERCNT(i);
        while (word) {
            minimum += word & 1u;
            word >>= 1;
        }
    }
    return version >= minimum;
}

/* Debug and readout protection: raise the protection level when it is still open. */
__attribute__((noinline)) void apply_readout_protection(void) {
    if ((FLASHC_OPTR & 0xFFu) == 0x5Au) {
        FLASHC_OPTKEYR = 0x13572468u;
        FLASHC_OPTKEYR = 0x24681357u;
        FLASHC_OPTR = (FLASHC_OPTR & ~0xFFu) | 0xA5u;
        FLASHC_CR |= 1u << 17;
        while (FLASHC_SR & 1u) {
        }
    }
}

/* Debugger detection: C_DEBUGEN in DHCSR. */
__attribute__((noinline)) int debugger_attached(void) {
    return DHCSR & 1u;
}

__attribute__((noreturn, noinline)) static void start_application(void) {
    uint32_t stack = REG(APP_SLOT + 0x100u);
    uint32_t entry = REG(APP_SLOT + 0x104u);
    __asm__ volatile("msr msp, %0" ::"r"(stack));
    ((void (*)(void))entry)();
    for (;;) {
    }
}

void boot_main(void) {
    apply_readout_protection();
    if (debugger_attached()) {
        halt();
    }
    if (verify_application() != 0) {
        system_reset();
    }
    if (!version_allowed(APP_HEADER->version)) {
        system_reset();
    }
    start_application();
}

/* Parts pairing: full power only with the motor unit recorded, together with this chip's unique ID, at pairing. */
__attribute__((noinline)) int paired_unit(uint32_t motor_serial) {
    uint32_t uid[3] = {UID_WORD(0), UID_WORD(1), UID_WORD(2)};
    return equal_bytes((const uint8_t *)uid, (const uint8_t *)PAIRING->uid, sizeof uid) &&
           motor_serial == PAIRING->motor_serial;
}

__attribute__((noinline)) void check_pairing(uint32_t motor_serial) {
    if (!paired_unit(motor_serial)) {
        degraded_mode = 1;
    }
}

/* Feature and region locks: fuse bits select the power limit and the permitted region. */
__attribute__((noinline)) uint32_t power_limit_watts(void) {
    if (OTP_FEATURES & (1u << 3)) {
        return 750;
    }
    return 250;
}

__attribute__((noinline)) int region_allowed(uint32_t region) {
    return ((OTP_FEATURES >> 8) & 0xFFu) == region;
}

/* Challenge-response: a random challenge, answered with HMAC-SHA256 under the service key, unlocks service
 * commands. */
__attribute__((noinline)) void service_challenge(volatile uint8_t *out) {
    for (int i = 0; i < 16; i += 4) {
        while (!(RNG_SR & 1u)) {
        }
        uint32_t word = RNG_DR;
        for (int k = 0; k < 4; k++) {
            challenge[i + k] = (uint8_t)(word >> (8 * k));
        }
    }
    for (int i = 0; i < 16; i++) {
        out[i] = challenge[i];
    }
}

__attribute__((noinline)) int service_unlock(const volatile uint8_t *response) {
    uint8_t expected[32], answer[32];
    for (int i = 0; i < 32; i++) {
        answer[i] = response[i];
    }
    hmac_sha256(service_key, sizeof service_key, challenge, sizeof challenge, expected);
    if (!equal_bytes(expected, answer, 32)) {
        return -1;
    }
    service_unlocked = 1;
    return 0;
}

__attribute__((noinline)) void service_write_calibration(uint32_t value) {
    if (!service_unlocked) {
        return;
    }
    calibration = value;
}

/* Negative control: a CRC-32 over the configuration block (integrity, not a lock). */
__attribute__((noinline)) void load_config(void) {
    if (crc32(CONFIG->data, sizeof CONFIG->data) != CONFIG->crc) {
        use_defaults = 1;
    }
}

/* Negative control: an ordinary sensor identity read over SPI. */
static uint8_t spi_transfer(uint8_t out) {
    SPI1_DR = out;
    while (!(SPI1_SR & 1u)) {
    }
    return (uint8_t)SPI1_DR;
}

__attribute__((noinline)) void probe_sensor(void) {
    spi_transfer(0x8F);
    if (spi_transfer(0) != 0x42) {
        sensor_fault = 1;
    }
}

/* Negative control: a running digest of the event log, which no decision depends on. */
__attribute__((noinline)) void log_event(uint8_t event) {
    static uint32_t used;
    log_buffer[used++ % sizeof log_buffer] = event;
    sha256(log_buffer, sizeof log_buffer, log_digest);
}

/* Negative control: the unique ID shown as a serial-number string. */
__attribute__((noinline)) void format_serial(void) {
    static const char digits[] = "0123456789ABCDEF";
    for (uint32_t i = 0; i < 3; i++) {
        uint32_t word = UID_WORD(i);
        for (uint32_t k = 0; k < 8; k++) {
            serial_text[8 * i + k] = digits[(word >> (28 - 4 * k)) & 0xFu];
        }
    }
    serial_text[24] = 0;
}

/* Negative control: the core's part number picks a code path. */
__attribute__((noinline)) int core_is_m4(void) {
    return ((SCB_CPUID >> 4) & 0xFFFu) == 0xC24u;
}

void systick_handler(void) {
    static uint32_t ticks;
    ticks++;
    log_event((uint8_t)ticks);
    if (core_is_m4()) {
        calibration += 2;
    } else {
        calibration += 1;
    }
}

void service_handler(void) {
    if (mailbox.command == 1) {
        service_challenge(mailbox.data);
    } else if (mailbox.command == 2) {
        mailbox.status = (uint32_t)service_unlock(mailbox.data);
    } else if (mailbox.command == 3) {
        service_write_calibration(mailbox.argument);
    }
}

void motor_handler(void) {
    check_pairing(mailbox.argument);
    mailbox.status = power_limit_watts();
    if (!region_allowed(mailbox.argument >> 16)) {
        mailbox.status = 0xE1;
    }
}

void maintenance_handler(void) {
    format_serial();
    probe_sensor();
    load_config();
}

/* Negative control: a fault handler that breaks into an attached debugger and otherwise resets. */
void hardfault_handler(void) {
    if (DHCSR & 1u) {
        __asm__ volatile("bkpt #0");
        return;
    }
    system_reset();
}

void reset_handler(void) {
    boot_main();
}

void default_handler(void) {
    for (;;) {
    }
}

extern uint32_t __stack_top;
__attribute__((section(".vectors"), used)) const void *const vectors[] = {
    &__stack_top,     reset_handler,   default_handler, hardfault_handler, default_handler,   default_handler,
    default_handler,  0,               0,               0,               0,                   default_handler,
    default_handler,  0,               default_handler, systick_handler, service_handler,     motor_handler,
    maintenance_handler,
};
