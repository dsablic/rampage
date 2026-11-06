// SPDX-License-Identifier: Apache-2.0
// Suite-v2 benchmark fixture: bare-metal Cortex-M3 firmware (lm3s6965-style memory map) shipped as a raw flash
// image loaded at 0x0, with no header. The reset handler configures a GPIO port through two helpers, then spins.
// The task asks for the reset handler's address and the ordered 32-bit peripheral stores it performs.
#include <stdint.h>

#define REG(address) (*(volatile uint32_t *)(address))

extern uint32_t __stack_top;

__attribute__((noreturn)) void fault_handler(void) {
    for (;;) {
    }
}

__attribute__((noinline)) void clock_enable(void) {
    REG(0x400FE108u) = 0x00000020u; /* RCGC2: port F clock */
    REG(0x400FE060u) = 0x078E3AD1u; /* RCC: oscillator and PLL configuration */
}

__attribute__((noinline)) void gpio_setup(void) {
    REG(0x40025400u) = 0x0000000Eu; /* GPIODIR */
    REG(0x4002551Cu) = 0x0000001Fu; /* GPIODEN */
    REG(0x40025038u) = 0x00000004u; /* GPIODATA, masked */
}

__attribute__((noinline)) void idle(void) {
    __asm__ volatile("wfi");
}

__attribute__((noreturn)) void reset_handler(void) {
    clock_enable();
    REG(0xE000E010u) = 0x00000000u; /* SysTick off (system space, not peripheral space) */
    gpio_setup();
    for (;;) {
        idle();
    }
}

__attribute__((section(".vectors"), used)) void *const vector_table[16] = {
    &__stack_top,  reset_handler, fault_handler, fault_handler, fault_handler, fault_handler,
    fault_handler, 0,             0,             0,             0,             fault_handler,
    fault_handler, 0,             fault_handler, fault_handler,
};
