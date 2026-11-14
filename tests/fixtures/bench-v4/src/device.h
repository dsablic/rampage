/* SPDX-License-Identifier: Apache-2.0 */
/* Register access for the suite-v4 Cortex-M fixtures (the made-up BENCHM4 device of ../companions/benchm4.svd).
 *
 * On the target, RD/WR are plain volatile 32-bit accesses. Built for the host with -DHOST (the truth harness in
 * tools/agent-bench/v4/derive-truth.py), they call host_read/host_write, which the harness defines to record every
 * access in program order and to answer reads; nothing else in the firmware sources differs between the builds. */
#ifndef BENCH_V4_DEVICE_H
#define BENCH_V4_DEVICE_H
#include <stdint.h>

#ifdef HOST
uint32_t host_read(uint32_t address);
void host_write(uint32_t address, uint32_t value);
#define RD(address) host_read(address)
#define WR(address, value) host_write((address), (uint32_t)(value))
#define HALT() return
#define NOINLINE __attribute__((noinline))
#else
#define RD(address) (*(volatile uint32_t *)(uintptr_t)(address))
#define WR(address, value) (*(volatile uint32_t *)(uintptr_t)(address) = (uint32_t)(value))
#define HALT()                                                                                                       \
  for (;;) {                                                                                                         \
    __asm__ volatile("wfi");                                                                                         \
  }
#define NOINLINE __attribute__((noinline))
#endif

#define CLKCTRL_ENR 0x40000000u
#define CLKCTRL_DIV 0x40000004u
#define CLKCTRL_STAT 0x40000008u
#define GPIOA_MODE 0x40001000u
#define GPIOA_OUT 0x40001004u
#define GPIOA_SET 0x4000100Cu
#define GPIOA_CLR 0x40001010u
#define GPIOB_MODE 0x40001400u
#define GPIOB_OUT 0x40001404u
#define GPIOB_IN 0x40001408u
#define UART0_CTRL 0x40002000u
#define UART0_BAUD 0x40002004u
#define UART0_STATUS 0x40002008u
#define UART0_DATA 0x4000200Cu
#define TIMER0_CTRL 0x40003000u
#define TIMER0_LOAD 0x40003004u
#define TIMER0_COUNT 0x40003008u
#define TIMER1_CTRL 0x40003400u
#define TIMER1_LOAD 0x40003404u
#define TIMER1_COUNT 0x40003408u
#define TIMER1_INTCLR 0x4000340Cu
#define WDOG_KEY 0x40004000u
#define WDOG_RELOAD 0x40004004u
#define WDOG_CTRL 0x40004008u
#define OTP_STATUS 0x40009000u
#define OTP_MINVER 0x40009010u
#define OTP_SERIAL 0x40009014u
#define UID_UID0 0x1FFF7000u
#define UID_UID1 0x1FFF7004u
#define UID_UID2 0x1FFF7008u
/* Architectural: the Application Interrupt and Reset Control Register. */
#define SCB_AIRCR 0xE000ED0Cu

#endif
