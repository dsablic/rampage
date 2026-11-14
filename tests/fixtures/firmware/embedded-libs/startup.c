/* SPDX-License-Identifier: Apache-2.0 */
/* Owned minimal Cortex-M startup for the embedded-libs fixtures: a vector table, data/bss initialisation and the
 * FreeRTOS port's exception handlers. */
#include <stdint.h>

extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;
extern int main(void);
#if defined(__ARM_ARCH_6M__)
/* FreeRTOS 11's ARMv6-M port installs its handlers under the CMSIS names. */
#define vPortSVCHandler SVC_Handler
#define xPortPendSVHandler PendSV_Handler
#define xPortSysTickHandler SysTick_Handler
#endif
extern void vPortSVCHandler(void);
extern void xPortPendSVHandler(void);
extern void xPortSysTickHandler(void);
#ifdef EMBSIG_HAL
extern void SystemInit(void);
extern void TIM2_IRQHandler(void);
#endif

void Reset_Handler(void)
{
    uint32_t *source = &_sidata;
    for (uint32_t *destination = &_sdata; destination < &_edata;) {
        *destination++ = *source++;
    }
    for (uint32_t *destination = &_sbss; destination < &_ebss;) {
        *destination++ = 0;
    }
#ifdef EMBSIG_HAL
    SystemInit();
#endif
    main();
    for (;;) {
    }
}

void Default_Handler(void)
{
    for (;;) {
    }
}

__attribute__((section(".isr_vector"), used)) void (*const vectors[])(void) = {
    (void (*)(void))&_estack,
    Reset_Handler,
    Default_Handler, /* NMI */
    Default_Handler, /* HardFault */
    Default_Handler,
    Default_Handler,
    Default_Handler,
    0,
    0,
    0,
    0,
    vPortSVCHandler,
    Default_Handler,
    0,
    xPortPendSVHandler,
    xPortSysTickHandler,
#ifdef EMBSIG_HAL
    [16 + 28] = TIM2_IRQHandler,
#endif
};
