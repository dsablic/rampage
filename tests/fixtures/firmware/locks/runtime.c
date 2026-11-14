/* SPDX-License-Identifier: Apache-2.0 */
/* The few run-time helpers the compiler calls in the freestanding firmware build. */
#include <stddef.h>
#include <stdint.h>

void __aeabi_memcpy(void *destination, const void *source, size_t size) {
    volatile uint8_t *to = destination;
    const uint8_t *from = source;
    while (size--) {
        *to++ = *from++;
    }
}

void __aeabi_memcpy4(void *destination, const void *source, size_t size) {
    __aeabi_memcpy(destination, source, size);
}

void __aeabi_memclr(void *destination, size_t size) {
    volatile uint8_t *to = destination;
    while (size--) {
        *to++ = 0;
    }
}

void __aeabi_memclr4(void *destination, size_t size) {
    __aeabi_memclr(destination, size);
}
