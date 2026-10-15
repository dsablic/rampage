/* SPDX-License-Identifier: Apache-2.0 */
__attribute__((noreturn)) void entry(void) {
    for (;;) {
        __asm__ volatile("" ::: "memory");
    }
}
