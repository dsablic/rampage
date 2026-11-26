/* SPDX-License-Identifier: Apache-2.0 */
/* The archive fixtures' second member: defines what objects.c leaves undefined. */
int ext_counter = 3;

void hal_init(int pin, int mode) {
    ext_counter += pin * mode;
}
