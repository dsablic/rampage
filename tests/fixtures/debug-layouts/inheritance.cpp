/* SPDX-License-Identifier: Apache-2.0 */
struct __attribute__((aligned(8))) debug_base {
    int first;
};

struct __attribute__((aligned(8))) debug_inherited : debug_base {
    int tail;
};

struct __attribute__((aligned(8))) debug_virtual : virtual debug_base {
    int tail;
};

extern "C" __attribute__((noinline)) int debug_inherited_read(debug_inherited *item) {
    return item->first;
}

extern "C" __attribute__((noinline)) int debug_virtual_read(debug_virtual *item) {
    return item->first;
}
