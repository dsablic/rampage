// Build centrally, not in the test: clang --target=x86_64-unknown-linux-gnu -std=c11 -ffreestanding -O2
// -fno-stack-protector
// -fno-asynchronous-unwind-tables -c layout_use.c -o layout_use.o
// rust-objcopy --only-section=.text -O binary layout_use.o layout_use.text
// Set RAMPAGE_LAYOUT_TEXT to that .text file when running the ignored field-use regression.
#include "layout_flat.h"

int32_t layout_use(layout_flat *item) {
    return item->count + *item->value + item->tail;
}
