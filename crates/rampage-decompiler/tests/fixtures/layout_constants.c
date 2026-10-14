// Build centrally without a target sysroot or target execution:
// clang --target=x86_64-unknown-linux-gnu -std=c11 -ffreestanding -O2
// -c layout_constants.c -o layout_constants.o
// rust-objcopy --only-section=.rampage_layout -O binary layout_constants.o layout_constants.bin
// Set RAMPAGE_LAYOUT_CONSTANTS to the extracted section when running the ignored oracle regression.
// -ffreestanding selects Clang's resource-header stdint fallback instead of host libc headers.
// The section is exactly 47 little-endian uint32_t words (188 bytes), with no executable code or relocations.
#include "layout_flat.h"

#include <limits.h>
#include <stddef.h>

#if !defined(__x86_64__) || !defined(__ELF__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "The constant oracle requires x86_64 little-endian ELF"
#endif

_Static_assert(CHAR_BIT == 8 && CHAR_MIN < 0 && (char)-1 < 0, "byte-addressed signed char required");
_Static_assert(sizeof(void *) == 8 && sizeof(int) == 4 && sizeof(long) == 8, "LP64 required");
_Static_assert(sizeof(uint32_t) == 4 && sizeof(int32_t) == 4 && (int32_t)-1 < 0, "32-bit word/pointee required");

#define FIELD_FACTS(member, ctype) \
    offsetof(layout_flat, member), sizeof(((layout_flat *)0)->member), sizeof(ctype), _Alignof(ctype)

__attribute__((used, section(".rampage_layout"), aligned(4)))
const uint32_t rampage_layout_constants[] = {
    // 0..2: magic (bytes RLY1), format version, total word count.
    0x31594c52, 1, 47,
    // 3..4: byte width in bits, signed-char predicate.
    CHAR_BIT, (char)-1 < 0,
    // 5..10: sizeof/_Alignof pairs for void pointer, int, long.
    sizeof(void *), _Alignof(void *), sizeof(int), _Alignof(int), sizeof(long), _Alignof(long),
    // 11..18: sizeof/_Alignof pairs for uint8_t, uint16_t, uint32_t, uint64_t.
    sizeof(uint8_t), _Alignof(uint8_t), sizeof(uint16_t), _Alignof(uint16_t),
    sizeof(uint32_t), _Alignof(uint32_t), sizeof(uint64_t), _Alignof(uint64_t),
    // 19..20: complete struct size and alignment, including tail padding.
    sizeof(layout_flat), _Alignof(layout_flat),
    // Each field has offset, actual member size, C type size, C type alignment, in declaration order.
    FIELD_FACTS(tag, char),          // 21..24
    FIELD_FACTS(count, int32_t),     // 25..28
    FIELD_FACTS(flags, uint16_t),    // 29..32
    FIELD_FACTS(weight, double),     // 33..36 (actual target floating-point size/alignment)
    FIELD_FACTS(value, int32_t *),   // 37..40 (actual target pointer size/alignment)
    FIELD_FACTS(tail, uint8_t),      // 41..44
    // 45..46: actual pointed-to scalar size/alignment, not inferred from pointer width.
    sizeof(int32_t), _Alignof(int32_t),
};

_Static_assert(sizeof(rampage_layout_constants) == 188, "constant oracle format must be exactly 188 bytes");
