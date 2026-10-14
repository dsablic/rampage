#include <stdio.h>

_Static_assert(sizeof(signed char) == 1, "The fixture needs an 8-bit char");
_Static_assert(sizeof(short) == 2, "The fixture needs a 16-bit short");
_Static_assert(sizeof(int) == 4, "The fixture needs a 32-bit int");
_Static_assert(sizeof(unsigned long) == 8, "The fixture needs a 64-bit unsigned long");

int narrow_signed_char(signed char value);
int narrow_signed_short(short value);
unsigned int narrow_unsigned_char(unsigned char value);
unsigned int narrow_unsigned_short(unsigned short value);
unsigned long narrow_signed_char_u32(signed char value);
unsigned long narrow_signed_short_u32(short value);
int narrow_signed_int(int value);
unsigned int narrow_unsigned_int(unsigned int value);
long narrow_signed_long(long value);
int narrow_pair(signed char first, short second);
int narrow_fixed_stack(long a, long b, long c, long d, long e, long f, long g, long h, signed char first, short second);

#ifdef NARROW_COMPARE_DECOMPILED
int oracle_narrow_signed_char(signed char value);
int oracle_narrow_signed_short(short value);
unsigned int oracle_narrow_unsigned_char(unsigned char value);
unsigned int oracle_narrow_unsigned_short(unsigned short value);
unsigned long oracle_narrow_signed_char_u32(signed char value);
unsigned long oracle_narrow_signed_short_u32(short value);
int oracle_narrow_signed_int(int value);
unsigned int oracle_narrow_unsigned_int(unsigned int value);
long oracle_narrow_signed_long(long value);
int oracle_narrow_pair(signed char first, short second);
int oracle_narrow_fixed_stack(
    long a, long b, long c, long d, long e, long f, long g, long h, signed char first, short second);
#define SOURCE(name) oracle_##name
#else
#define SOURCE(name) name
#endif

static int check(const char *name, long long input, long long expected, long long source, long long recovered) {
    printf("%s(%lld): expected=%lld source=%lld recovered=%lld\n", name, input, expected, source, recovered);
    if (source != expected) {
        fprintf(stderr, "Source oracle disagrees for %s(%lld)\n", name, input);
        return 1;
    }
    if (recovered != source) {
        fprintf(stderr, "Embedded-Ghidra C arithmetic disagrees for %s(%lld)\n", name, input);
        return 1;
    }
    return 0;
}

int main(void) {
    int failures = 0;
    const signed char signed_bytes[] = {-128, -127, -1, 0, 1, 127};
    const short signed_halves[] = {-32768, -32767, -129, -1, 0, 32767};
    const unsigned char unsigned_bytes[] = {0, 1, 127, 128, 255};
    const unsigned short unsigned_halves[] = {0, 1, 32767, 32768, 65535};
    const int signed_words[] = {-2147483647 - 1, -1, 0, 2147483640};
    const unsigned int unsigned_words[] = {0, 2147483647U, 2147483648U, 4294967295U};
    const long signed_wides[] = {-9223372036854775807L - 1, -1, 0, 9223372036854775800L};

    for (size_t index = 0; index < sizeof(signed_bytes) / sizeof(signed_bytes[0]); ++index) {
        signed char value = signed_bytes[index];
        failures += check("narrow_signed_char", value, (long long)value + 7,
            SOURCE(narrow_signed_char)(value), narrow_signed_char(value));
        unsigned long expected_u32 = value < 0 ? (unsigned long)(4294967296LL + value) : (unsigned long)value;
        failures += check("narrow_signed_char_u32", value, expected_u32,
            SOURCE(narrow_signed_char_u32)(value), narrow_signed_char_u32(value));
    }
    for (size_t index = 0; index < sizeof(signed_halves) / sizeof(signed_halves[0]); ++index) {
        short value = signed_halves[index];
        failures += check("narrow_signed_short", value, (long long)value + 7,
            SOURCE(narrow_signed_short)(value), narrow_signed_short(value));
        unsigned long expected_u32 = value < 0 ? (unsigned long)(4294967296LL + value) : (unsigned long)value;
        failures += check("narrow_signed_short_u32", value, expected_u32,
            SOURCE(narrow_signed_short_u32)(value), narrow_signed_short_u32(value));
    }
    for (size_t index = 0; index < sizeof(unsigned_bytes) / sizeof(unsigned_bytes[0]); ++index) {
        unsigned char value = unsigned_bytes[index];
        failures += check("narrow_unsigned_char", value, (long long)value + 7,
            SOURCE(narrow_unsigned_char)(value), narrow_unsigned_char(value));
    }
    for (size_t index = 0; index < sizeof(unsigned_halves) / sizeof(unsigned_halves[0]); ++index) {
        unsigned short value = unsigned_halves[index];
        failures += check("narrow_unsigned_short", value, (long long)value + 7,
            SOURCE(narrow_unsigned_short)(value), narrow_unsigned_short(value));
    }
    for (size_t index = 0; index < sizeof(signed_words) / sizeof(signed_words[0]); ++index) {
        int value = signed_words[index];
        failures += check("narrow_signed_int", value, (long long)value + 7,
            SOURCE(narrow_signed_int)(value), narrow_signed_int(value));
    }
    for (size_t index = 0; index < sizeof(unsigned_words) / sizeof(unsigned_words[0]); ++index) {
        unsigned int value = unsigned_words[index];
        long long expected = ((unsigned long long)value + 7) % 4294967296ULL;
        failures += check("narrow_unsigned_int", value, expected,
            SOURCE(narrow_unsigned_int)(value), narrow_unsigned_int(value));
    }
    for (size_t index = 0; index < sizeof(signed_wides) / sizeof(signed_wides[0]); ++index) {
        long value = signed_wides[index];
        failures += check("narrow_signed_long", value, (long long)value + 7,
            SOURCE(narrow_signed_long)(value), narrow_signed_long(value));
    }
    for (size_t index = 0; index < sizeof(signed_bytes) / sizeof(signed_bytes[0]); ++index) {
        signed char first = signed_bytes[index];
        short second = signed_halves[index];
        long long expected = (long long)first + second;
        failures += check("narrow_pair", first, expected,
            SOURCE(narrow_pair)(first, second), narrow_pair(first, second));
        failures += check("narrow_fixed_stack", first, expected,
            SOURCE(narrow_fixed_stack)(0, 0, 0, 0, 0, 0, 0, 0, first, second),
            narrow_fixed_stack(0, 0, 0, 0, 0, 0, 0, 0, first, second));
    }
    return failures == 0 ? 0 : 1;
}
