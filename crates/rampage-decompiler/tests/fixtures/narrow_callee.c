#ifdef NARROW_ORACLE
#define NARROW_NAME(name) oracle_##name
#else
#define NARROW_NAME(name) name
#endif

__attribute__((noinline)) int NARROW_NAME(narrow_signed_char)(signed char value) {
    return value + 7;
}

__attribute__((noinline)) int NARROW_NAME(narrow_signed_short)(short value) {
    return value + 7;
}

__attribute__((noinline)) unsigned int NARROW_NAME(narrow_unsigned_char)(unsigned char value) {
    return (unsigned int)value + 7;
}

__attribute__((noinline)) unsigned int NARROW_NAME(narrow_unsigned_short)(unsigned short value) {
    return (unsigned int)value + 7;
}

__attribute__((noinline)) unsigned long NARROW_NAME(narrow_signed_char_u32)(signed char value) {
    return (unsigned int)value;
}

__attribute__((noinline)) unsigned long NARROW_NAME(narrow_signed_short_u32)(short value) {
    return (unsigned int)value;
}

__attribute__((noinline)) int NARROW_NAME(narrow_signed_int)(int value) {
    return value + 7;
}

__attribute__((noinline)) unsigned int NARROW_NAME(narrow_unsigned_int)(unsigned int value) {
    return value + 7;
}

__attribute__((noinline)) long NARROW_NAME(narrow_signed_long)(long value) {
    return value + 7;
}

__attribute__((noinline)) int NARROW_NAME(narrow_pair)(signed char first, short second) {
    return first + second;
}

__attribute__((noinline)) int NARROW_NAME(narrow_fixed_stack)(
    long a, long b, long c, long d, long e, long f, long g, long h, signed char first, short second) {
    return first + second;
}
