int narrow_signed_char(signed char value);
int narrow_signed_short(short value);
unsigned int narrow_unsigned_char(unsigned char value);
unsigned int narrow_unsigned_short(unsigned short value);
int narrow_pair(signed char first, short second);
unsigned char narrow_return_char(signed char first, short second);
int narrow_variadic(int tag, ...);

int narrow_call_signed_char(int value) {
    return narrow_signed_char((signed char)value);
}

int narrow_call_signed_short(int value) {
    return narrow_signed_short((short)value);
}

unsigned int narrow_call_unsigned_char(unsigned int value) {
    return narrow_unsigned_char((unsigned char)value);
}

unsigned int narrow_call_unsigned_short(unsigned int value) {
    return narrow_unsigned_short((unsigned short)value);
}

int narrow_call_pair(int first, int second) {
    return narrow_pair((signed char)first, (short)second);
}

int narrow_call_small_return(int first, int second) {
    return (signed char)narrow_return_char((signed char)first, (short)second);
}

int narrow_call_variadic(signed char first, unsigned short second) {
    return narrow_variadic(7, first, second);
}
