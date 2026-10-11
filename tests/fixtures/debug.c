typedef unsigned long long counter_t;
typedef char character_t;

__attribute__((noinline))
counter_t debug_mix(counter_t total, const character_t *message, int delta, double ratio) {
    return total + (counter_t)message[0] + (counter_t)delta + (counter_t)ratio;
}

__attribute__((noinline))
void debug_reset(void *context, volatile unsigned short *flag) {
    *flag = context != 0;
}

__attribute__((noinline))
_Bool debug_scalars(signed char small, unsigned char byte, short half, unsigned int word, float fraction) {
    return small + byte + half + word + fraction != 0;
}

__attribute__((noinline))
int debug_variadic(const char *format, ...) {
    return format[0];
}

struct debug_pair {
    int first;
    int second;
};

__attribute__((noinline))
int debug_aggregate(struct debug_pair pair) {
    return pair.first + pair.second;
}

__attribute__((noinline))
int debug_aggregate_pointer(struct debug_pair *pair) {
    return pair->first;
}

__attribute__((noinline))
int debug_callback(int (*callback)(int), int value) {
    return callback(value);
}

__attribute__((noinline))
int debug_nested_pointer(int **value) {
    return **value;
}

__attribute__((noinline))
long double debug_extended_float(long double value) {
    return value;
}

int main(void) {
    return (int)debug_mix(1, "debug", 2, 3.0);
}
