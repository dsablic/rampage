/* Type-recovery corpus: functions with varied C signatures, built with -g so DWARF is the truth for the
 * signatures the decompiler infers on a stripped copy. Every function is external and noinline, and main feeds
 * them volatile inputs, so the compiler keeps each one's ABI instead of folding constants into it. */
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#define KEEP __attribute__((noinline))

struct point { int x; int y; };
struct node { struct node *next; long value; };
struct pair { int first; int second; };
struct big { long a; long b; long c; long d; };
enum color { RED, GREEN, BLUE };

KEEP int8_t t_i8(int8_t a) { return (int8_t)(a * 3 - 1); }
KEEP uint8_t t_u8(uint8_t a, uint8_t b) { return (uint8_t)(a ^ (b << 1)); }
KEEP int16_t t_i16(int16_t a) { return (int16_t)(a / 7); }
KEEP uint16_t t_u16(uint16_t a, uint16_t b) { return (uint16_t)(a * b + 3); }
KEEP int32_t t_i32(int32_t a, int32_t b, int32_t c) { return a * b - c; }
KEEP uint32_t t_u32(uint32_t a) { return a >> 3 | a << 29; }
KEEP int64_t t_i64(int64_t a, int64_t b) { return a / (b | 1); }
KEEP uint64_t t_u64(uint64_t a, uint32_t shift) { return a >> (shift & 63); }
KEEP _Bool t_bool(int a, int b) { return a < b; }
KEEP int t_mixed(char a, short b, int c, long long d) { return a + b * 2 + c * 3 + (int)(d >> 4); }
KEEP long t_many(long a, long b, long c, long d, long e, long f, long g, long h) {
    return a - b + c * d - e + f * g - h;
}
KEEP int t_ignore(int used, int unused) { return used * 5 + 1; }
KEEP enum color t_next_color(enum color c) { return (enum color)((c + 1) % 3); }

KEEP int t_deref(const int *p) { return p[0] + p[1]; }
KEEP void t_store(long *p, long v) { p[2] = v * 9; }
KEEP char *t_strchr(char *s, int c) {
    while (*s && *s != (char)c) s++;
    return *s ? s : NULL;
}
KEEP size_t t_strlen(const char *s) {
    const char *e = s;
    while (*e) e++;
    return (size_t)(e - s);
}
KEEP void *t_pick(void *a, void *b, int which) { return which ? a : b; }
KEEP int t_apply(int (*f)(int), int x) { return f(x) + 1; }
KEEP int t_increment(int x) { return x + 1; }

KEEP int t_point_sum(struct point *p) { return p->x + p->y; }
KEEP void t_point_init(struct point *p, int x, int y) {
    p->x = x;
    p->y = y;
}
KEEP struct node *t_next(struct node *n) { return n ? n->next : NULL; }
KEEP long t_list_sum(const struct node *n) {
    long total = 0;
    for (; n; n = n->next) total += n->value;
    return total;
}

KEEP float t_scale(float x, float y) { return x * y + 0.5f; }
KEEP double t_mix(double a, int b, double c) { return a * b + c; }
KEEP double t_poly(double x) { return ((x * 3.0 + 2.0) * x - 1.0) * x; }
KEEP float t_to_float(int x) { return (float)x / 3.0f; }
KEEP int t_round(double x) { return (int)(x + 0.5); }
KEEP void t_store_double(double *p, double v) { *p = v * 2.0; }
/* Negation only: other long double arithmetic is a compiler_rt call on aarch64, which -nostdlib omits. */
KEEP long double t_extended(long double x) { return -x; }

KEEP int t_sum_ints(int n, ...) {
    va_list args;
    va_start(args, n);
    int total = 0;
    for (int i = 0; i < n; i++) total += va_arg(args, int);
    va_end(args);
    return total;
}
KEEP double t_average(int n, ...) {
    va_list args;
    va_start(args, n);
    double total = 0;
    for (int i = 0; i < n; i++) total += va_arg(args, double);
    va_end(args);
    return n ? total / n : 0;
}

KEEP void t_clear(int *p, int n) {
    for (int i = 0; i < n; i++) p[i] = 0;
}
KEEP void t_flag(volatile int *flag) { *flag = 1; }

KEEP int t_pair_sum(struct pair p) { return p.first + p.second; }
KEEP struct pair t_make_pair(int a, int b) {
    struct pair p = {a * 2, b * 3};
    return p;
}
KEEP long t_big_sum(struct big b) { return b.a + b.b + b.c + b.d; }

volatile long sink;
volatile int vi = 3;
volatile double vd = 1.5;
volatile long double vld = 2.5L, vld_out;

int main(void) {
    int values[4] = {vi, vi + 1, vi + 2, vi + 3};
    long longs[4] = {0};
    char text[] = "types corpus";
    struct point point;
    struct node second = {NULL, vi}, first = {&second, vi * 2};
    struct big big = {vi, vi, vi, vi};
    double d;
    sink += t_i8((int8_t)vi) + t_u8((uint8_t)vi, (uint8_t)vi) + t_i16((int16_t)vi) + t_u16((uint16_t)vi, 2);
    sink += t_i32(vi, vi, vi) + t_u32((uint32_t)vi) + t_i64(vi, vi) + (long)t_u64((uint64_t)vi, (uint32_t)vi);
    sink += t_bool(vi, 4) + t_mixed((char)vi, (short)vi, vi, vi) + t_many(vi, vi, vi, vi, vi, vi, vi, vi);
    sink += t_ignore(vi, vi) + t_next_color((enum color)(vi % 3));
    sink += t_deref(values);
    t_store(longs, vi);
    sink += longs[2] + (long)t_strchr(text, vi + 'a') + (long)t_strlen(text) + (long)t_pick(text, values, vi);
    sink += t_apply(t_increment, vi);
    t_point_init(&point, vi, vi);
    sink += t_point_sum(&point) + (long)t_next(&first) + t_list_sum(&first);
    sink += (long)t_scale((float)vd, 2.0f) + (long)t_mix(vd, vi, vd) + (long)t_poly(vd) + (long)t_to_float(vi);
    sink += t_round(vd);
    t_store_double(&d, vd);
    sink += (long)d;
    vld_out = t_extended(vld);
    sink += t_sum_ints(3, vi, vi, vi) + (long)t_average(2, vd, vd);
    t_clear(values, vi);
    t_flag(&vi);
    struct pair pair = t_make_pair(vi, vi);
    sink += t_pair_sum(pair) + t_big_sum(big);
    return (int)sink;
}
