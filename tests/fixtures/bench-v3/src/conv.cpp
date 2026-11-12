// SPDX-License-Identifier: Apache-2.0
// Suite v3, 32-bit x86 calling conventions: C functions declared cdecl, stdcall and fastcall, one call site with
// distinct constant arguments, and a C++ member function (thiscall on 32-bit Windows). Every parameter is a
// 32-bit integer. The host build ignores the convention attributes and prints the arguments each callee received.
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#if defined(__i386__)
#define CDECL __attribute__((cdecl))
#define STDCALL __attribute__((stdcall))
#define FASTCALL __attribute__((fastcall))
#else
#define CDECL
#define STDCALL
#define FASTCALL
#endif
#define NOINLINE __attribute__((noinline))

extern "C" {

volatile uint32_t sink;

NOINLINE int CDECL blend_three(int a, int b, int c) {
    return (a ^ (b << 3)) + c * 5;
}

NOINLINE int STDCALL clamp_three(int a, int b, int c) {
    int low = b < c ? b : c;
    return a < low ? low : a - low;
}

NOINLINE int FASTCALL pack_three(int a, int b, int c) {
    return (a << 16) | ((b & 0xFF) << 8) | (c & 0xFF);
}

NOINLINE int CDECL weigh_four(int a, int b, int c, int d) {
    return a * 2 + b * 3 + c * 5 + d * 7;
}

NOINLINE int STDCALL select_four(int a, int b, int c, int d) {
    return (a & 1) ? b - d : c + d;
}

NOINLINE int FASTCALL rotate_four(int a, int b, int c, int d) {
    uint32_t value = (uint32_t)a ^ (uint32_t)d;
    return (int)((value << (b & 31)) | (value >> ((32 - b) & 31))) + c;
}

NOINLINE int FASTCALL record_five(int a, int b, int c, int d, int e) {
    printf("record_five %d %d %d %d %d\n", a, b, c, d, e);
    return a + b - c + d - e;
}

NOINLINE int STDCALL record_three(int a, int b, int c) {
    printf("record_three %d %d %d\n", a, b, c);
    return a - b + c;
}

NOINLINE int submit(void) {
    int first = record_five(0x51, 0x1F, 0x300, 0x7, 0xBEE);
    return record_three(0x2A, first, 0x64) + 1;
}

} // extern "C"

class Mixer {
  public:
    explicit Mixer(int seed) : level_(seed), calls_(0) {}
    NOINLINE int blend(int left, int right, int bias);
    NOINLINE int level() const;

  private:
    int level_;
    int calls_;
};

int Mixer::blend(int left, int right, int bias) {
    calls_++;
    level_ = (level_ * 3 + left - right) ^ bias;
    return level_ + calls_;
}

int Mixer::level() const {
    return level_ - calls_;
}

int main(int argc, char **argv) {
    int seed = argc > 1 ? atoi(argv[1]) : 3;
    Mixer mixer(seed);
    sink = (uint32_t)blend_three(seed, 2, 3);
    sink = (uint32_t)clamp_three(seed, 4, 5);
    sink = (uint32_t)pack_three(seed, 6, 7);
    sink = (uint32_t)weigh_four(seed, 8, 9, 10);
    sink = (uint32_t)select_four(seed, 11, 12, 13);
    sink = (uint32_t)rotate_four(seed, 14, 15, 16);
    sink = (uint32_t)mixer.blend(seed, 21, 22);
    sink = (uint32_t)mixer.level();
    printf("%d\n", submit());
    return 0;
}
