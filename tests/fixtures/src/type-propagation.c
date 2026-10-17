/* SPDX-License-Identifier: Apache-2.0; original typing fixture, never executed. */
struct PropState { int gain; int bias; };

struct PropState prop_global = { 3, 5 };

__attribute__((noinline)) int prop_sink(void *opaque, int value)
{
    int *fields = opaque;
    return fields[0] * value + fields[1];
}

__attribute__((noinline)) int prop_caller(void *opaque, int value)
{
    return prop_sink(opaque, value) + 1;
}

__attribute__((noinline)) int prop_wrapper(void *opaque, int value)
{
    return prop_caller(opaque, value) + 2;
}

__attribute__((noinline)) void *prop_factory(void *opaque)
{
    __asm__ volatile ("" : "+r" (opaque) : : "memory");
    return opaque;
}

__attribute__((noinline)) void *prop_return_caller(void *opaque)
{
    return prop_factory(opaque);
}

__attribute__((noinline)) int prop_global_caller(int value)
{
    return prop_sink(&prop_global, value);
}
