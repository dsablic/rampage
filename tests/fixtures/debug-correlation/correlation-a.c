// SPDX-License-Identifier: Apache-2.0
// Static side of the debug correlation tests: a freestanding x86-64 PIE with a GNU build ID. `caller` calls
// `leaf` (a call to step over), `greeting` is a string a register can point at, and `helper` exists twice (here and
// in correlation-b.c, both static) so a breakpoint by that name is ambiguous.

const char greeting[] = "rampage correlation fixture";

__attribute__((noinline, used)) static int helper(int x) { return x * 3; }

__attribute__((noinline)) int leaf(int x) { return x + 1; }

__attribute__((noinline)) int caller(int x) { return leaf(x) + helper(x); }

__attribute__((noinline)) const char *greet(void) { return greeting; }
