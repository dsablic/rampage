// SPDX-License-Identifier: Apache-2.0
// The second translation unit of the debug correlation fixture: another static `helper`, and the entry point.

int caller(int x);
const char *greet(void);

__attribute__((noinline, used)) static int helper(int x) { return x - 7; }

__attribute__((noinline)) int use_b(int x) { return helper(x); }

__attribute__((noreturn)) void _start(void) {
  volatile int sink = caller(1) + use_b(2) + greet()[0];
  (void)sink;
  for (;;) {
  }
}
