/* A shared library whose exported entry point calls another exported function through the PLT. */
__attribute__((noinline)) int helper(int x) { return x * 3; }
int entry_point(int x) { return helper(x) + 1; }
