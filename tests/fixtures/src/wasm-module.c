/* A tiny WebAssembly module for the wasm_module tests: two host imports, exported functions and an exported memory.
 * Built by build-formats.sh; the linker writes the name section and clang the producers section. */
__attribute__((import_module("env"), import_name("log"))) void host_log(int value);
__attribute__((import_module("env"), import_name("now"))) long long host_now(void);

static int counter;

__attribute__((export_name("add"))) int add(int a, int b) {
    return a + b;
}

__attribute__((export_name("tick"))) int tick(void) {
    counter += (int)host_now();
    host_log(counter);
    return counter;
}
