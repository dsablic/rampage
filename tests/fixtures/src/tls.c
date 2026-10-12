#include <stdio.h>
#include <windows.h>

static int tls_ran = 0;

// A TLS callback runs before main on thread attach, so static discovery from the entry point misses it.
static void NTAPI tls_callback(PVOID handle, DWORD reason, PVOID reserved) {
    (void)handle;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        tls_ran = 1;
    }
}

#ifdef _WIN64
#pragma comment(linker, "/INCLUDE:_tls_used")
#else
#pragma comment(linker, "/INCLUDE:__tls_used")
#endif

PIMAGE_TLS_CALLBACK __crt_xl_tls_callback __attribute__((section(".CRT$XLB"), used)) = tls_callback;

int main(void) {
    printf("rampage fixture greeting %d\n", tls_ran);
    return 0;
}
