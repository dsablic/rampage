/* Modified from mingw-w64 v12.0.0 on 2026-10-17: bounded native-parser declarations.
 * See provenance.json, LICENSE.mingw-w64 and DISCLAIMER.PD.mingw-w64.
 */
typedef void *HANDLE;
typedef uint4 DWORD;
typedef int4 BOOL;
typedef uint2 WCHAR;
typedef int4 LONG;
typedef int8 LONGLONG;
typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG HighPart;
    } u;
    LONGLONG QuadPart;
} LARGE_INTEGER;
