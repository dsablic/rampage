// SPDX-License-Identifier: Apache-2.0
// A Windows program with a hand-written load configuration directory: the linker publishes `_load_config_used`
// as IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG. The tables hold made-up RVAs; only their placement and counts matter.
#include <stddef.h>
#include <windows.h>

static UINT_PTR cookie = (UINT_PTR)0x2B992DDFA232ULL;
static DWORD cfg_functions[3] = {0x1000, 0x1010, 0x1020};
static DWORD longjump_targets[1] = {0x1030};
static DWORD eh_continuations[2] = {0x1040, 0x1050};
#ifndef _WIN64
static DWORD seh_handlers[2] = {0x1060, 0x1070};
#endif
static void guard_check(void) {}
static void guard_dispatch(void) {}
static void (*guard_check_pointer)(void) = guard_check;
static void (*guard_dispatch_pointer)(void) = guard_dispatch;

#ifdef _WIN64
const IMAGE_LOAD_CONFIG_DIRECTORY64 _load_config_used = {
    .Size = sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64),
#else
// The 32-bit directory declares a Size that stops after GuardFlags, so the later fields are absent.
const IMAGE_LOAD_CONFIG_DIRECTORY32 _load_config_used = {
    .Size = offsetof(IMAGE_LOAD_CONFIG_DIRECTORY32, CodeIntegrity),
    .SEHandlerTable = (UINT_PTR)seh_handlers,
    .SEHandlerCount = 2,
#endif
    .SecurityCookie = (UINT_PTR)&cookie,
    .GuardCFCheckFunctionPointer = (UINT_PTR)&guard_check_pointer,
    .GuardCFDispatchFunctionPointer = (UINT_PTR)&guard_dispatch_pointer,
    .GuardCFFunctionTable = (UINT_PTR)cfg_functions,
    .GuardCFFunctionCount = 3,
    // CF_INSTRUMENTED | CF_FUNCTION_TABLE_PRESENT | CF_LONGJUMP_TABLE_PRESENT | EH_CONTINUATION_TABLE_PRESENT;
    // mingw-w64's winnt.h lacks the newer names.
    .GuardFlags = 0x00000100 | 0x00000400 | 0x00010000 | 0x00400000,
    .GuardLongJumpTargetTable = (UINT_PTR)longjump_targets,
    .GuardLongJumpTargetCount = 1,
#ifdef _WIN64
    .GuardEHContinuationTable = (UINT_PTR)eh_continuations,
    .GuardEHContinuationCount = 2,
#endif
};

int main(void) { return (int)(cookie & 1) + (int)eh_continuations[0] - 0x1040; }
