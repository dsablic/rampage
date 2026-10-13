//! Functions known by name never to return to their caller.

use rampage_loaders::Binary;

use crate::discover::ReturnFacts;

use crate::functions::{stub_names, thunk_names};
use crate::language::demangle;

/// Symbol and import names of callees that never return, matched case-sensitively once import decoration is
/// dropped (`__imp_`, an `@` suffix such as `@plt`, `@GLIBC_2.2.5` or stdcall's `@4`, Go's `.abi0`), as written or
/// with the one leading underscore Mach-O and 32-bit Windows add (`_exit` names `exit`, `___stack_chk_fail` names
/// `__stack_chk_fail`). A trailing `*` matches by prefix, but never into a nested item: Go closures
/// (`runtime.gopanic.func1`) return normally.
///
/// Every entry is documented never to return to its caller: C11/POSIX (`exit`, `_Exit`, `abort`, `quick_exit`,
/// `longjmp`, `pthread_exit`), glibc/musl/Apple `<assert.h>` and fortify/stack-protector handlers, the Itanium C++
/// ABI and libunwind, Microsoft's Win32/CRT docs (`ExitProcess`, `ExitThread`, `FreeLibraryAndExitThread`,
/// `_CxxThrowException`, `__report_gsfailure`, `_invalid_parameter_noinfo_noreturn`), Objective-C
/// `objc_exception_throw`, Rust's panic entry points, and the Go runtime functions that `throw`, `panic` or end the
/// goroutine. Ghidra's `*FunctionsThatDoNotReturn` lists served as a cross-check; entries that can return are left
/// out on purpose: `RaiseException`, `TerminateProcess` on another process, `FatalExit` and `FatalAppExit` (both
/// hand control to an attached debugger, which may resume), `reboot`, Go `panicCheck1`/`panicCheck2`, Rust
/// `__rust_start_panic`.
const NORETURN: &[&str] = &[
    // C and POSIX.
    "exit",
    "_exit",
    "_Exit",
    "abort",
    "quick_exit",
    "thrd_exit",
    "pthread_exit",
    "longjmp",
    "_longjmp",
    "siglongjmp",
    "__longjmp_chk",
    "__libc_longjmp",
    "__libc_siglongjmp",
    "__assert_fail",
    "__assert_perror_fail",
    "__assert_rtn",
    "__stack_chk_fail",
    "__stack_chk_fail_local",
    "__fortify_fail",
    "__chk_fail",
    "__libc_fatal",
    // C++ runtime (Itanium ABI, libstdc++, libc++abi) and unwinding.
    "__cxa_throw",
    "__cxa_rethrow",
    "__cxa_bad_cast",
    "__cxa_bad_typeid",
    "__cxa_throw_bad_array_new_length",
    "__cxa_pure_virtual",
    "__cxa_deleted_virtual",
    "__cxa_call_unexpected",
    "_Unwind_Resume",
    "objc_exception_throw",
    "objc_exception_rethrow",
    // Windows API and the Microsoft CRT.
    "ExitProcess",
    "ExitThread",
    "FreeLibraryAndExitThread",
    "RtlExitUserProcess",
    "RtlExitUserThread",
    "_CxxThrowException",
    "__report_gsfailure",
    "__report_rangecheckfailure",
    "_invalid_parameter_noinfo_noreturn",
    "_invoke_watson",
    // Rust's unmangled panic and allocation-failure entry points.
    "rust_begin_unwind",
    "__rust_drop_panic",
    "__rust_foreign_exception",
    "__rg_oom",
    // Go.
    "runtime.throw",
    "runtime.fatal",
    "runtime.fatalthrow",
    "runtime.fatalpanic",
    "runtime.abort",
    "runtime.exit",
    "runtime.exitThread",
    "runtime.dieFromSignal",
    "runtime.goexit",
    "runtime.goexit0",
    "runtime.goexit1",
    "runtime.gopanic",
    "runtime.goPanic*",
    "runtime.panicIndex*",
    "runtime.panicSlice*",
    "runtime.panicExtend*",
    "runtime.panicunsafe*",
    "runtime.panicdottype*",
    "runtime.panicmakeslice*",
    "runtime.panicdivide",
    "runtime.panicshift",
    "runtime.panicmem",
    "runtime.panicmemAddr",
    "runtime.panicnildottype",
    "runtime.panicoverflow",
    "runtime.panicfloat",
    "runtime.panicunaligned",
    "runtime.panicwrap",
    "runtime.panicrangestate",
];

/// Names that count only as imports, because a program's own function of that name may well return: MSVC's CRT
/// `terminate` and BSD `err(3)`.
const NORETURN_IMPORTS: &[&str] = &["terminate", "err", "errx", "verr", "verrx"];

/// Demangled C++ and Rust qualified names, without parameters. MSVC's `std::terminate` is the global
/// `::terminate`, which counts only when MSVC-mangled (`?terminate@@YAXXZ`).
const NORETURN_DEMANGLED: &[&str] = &[
    "std::terminate",
    "std::__terminate",
    "__cxxabiv1::__terminate",
    "std::__throw_*",
    "core::panicking::*",
    "core::option::unwrap_failed",
    "core::option::expect_failed",
    "core::result::unwrap_failed",
    "std::process::exit",
    "std::process::abort",
    "std::panicking::begin_panic",
    "std::panicking::rust_panic_with_hook",
    "std::alloc::rust_oom",
    "alloc::alloc::handle_alloc_error",
    "alloc::raw_vec::capacity_overflow",
    "alloc::raw_vec::handle_error",
];

/// Functions whose every path ends in a noreturn call or a trap, which nevertheless resume their caller: Go's
/// `mcall` switches to the scheduler stack and its caller continues when `gogo` restores the context `mcall` saved,
/// and `morestack` resumes the function that called it, from its start, on a larger stack.
const RETURNS_THROUGH_SAVED_CONTEXT: &[&str] = &["runtime.mcall", "runtime.morestack", "runtime.morestack_noctxt"];

/// Whether the raw symbol `name` is a function [`NORETURN`] or [`NORETURN_DEMANGLED`] lists.
pub fn is_noreturn_name(name: &str) -> bool {
    listed(NORETURN, name) || demangled_listed(name)
}

/// Whether the import (slot, stub or thunk) `name` never returns: as [`is_noreturn_name`], or [`NORETURN_IMPORTS`].
pub fn is_noreturn_import(name: &str) -> bool {
    is_noreturn_name(name) || listed(NORETURN_IMPORTS, name)
}

/// `name` without import decoration: `__imp_`, an `@` suffix (except in MSVC-mangled names) and Go's `.abi0`.
fn undecorated(name: &str) -> &str {
    let name = name.strip_prefix("__imp_").or_else(|| name.strip_prefix("_imp__")).unwrap_or(name);
    let name = if name.starts_with('?') { name } else { name.split('@').next().unwrap_or(name) };
    name.strip_suffix(".abi0").unwrap_or(name)
}

fn listed(table: &[&str], name: &str) -> bool {
    let name = undecorated(name);
    std::iter::once(name).chain(name.strip_prefix('_')).any(|name| table.iter().any(|&pattern| matches(pattern, name)))
}

fn demangled_listed(name: &str) -> bool {
    let Some(display) = demangle(name) else { return false };
    let qualified = display.split('(').next().unwrap_or_default();
    NORETURN_DEMANGLED.iter().any(|&pattern| matches(pattern, qualified))
        || name.starts_with('?') && qualified == "terminate"
}

fn matches(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == ':')),
        None => name == pattern,
    }
}

/// The functions, import stubs and thunks, and import slots in `binary` whose names say whether they return: the
/// ones [`is_noreturn_name`] (or, for imports, [`is_noreturn_import`]) lists never do, nor does a call through a
/// listed slot, and the ones that resume their caller through a saved context are never inferred noreturn.
pub fn return_facts(binary: &Binary) -> ReturnFacts {
    let symbols = binary.symbols.iter().map(|symbol| (symbol.address, symbol.name.clone(), false));
    let exports = binary.exports.iter().map(|export| (export.address, export.name.clone(), false));
    let code = symbols.chain(exports).filter(|&(address, _, _)| binary.is_code(address));
    let imports =
        stub_names(binary).into_iter().chain(thunk_names(binary)).map(|(address, name)| (address, name, true));
    let mut facts = ReturnFacts::default();
    for (address, name, import) in code.chain(imports) {
        if if import { is_noreturn_import(&name) } else { is_noreturn_name(&name) } {
            facts.noreturn.insert(address);
        }
        if listed(RETURNS_THROUGH_SAVED_CONTEXT, &name) {
            facts.returns.insert(address);
        }
    }
    let slots = binary.import_slots.iter().filter(|slot| is_noreturn_import(&slot.name));
    facts.noreturn.extend(slots.map(|slot| slot.address));
    facts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listed_names_match_through_import_decoration_and_mangling() {
        for name in [
            "exit",
            "_exit",
            "_Exit",
            "exit@plt",
            "abort@GLIBC_2.2.5",
            "__imp_ExitProcess",
            "__imp__ExitProcess@4",
            "__stack_chk_fail",
            "___stack_chk_fail",
            "__assert_fail",
            "__cxa_throw",
            "_Unwind_Resume",
            "_CxxThrowException",
            "?terminate@@YAXXZ",
            "_ZSt9terminatev",
            "_ZSt20__throw_length_errorPKc",
            "_ZN4core9panicking9panic_fmt17h0123456789abcdefE",
            "_ZN4core9panicking11panic_const24panic_const_add_overflow17h0123456789abcdefE",
            "_ZN3std7process4exit17h0123456789abcdefE",
            "runtime.throw",
            "runtime.gopanic",
            "runtime.goPanicIndex",
            "runtime.panicSliceAlen",
            "runtime.exit.abi0",
        ] {
            assert!(is_noreturn_name(name), "{name}");
        }
    }

    #[test]
    fn functions_that_can_return_are_not_listed() {
        for name in [
            "atexit",
            "exitw",
            "_cexit",
            "error",
            "RaiseException",
            "TerminateProcess",
            "setjmp",
            "runtime.throw.func1",
            "runtime.gopanic.func1",
            "runtime.panicCheck1",
            "runtime.panicking",
            "_ZN4core9panicking9panic_fmt28_$u7b$$u7b$closure$u7d$$u7d$17h0123456789abcdefE",
            "_ZN4core6option15Option$LT$T$GT$6unwrap17h0123456789abcdefE",
            "__rust_start_panic",
            // C and Windows names match only in their own case, and FatalExit can return to a debugger.
            "Exit",
            "EXIT",
            "Abort",
            "exitprocess",
            "FatalExit",
            "FatalAppExitA",
            // Common words count only as imports.
            "terminate",
            "err",
            "ERR",
        ] {
            assert!(!is_noreturn_name(name), "{name}");
        }
        // An Itanium-mangled global `terminate` is the program's own function, not `std::terminate`.
        assert!(!is_noreturn_name("_Z9terminatev"));
    }

    #[test]
    fn imported_common_words_are_listed() {
        for name in ["terminate", "__imp_terminate", "err", "_err", "errx@plt", "exit"] {
            assert!(is_noreturn_import(name), "{name}");
        }
        for name in ["ERR", "Terminate", "error", "FatalExit"] {
            assert!(!is_noreturn_import(name), "{name}");
        }
    }
}
