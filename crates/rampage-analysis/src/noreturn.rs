//! Functions known by name never to return to their caller.

use rampage_capabilities::names::import_stem;
use rampage_loaders::Binary;

use crate::discover::ReturnFacts;

use crate::functions::{stub_names, thunk_names};
use crate::language::demangle;

/// Callees that never return, written as lowercase [`import_stem`]s (leading underscores and `@` suffixes dropped,
/// so `exit` also covers `_exit`, Mach-O `__exit` and `exit@plt`) or demangled qualified names without parameters.
/// A trailing `*` matches by prefix, but never into a nested item: Go closures (`runtime.gopanic.func1`) and Rust
/// closures return normally.
///
/// Every entry is declared noreturn by its own documentation or headers: C11/POSIX (`exit`, `_Exit`, `abort`,
/// `quick_exit`, `longjmp`, `pthread_exit`), BSD `err(3)`, glibc/musl `<assert.h>` and fortify/stack-protector
/// handlers, the Itanium C++ ABI and libunwind, Microsoft's Win32/CRT docs (`ExitProcess`, `ExitThread`,
/// `FreeLibraryAndExitThread`, `FatalExit`, `FatalAppExit`, `_CxxThrowException`, `__report_gsfailure`,
/// `_invalid_parameter_noinfo_noreturn`), Objective-C `objc_exception_throw`, Rust functions returning `!`, and the
/// Go runtime functions that `throw`, `panic` or end the goroutine. Ghidra's `*FunctionsThatDoNotReturn` lists
/// served as a cross-check; their entries that can return (`RaiseException`, `TerminateProcess` on another process,
/// `reboot`, Go `panicCheck1`/`panicCheck2`, Rust `__rust_start_panic`) are left out on purpose.
const NORETURN: &[&str] = &[
    // C and POSIX.
    "exit",
    "abort",
    "quick_exit",
    "thrd_exit",
    "pthread_exit",
    "longjmp",
    "siglongjmp",
    "longjmp_chk",
    "libc_longjmp",
    "libc_siglongjmp",
    "err",
    "errx",
    "verr",
    "verrx",
    "assert_fail",
    "assert_perror_fail",
    "assert_rtn",
    "stack_chk_fail",
    "stack_chk_fail_local",
    "fortify_fail",
    "chk_fail",
    "libc_fatal",
    // C++ runtime (Itanium ABI, libstdc++, libc++abi) and unwinding.
    "cxa_throw",
    "cxa_rethrow",
    "cxa_bad_cast",
    "cxa_bad_typeid",
    "cxa_throw_bad_array_new_length",
    "cxa_pure_virtual",
    "cxa_deleted_virtual",
    "cxa_call_unexpected",
    "unwind_resume",
    "terminate",
    "std::terminate",
    "std::__terminate",
    "__cxxabiv1::__terminate",
    "std::__throw_*",
    "objc_exception_throw",
    "objc_exception_rethrow",
    // Windows API and the Microsoft CRT.
    "exitprocess",
    "exitthread",
    "freelibraryandexitthread",
    "fatalexit",
    "fatalappexita",
    "fatalappexitw",
    "rtlexituserprocess",
    "rtlexituserthread",
    "cxxthrowexception",
    "report_gsfailure",
    "report_rangecheckfailure",
    "invalid_parameter_noinfo_noreturn",
    "invoke_watson",
    // Rust.
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
    "rust_begin_unwind",
    "rust_drop_panic",
    "rust_foreign_exception",
    "rg_oom",
    // Go.
    "runtime.throw",
    "runtime.fatal",
    "runtime.fatalthrow",
    "runtime.fatalpanic",
    "runtime.abort",
    "runtime.exit",
    "runtime.exitthread",
    "runtime.diefromsignal",
    "runtime.goexit",
    "runtime.goexit0",
    "runtime.goexit1",
    "runtime.gopanic*",
    "runtime.panicindex*",
    "runtime.panicslice*",
    "runtime.panicextend*",
    "runtime.panicunsafe*",
    "runtime.panicdottype*",
    "runtime.panicmakeslice*",
    "runtime.panicdivide",
    "runtime.panicshift",
    "runtime.panicmem",
    "runtime.panicmemaddr",
    "runtime.panicnildottype",
    "runtime.panicoverflow",
    "runtime.panicfloat",
    "runtime.panicunaligned",
    "runtime.panicwrap",
    "runtime.panicrangestate",
];

/// Functions whose every path ends in a noreturn call or a trap, which nevertheless resume their caller: Go's
/// `mcall` switches to the scheduler stack and its caller continues when `gogo` restores the context `mcall` saved,
/// and `morestack` resumes the function that called it, from its start, on a larger stack.
const RETURNS_THROUGH_SAVED_CONTEXT: &[&str] = &["runtime.mcall", "runtime.morestack", "runtime.morestack_noctxt"];

/// Whether the raw symbol or import `name` is a function [`NORETURN`] lists.
pub fn is_noreturn_name(name: &str) -> bool {
    listed(NORETURN, name)
}

fn listed(table: &[&str], name: &str) -> bool {
    let stem = import_stem(name);
    let stem = stem.strip_suffix(".abi0").unwrap_or(&stem);
    let demangled = demangle(name).map(|display| display.split('(').next().unwrap_or_default().to_ascii_lowercase());
    std::iter::once(stem).chain(demangled.as_deref()).any(|name| table.iter().any(|&pattern| matches(pattern, name)))
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
/// ones [`is_noreturn_name`] lists never do (nor does a call through a listed slot), and the ones that resume
/// their caller through a saved context are never inferred noreturn.
pub fn return_facts(binary: &Binary) -> ReturnFacts {
    let symbols = binary.symbols.iter().map(|symbol| (symbol.address, symbol.name.clone()));
    let exports = binary.exports.iter().map(|export| (export.address, export.name.clone()));
    let code = symbols.chain(exports).filter(|&(address, _)| binary.is_code(address));
    let mut facts = ReturnFacts::default();
    for (address, name) in code.chain(stub_names(binary)).chain(thunk_names(binary)) {
        if is_noreturn_name(&name) {
            facts.noreturn.insert(address);
        }
        if listed(RETURNS_THROUGH_SAVED_CONTEXT, &name) {
            facts.returns.insert(address);
        }
    }
    let slots = binary.import_slots.iter().filter(|slot| is_noreturn_name(&slot.name));
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
        ] {
            assert!(!is_noreturn_name(name), "{name}");
        }
    }
}
