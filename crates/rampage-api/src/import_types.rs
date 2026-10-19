//! A three-name, target-selected import subset. This never imports a type library or changes annotations.

use rampage_decompiler::{DataOrganization, Platform};
use serde::Serialize;

/// Explicit POSIX evidence supplied by the caller; a default compiler or ELF container is not evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosixContext {
    TargetAssertion,
    AnalystAssertion,
    PosixLinuxProfile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportPrototype {
    pub canonical_name: &'static str,
    /// Bind by address, not by parsing the original import spelling (which may contain `@`).
    pub declaration: String,
    /// Retained upstream header excerpts, versioned URLs, adaptations and redistribution notices.
    pub source: &'static str,
    /// Records the selected model and assertion, not proof of the binary's implementation or runtime OS.
    pub context: String,
    pub confidence: &'static str,
}

const MUSL_SOURCE: &str = include_str!("../resources/import-types/musl.txt");
const MINGW_SOURCE: &str = include_str!("../resources/import-types/mingw-w64.txt");

/// `language_id` is the complete selected native ID, including its final compiler field, for example
/// `x86:LE:64:default:windows`. Compiler selection overrides platform defaults, just as in the native engine.
/// Returns None for unknown names, unsupported models, contradictory POSIX/Windows context or bad decoration.
/// Apply the returned declaration before analyst signatures, so analyst signatures take precedence.
pub fn import_prototype(
    name: &str,
    platform: Platform,
    language_id: &str,
    organization: DataOrganization,
    posix_context: Option<PosixContext>,
) -> Option<ImportPrototype> {
    if name.len() > 64 || language_id.len() > 128 {
        return None;
    }
    let model = target_model(language_id, organization)?;
    let canonical_name = match name {
        "memcpy" => "memcpy",
        "recv" => "recv",
        "CreateFileW" => "CreateFileW",
        "_memcpy" if model.darwin || (model.windows && model.x86_32) => "memcpy",
        "_recv" if model.darwin => "recv",
        "_recv@16" if model.windows && model.x86_32 => "recv",
        "_CreateFileW@28" if model.windows && model.x86_32 => "CreateFileW",
        // Darwin x86 uses the gcc compiler ID, so the platform supplies the Mach-O spelling context.
        "_memcpy" if platform == Platform::Darwin && !model.windows => "memcpy",
        "_recv" if platform == Platform::Darwin && !model.windows => "recv",
        _ => return None,
    };
    let (declaration, source, assertion, convention) = match canonical_name {
        "memcpy" => {
            let mut declaration = runtime_declaration("memcpy", organization.pointer)?;
            let convention = if model.windows && model.x86_32 {
                declaration = declaration.replacen("extern ", "extern __cdecl ", 1);
                "cdecl"
            } else {
                "selected compiler C model"
            };
            (declaration, MUSL_SOURCE, "portable C; no OS assertion", convention)
        }
        "recv" if model.windows => {
            if posix_context.is_some() || !model.windows_api {
                return None;
            }
            let convention = if model.x86_32 { "__stdcall " } else { "" };
            let pointer = organization.pointer;
            let declaration =
                format!("extern {convention}int4 recv(uint{pointer} s, char *buf, int4 len, int4 flags);");
            (declaration, MINGW_SOURCE, "Windows API selected by compiler", winapi_convention(model))
        }
        "recv" => {
            if platform == Platform::Windows {
                return None;
            }
            let assertion = match posix_context? {
                PosixContext::TargetAssertion => "POSIX target assertion; not Linux detection",
                PosixContext::AnalystAssertion => "POSIX analyst assertion; not Linux detection",
                PosixContext::PosixLinuxProfile if platform == Platform::Default && !model.darwin => {
                    "explicit posix-linux profile; Linux ABI assertion, not OS detection"
                }
                PosixContext::PosixLinuxProfile => return None,
            };
            (runtime_declaration("recv", organization.pointer)?, MUSL_SOURCE, assertion, "selected compiler C model")
        }
        "CreateFileW" if model.windows_api => {
            if posix_context.is_some() {
                return None;
            }
            let convention = if model.x86_32 { "__stdcall " } else { "" };
            let declaration = format!(
                "extern {convention}void * CreateFileW(uint2 *filename, uint4 access, uint4 share, \
                 void *security, uint4 disposition, uint4 flags, void *template_file);"
            );
            (declaration, MINGW_SOURCE, "Windows API selected by compiler", winapi_convention(model))
        }
        _ => return None,
    };
    let DataOrganization { pointer, int, long } = organization;
    Some(ImportPrototype {
        canonical_name,
        declaration,
        source,
        context: format!(
            "platform={platform:?}; language/compiler={language_id}; \
             byte widths pointer={pointer}, int={int}, long={long}; {assertion}; calling convention={convention}"
        ),
        confidence: "high within selected target/assertion; import name is not implementation proof",
    })
}

/// Only these two catalog entries contain pointer-sized uint8/int8 and no unrelated 64-bit scalar.
/// The public legacy renderer is explicitly LP64; adapt that bounded subset, never arbitrary catalog entries.
fn runtime_declaration(name: &str, pointer: u8) -> Option<String> {
    if !matches!(name, "memcpy" | "recv") {
        return None;
    }
    Some(
        rampage_decompiler::c_prototype(name)?
            .replace("uint8", &format!("uint{pointer}"))
            .replace("int8", &format!("int{pointer}")),
    )
}

#[derive(Clone, Copy)]
struct TargetModel {
    windows: bool,
    darwin: bool,
    x86_32: bool,
    windows_api: bool,
}

fn target_model(language_id: &str, organization: DataOrganization) -> Option<TargetModel> {
    let mut fields = language_id.split(':');
    let (processor, endian, bits, variant, compiler) =
        (fields.next()?, fields.next()?, fields.next()?, fields.next()?, fields.next()?);
    if fields.next().is_some()
        || variant.is_empty()
        || !variant.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || !matches!(endian, "LE" | "BE" | "LEBE")
        || !matches!(compiler, "default" | "gcc" | "macosx" | "apcs" | "apple" | "windows" | "clangwindows")
    {
        return None;
    }
    let pointer = match (processor, bits) {
        ("x86" | "MIPS" | "PowerPC" | "RISCV" | "sparc", "32") | ("ARM" | "68000", "32") => 4,
        ("x86" | "MIPS" | "PowerPC" | "RISCV" | "sparc" | "AARCH64", "64") => 8,
        _ => return None,
    };
    let windows = matches!(compiler, "windows" | "clangwindows");
    if rampage_decompiler::c_data_organization(language_id) != Some(organization)
        || organization.pointer != pointer
        || (matches!(processor, "x86" | "RISCV") && endian != "LE")
        || (windows && (endian != "LE" || !matches!(processor, "x86" | "ARM" | "AARCH64")))
    {
        return None;
    }
    Some(TargetModel {
        windows,
        darwin: matches!(compiler, "macosx" | "apple"),
        x86_32: processor == "x86" && pointer == 4,
        // The retained WinAPI calling-convention subset is deliberately bounded to x86/x64.
        windows_api: windows && processor == "x86",
    })
}

fn winapi_convention(model: TargetModel) -> &'static str {
    if model.x86_32 { "x86 stdcall" } else { "selected Windows x64 unified model" }
}

#[cfg(test)]
mod tests {
    use rampage_arch::Arch;
    use rampage_decompiler::results::{Signature, TypeInfo};
    use rampage_decompiler::{Decompiler, DecompilerOptions, MemoryRegion};

    use super::*;

    const ILP32: DataOrganization = DataOrganization { pointer: 4, int: 4, long: 4 };
    const LP64: DataOrganization = DataOrganization { pointer: 8, int: 4, long: 8 };
    const LLP64: DataOrganization = DataOrganization { pointer: 8, int: 4, long: 4 };

    fn native_signature(
        arch: Arch,
        platform: Platform,
        name: &str,
        bytes: &[u8],
        posix_context: Option<PosixContext>,
    ) -> (DataOrganization, Signature) {
        let compiler = match platform {
            Platform::Windows => "windows",
            Platform::Default => "gcc",
            Platform::Darwin => panic!("native import fixtures cover Windows and default gcc only"),
        };
        let regions = [MemoryRegion {
            base: 0x1000,
            bytes,
            size: bytes.len() as u64,
            readable: true,
            writable: false,
            executable: true,
        }];
        let options = DecompilerOptions { platform, compiler: Some(compiler.to_owned()), arm_be8: false };
        let mut engine = Decompiler::open_with_options(arch, false, &regions, &options).unwrap();
        engine.set_symbol(0x1000, name).unwrap();
        let organization = engine.data_organization();
        let prototype = import_prototype(name, platform, engine.language_id(), organization, posix_context).unwrap();
        engine.apply_prototype(0x1000, false, &prototype.declaration).unwrap();
        engine.decompile(0x1000, name, false).unwrap();
        let signature = engine.structured_result().unwrap().signature;
        assert!(!signature.variadic);
        for parameter in &signature.parameters {
            assert_eq!(parameter.storage.size, parameter.data_type.size, "{parameter:?}");
        }
        (organization, signature)
    }

    fn assert_native_type(actual: &TypeInfo, canonical_name: &str, size: u32) {
        let name: String = actual.name.chars().filter(|character| !character.is_whitespace()).collect();
        assert_eq!(name, canonical_name, "{actual:?}");
        assert_eq!(actual.size, size, "{actual:?}");
    }

    #[test]
    fn native_windows_x86_create_file_w_retains_seven_parameters_and_stdcall() {
        let (organization, signature) =
            native_signature(Arch::X86, Platform::Windows, "_CreateFileW@28", &[0x31, 0xc0, 0xc2, 0x1c, 0x00], None);
        assert_eq!(organization, ILP32);
        assert_eq!(signature.calling_convention.as_deref(), Some("__stdcall"));
        assert_native_type(&signature.return_type, "void*", 4);
        assert_eq!(signature.parameters.len(), 7, "{signature:?}");
        for (parameter, expected) in
            signature.parameters.iter().zip(["uint2*", "uint4", "uint4", "void*", "uint4", "uint4", "void*"])
        {
            assert_native_type(&parameter.data_type, expected, 4);
        }
    }

    #[test]
    fn native_recv_distinguishes_windows_x64_socket_and_int_from_posix_lp64_sizes() {
        let (organization, windows) =
            native_signature(Arch::X86_64, Platform::Windows, "recv", &[0x31, 0xc0, 0xc3], None);
        assert_eq!(organization, LLP64);
        assert_eq!(windows.calling_convention.as_deref(), Some("__fastcall"));
        assert_native_type(&windows.return_type, "int4", 4);
        assert_eq!(windows.parameters.len(), 4, "{windows:?}");
        for (parameter, (name, size)) in
            windows.parameters.iter().zip([("uint8", 8), ("char*", 8), ("int4", 4), ("int4", 4)])
        {
            assert_native_type(&parameter.data_type, name, size);
        }

        let (organization, posix) = native_signature(
            Arch::X86_64,
            Platform::Default,
            "recv",
            &[0x48, 0x31, 0xc0, 0xc3],
            Some(PosixContext::TargetAssertion),
        );
        assert_eq!(organization, LP64);
        // This is the bundled gcc spec's native model name, not an x86 WinAPI ABI claim.
        assert_eq!(posix.calling_convention.as_deref(), Some("__stdcall"));
        assert_native_type(&posix.return_type, "int8", 8);
        assert_eq!(posix.parameters.len(), 4, "{posix:?}");
        for (parameter, (name, size)) in
            posix.parameters.iter().zip([("int4", 4), ("void*", 8), ("uint8", 8), ("int4", 4)])
        {
            assert_native_type(&parameter.data_type, name, size);
        }
    }

    #[test]
    fn native_memcpy_retains_pointer_return_and_pointer_sized_count_on_lp64_and_llp64() {
        for (platform, bytes, expected_organization, model) in [
            (Platform::Default, [0x48, 0x89, 0xf8, 0xc3], LP64, "__stdcall"),
            (Platform::Windows, [0x48, 0x89, 0xc8, 0xc3], LLP64, "__fastcall"),
        ] {
            let (organization, signature) = native_signature(Arch::X86_64, platform, "memcpy", &bytes, None);
            assert_eq!(organization, expected_organization);
            assert_eq!(signature.calling_convention.as_deref(), Some(model));
            assert_native_type(&signature.return_type, "void*", 8);
            assert_eq!(signature.parameters.len(), 3, "{signature:?}");
            for (parameter, expected) in signature.parameters.iter().zip(["void*", "void*", "uint8"]) {
                assert_native_type(&parameter.data_type, expected, 8);
            }
        }
    }

    #[test]
    fn memcpy_reuses_the_catalog_with_selected_widths_and_pointer_return() {
        for (platform, language, organization, expected) in [
            (Platform::Default, "x86:LE:32:default:gcc", ILP32, "extern void * memcpy(void *dst, void *src, uint4 n);"),
            (Platform::Default, "x86:LE:64:default:gcc", LP64, "extern void * memcpy(void *dst, void *src, uint8 n);"),
            (
                Platform::Windows,
                "x86:LE:64:default:windows",
                LLP64,
                "extern void * memcpy(void *dst, void *src, uint8 n);",
            ),
            (
                Platform::Windows,
                "x86:LE:32:default:windows",
                ILP32,
                "extern __cdecl void * memcpy(void *dst, void *src, uint4 n);",
            ),
        ] {
            let prototype = import_prototype("memcpy", platform, language, organization, None).unwrap();
            assert_eq!(prototype.declaration, expected);
            assert!(prototype.context.contains("no OS assertion"));
            assert!(prototype.source.contains("v1.2.5"));
        }
    }

    #[test]
    fn recv_distinguishes_posix_ssize_t_from_windows_int_and_socket() {
        for (language, organization, expected) in [
            ("x86:LE:32:default:gcc", ILP32, "extern int4 recv(int4 fd, void *buf, uint4 n, int4 flags);"),
            ("x86:LE:64:default:gcc", LP64, "extern int8 recv(int4 fd, void *buf, uint8 n, int4 flags);"),
        ] {
            let prototype = import_prototype(
                "recv",
                Platform::Default,
                language,
                organization,
                Some(PosixContext::AnalystAssertion),
            )
            .unwrap();
            assert_eq!(prototype.declaration, expected);
            assert!(prototype.context.contains("POSIX analyst assertion; not Linux detection"));
            assert!(import_prototype("recv", Platform::Default, language, organization, None).is_none());
        }
        for (language, organization, expected) in [
            (
                "x86:LE:32:default:windows",
                ILP32,
                "extern __stdcall int4 recv(uint4 s, char *buf, int4 len, int4 flags);",
            ),
            ("x86:LE:64:default:windows", LLP64, "extern int4 recv(uint8 s, char *buf, int4 len, int4 flags);"),
        ] {
            let prototype = import_prototype("recv", Platform::Windows, language, organization, None).unwrap();
            assert_eq!(prototype.declaration, expected);
        }
    }

    #[test]
    fn create_file_w_keeps_wchar_and_dword_widths_on_both_windows_models() {
        for (language, organization, prefix) in [
            ("x86:LE:32:default:windows", ILP32, "extern __stdcall void *"),
            ("x86:LE:64:default:clangwindows", LLP64, "extern void *"),
        ] {
            let prototype = import_prototype("CreateFileW", Platform::Windows, language, organization, None).unwrap();
            assert_eq!(
                prototype.declaration,
                format!(
                    "{prefix} CreateFileW(uint2 *filename, uint4 access, uint4 share, \
                 void *security, uint4 disposition, uint4 flags, void *template_file);"
                )
            );
            assert!(prototype.source.contains("v12.0.0"));
        }
    }

    #[test]
    fn decoration_requires_exact_known_name_byte_count_and_x86_windows_model() {
        let language = "x86:LE:32:default:windows";
        for (name, canonical) in [("_recv@16", "recv"), ("_CreateFileW@28", "CreateFileW"), ("_memcpy", "memcpy")] {
            let prototype = import_prototype(name, Platform::Windows, language, ILP32, None).unwrap();
            assert_eq!(prototype.canonical_name, canonical);
            assert!(!prototype.declaration.contains('@'));
        }
        for name in [
            "_recv@12",
            "_recv@016",
            "recv@16",
            "__recv@16",
            "_recv",
            "_memcpy@12",
            "_CreateFileW@24",
            "_CreateFileW",
            "CreateFile",
            "createfilew",
            "__imp_recv",
            "my_memcpy",
            "memcpy_s",
            "memcpy@@GLIBC_2.14",
            "recv\0",
            "recv ",
        ] {
            assert!(import_prototype(name, Platform::Windows, language, ILP32, None).is_none(), "{name:?}");
        }
        for name in ["_recv@16", "_CreateFileW@28", "_memcpy"] {
            assert!(import_prototype(name, Platform::Windows, "x86:LE:64:default:windows", LLP64, None,).is_none());
        }
        assert!(import_prototype("_memcpy", Platform::Default, "x86:LE:64:default:gcc", LP64, None,).is_none());
        assert!(import_prototype("_memcpy", Platform::Darwin, "x86:LE:64:default:gcc", LP64, None,).is_some());
    }

    #[test]
    fn unsupported_or_conflicting_context_never_supplies_a_prototype() {
        for (language, organization) in [
            ("x86:LE:64:default:windows", LP64),
            ("x86:LE:64:default:gcc", LLP64),
            ("x86:LE:32:default:gcc", LP64),
            ("x86:BE:32:default:gcc", ILP32),
            ("x86:LE:64:default:unknown", LP64),
            ("x86:LE:64:default", LP64),
            ("unknown:LE:64:default:gcc", LP64),
            ("x86:LE:64:default:gcc:extra", LP64),
            ("x86:LE:64:default:gcc", DataOrganization { int: 8, ..LP64 }),
        ] {
            assert!(import_prototype("memcpy", Platform::Default, language, organization, None).is_none());
        }
        for name in ["recv", "CreateFileW"] {
            assert!(
                import_prototype(
                    name,
                    Platform::Windows,
                    "x86:LE:64:default:windows",
                    LLP64,
                    Some(PosixContext::TargetAssertion),
                )
                .is_none()
            );
            assert!(import_prototype(name, Platform::Default, "AARCH64:LE:64:v8A:windows", LLP64, None,).is_none());
        }
        assert!(import_prototype("CreateFileW", Platform::Default, "x86:LE:64:default:gcc", LP64, None,).is_none());
        assert!(
            import_prototype(
                "recv",
                Platform::Darwin,
                "AARCH64:LE:64:v8A:apple",
                LP64,
                Some(PosixContext::PosixLinuxProfile),
            )
            .is_none()
        );
        let explicit_profile = import_prototype(
            "recv",
            Platform::Default,
            "x86:LE:64:default:gcc",
            LP64,
            Some(PosixContext::PosixLinuxProfile),
        )
        .unwrap();
        assert!(explicit_profile.context.contains("Linux ABI assertion, not OS detection"));
        // An explicitly selected compiler overrides a Windows platform default.
        assert!(import_prototype("CreateFileW", Platform::Windows, "x86:LE:64:default:gcc", LP64, None,).is_none());
    }
}
