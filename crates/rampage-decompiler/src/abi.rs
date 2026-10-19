use rampage_arch::Arch;

use crate::Error;

/// Platform defaults select a compiler specification, not the source compiler's brand.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Platform {
    #[default]
    Default,
    Windows,
    Darwin,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecompilerOptions {
    pub platform: Platform,
    /// Ghidra compiler ID, such as `gcc`, `windows`, `apcs` or `macosx`.
    /// Overrides platform selection; it must exist for the selected processor language.
    pub compiler: Option<String>,
    /// ARM BE8: little-endian instructions and big-endian data.
    pub arm_be8: bool,
}

/// Byte widths reported by the selected compiler specification, never by the host platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataOrganization {
    pub pointer: u8,
    pub int: u8,
    pub long: u8,
}

pub(crate) fn checked_data_organization(widths: [i32; 3]) -> Result<DataOrganization, Error> {
    let checked = widths.map(|width| u8::try_from(width).ok().filter(|&width| width != 0));
    let [Some(pointer), Some(int), Some(long)] = checked else {
        return Err(Error::Ghidra(format!("invalid compiler data widths: {widths:?}")));
    };
    Ok(DataOrganization { pointer, int, long })
}

pub(crate) fn is_windows(compiler: &str) -> bool {
    matches!(compiler, "windows" | "clangwindows")
}

pub(crate) fn is_darwin(compiler: &str) -> bool {
    matches!(compiler, "macosx" | "apple")
}

pub(crate) fn has_c_runtime(compiler: &str) -> bool {
    matches!(compiler, "default" | "gcc" | "macosx" | "apcs" | "apple") || is_windows(compiler)
}

/// Reviewed C widths for an exact language/compiler ID. This is not specification or source proof.
pub fn c_data_organization(language_id: &str) -> Option<DataOrganization> {
    let (pointer, int, long) = match language_id {
        "TI_MSP430:LE:16:default:default" | "avr8:LE:16:default:gcc" => (2, 2, 4),
        "x86:LE:32:default:gcc"
        | "x86:LE:32:default:windows"
        | "x86:LE:32:default:clangwindows"
        | "ARM:LE:32:v8:default"
        | "ARM:BE:32:v8:default"
        | "ARM:LE:32:v8:apcs"
        | "ARM:BE:32:v8:apcs"
        | "ARM:LE:32:v8:windows"
        | "ARM:LEBE:32:v8LEInstruction:default"
        | "ARM:LEBE:32:v8LEInstruction:apcs"
        | "ARM:LEBE:32:v8LEInstruction:windows"
        | "MIPS:LE:32:default:default"
        | "MIPS:BE:32:default:default"
        | "MIPS:LE:32:default:windows"
        | "MIPS:BE:32:default:windows"
        | "PowerPC:LE:32:default:default"
        | "PowerPC:BE:32:default:default"
        | "PowerPC:LE:32:default:windows"
        | "PowerPC:BE:32:default:macosx"
        | "RISCV:LE:32:default:gcc"
        | "sparc:BE:32:default:default"
        | "68000:BE:32:default:default" => (4, 4, 4),
        "x86:LE:64:default:gcc"
        | "AARCH64:LE:64:v8A:default"
        | "AARCH64:BE:64:v8A:default"
        | "AARCH64:LE:64:v8A:apple"
        | "MIPS:LE:64:default:default"
        | "MIPS:BE:64:default:default"
        | "PowerPC:LE:64:default:default"
        | "PowerPC:BE:64:default:default"
        | "PowerPC:BE:64:default:macosx"
        | "RISCV:LE:64:default:gcc"
        | "sparc:BE:64:default:default" => (8, 4, 8),
        "x86:LE:64:default:windows"
        | "x86:LE:64:default:clangwindows"
        | "AARCH64:LE:64:v8A:windows"
        | "MIPS:LE:64:default:windows" => (8, 4, 4),
        _ => return None,
    };
    Some(DataOrganization { pointer, int, long })
}

pub(crate) fn validate_c_admission(default_pointer_size: Option<u8>, language_id: &str) -> Result<(), Error> {
    if default_pointer_size.is_none() && c_data_organization(language_id).is_none() {
        return Err(Error::Ghidra(format!("no reviewed C data organization for {language_id}")));
    }
    Ok(())
}

pub(crate) fn validate_data_organization(
    default_pointer_size: Option<u8>,
    language_id: &str,
    actual: DataOrganization,
) -> Result<(), Error> {
    let compiler = language_id.rsplit(':').next().unwrap_or("");
    let expected = if let Some(pointer) = default_pointer_size {
        // Preserve legacy native admission; this does not publish automatic C-model facts.
        if !has_c_runtime(compiler) {
            return Ok(());
        }
        let long = if is_windows(compiler) { 4 } else { pointer };
        DataOrganization { pointer, int: 4, long }
    } else {
        c_data_organization(language_id)
            .ok_or_else(|| Error::Ghidra(format!("no reviewed C data organization for {language_id}")))?
    };
    if actual != expected {
        return Err(Error::Ghidra(format!(
            "compiler specification has incompatible C data organization: {actual:?}, expected {expected:?}"
        )));
    }
    Ok(())
}

pub fn language_id(arch: Arch, big_endian: bool) -> Option<String> {
    language_id_with_options(arch, big_endian, &DecompilerOptions::default()).ok()
}

pub fn language_id_with_options(arch: Arch, big_endian: bool, options: &DecompilerOptions) -> Result<String, Error> {
    let endian = if big_endian { "BE" } else { "LE" };
    let (language, default_compiler) = match arch {
        Arch::X86 => ("x86:LE:32:default".to_owned(), "gcc"),
        Arch::X86_64 => ("x86:LE:64:default".to_owned(), "gcc"),
        Arch::Aarch64 => (format!("AARCH64:{endian}:64:v8A"), "default"),
        Arch::Arm if options.arm_be8 => ("ARM:LEBE:32:v8LEInstruction".to_owned(), "default"),
        Arch::Arm => (format!("ARM:{endian}:32:v8"), "default"),
        Arch::Mips => (format!("MIPS:{endian}:32:default"), "default"),
        Arch::Mips64 => (format!("MIPS:{endian}:64:default"), "default"),
        Arch::PowerPc => (format!("PowerPC:{endian}:32:default"), "default"),
        Arch::PowerPc64 => (format!("PowerPC:{endian}:64:default"), "default"),
        Arch::Riscv32 => ("RISCV:LE:32:default".to_owned(), "gcc"),
        Arch::Riscv64 => ("RISCV:LE:64:default".to_owned(), "gcc"),
        Arch::Sparc => ("sparc:BE:32:default".to_owned(), "default"),
        Arch::Sparc64 => ("sparc:BE:64:default".to_owned(), "default"),
        Arch::M68k => ("68000:BE:32:default".to_owned(), "default"),
        Arch::S390x => return Err(Error::UnsupportedArch(arch)),
    };
    if options.arm_be8 && (arch != Arch::Arm || !big_endian) {
        return Err(Error::Ghidra("BE8 requires ARM with big-endian data".to_owned()));
    }
    let compiler = if let Some(compiler) = options.compiler.as_deref() {
        if compiler.is_empty() || !compiler.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
            return Err(Error::Ghidra("invalid compiler specification ID".to_owned()));
        }
        compiler
    } else {
        match (options.platform, arch, big_endian) {
            (Platform::Windows, Arch::X86 | Arch::X86_64 | Arch::Arm | Arch::Aarch64, false) => "windows",
            (Platform::Windows, _, _) => {
                return Err(Error::Ghidra(format!("no Windows compiler default for {arch}")));
            }
            (Platform::Darwin, Arch::PowerPc | Arch::PowerPc64, true) => "macosx",
            (Platform::Darwin, Arch::Aarch64, false) => "apple",
            (Platform::Default | Platform::Darwin, _, _) => default_compiler,
        }
    };
    Ok(format!("{language}:{compiler}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pilot_c_models_are_exact_and_unknown_pairs_do_not_inherit_widths() {
        let small = DataOrganization { pointer: 2, int: 2, long: 4 };
        for language in ["TI_MSP430:LE:16:default:default", "avr8:LE:16:default:gcc"] {
            assert_eq!(c_data_organization(language), Some(small));
            assert!(validate_c_admission(None, language).is_ok());
            assert!(validate_data_organization(None, language, small).is_ok());
            assert!(validate_data_organization(None, language, DataOrganization { int: 4, ..small }).is_err());
        }
        for language in [
            "TI_MSP430:LE:16:default:gcc",
            "TI_MSP430X:LE:32:default:default",
            "TI_MSP430:BE:16:default:default",
            "avr8:LE:16:default:default",
            "avr8:LE:16:extended:gcc",
            "avr8:LE:16:default:iarV1",
            "avr8:LE:16:default:gcc:extra",
            "6502:LE:16:default:default",
            "65C02:LE:16:default:default",
            "unknown:LE:32:default:gcc",
        ] {
            assert_eq!(c_data_organization(language), None, "{language}");
            assert!(validate_c_admission(None, language).is_err(), "{language}");
            assert!(validate_data_organization(None, language, small).is_err(), "{language}");
        }
        assert!(validate_data_organization(None, "6502:LE:16:default:default", small).is_err());
        // Preserve non-C native specifications; they acquire no C-model resolver entry.
        assert!(validate_data_organization(Some(8), "x86:LE:64:default:golang", small).is_ok());
        assert_eq!(c_data_organization("x86:LE:64:default:golang"), None);
    }

    #[test]
    fn custom_native_compiler_does_not_acquire_automatic_c_facts() {
        let language = "x86:LE:64:default:owned_alias";
        let native = checked_data_organization([8, 4, 8]).unwrap();
        assert_eq!(c_data_organization(language), None);
        assert!(validate_c_admission(Some(8), language).is_ok());
        assert!(validate_c_admission(None, language).is_err());
        assert!(validate_data_organization(Some(8), language, native).is_ok());
        assert!(validate_data_organization(None, language, native).is_err());
        assert!(checked_data_organization([8, 0, 8]).is_err());
    }

    #[test]
    fn inconsistent_external_c_specs_are_rejected_instead_of_guessing_types() {
        let lp64 = DataOrganization { pointer: 8, int: 4, long: 8 };
        assert!(validate_data_organization(Some(8), "sparc:BE:64:default:default", lp64).is_ok());
        assert!(
            validate_data_organization(Some(8), "sparc:BE:64:default:default", DataOrganization { long: 4, ..lp64 },)
                .is_err()
        );
        assert!(
            validate_data_organization(
                Some(4),
                "MIPS:LE:32:default:default",
                DataOrganization { pointer: 4, int: 4, long: 8 },
            )
            .is_err()
        );
        assert!(validate_data_organization(Some(8), "x86:LE:64:default:clangwindows", lp64).is_err());
    }
}
