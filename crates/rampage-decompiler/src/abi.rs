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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

pub(crate) fn validate_data_organization(arch: Arch, compiler: &str, actual: DataOrganization) -> Result<(), Error> {
    if !has_c_runtime(compiler) {
        return Ok(());
    }
    let pointer = arch.pointer_size();
    let long = if is_windows(compiler) { 4 } else { pointer };
    let expected = DataOrganization { pointer, int: 4, long };
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
    fn inconsistent_external_c_specs_are_rejected_instead_of_guessing_types() {
        let lp64 = DataOrganization { pointer: 8, int: 4, long: 8 };
        assert!(validate_data_organization(Arch::Sparc64, "default", lp64).is_ok());
        assert!(validate_data_organization(Arch::Sparc64, "default", DataOrganization { long: 4, ..lp64 }).is_err());
        assert!(
            validate_data_organization(Arch::Mips, "default", DataOrganization { pointer: 4, int: 4, long: 8 })
                .is_err()
        );
        assert!(validate_data_organization(Arch::X86_64, "clangwindows", lp64).is_err());
    }
}
