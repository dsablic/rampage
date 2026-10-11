//! A safe wrapper over Ghidra's decompiler, embedded through a C ABI shim (see `src/shim.cc`). A `Decompiler`
//! holds one Ghidra architecture over the program's executable segments and decompiles functions on demand.
//!
//! Ghidra's processor specifications (the compiled `.sla` files) are found at a "sleigh home": a directory that
//! contains a `Ghidra/Processors` tree. `sleigh_home` locates a local Ghidra install; set `GHIDRA_INSTALL_DIR`
//! to override it.

use std::ffi::{CStr, CString, c_char};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

use rampage_arch::Arch;

/// Ghidra's decompiler library keeps process-global state and is not built for concurrent use, so every call
/// into it is serialized. Decompilation is CPU-bound but fast, so this is not a throughput concern in practice.
static FFI_LOCK: Mutex<()> = Mutex::new(());

#[repr(C)]
struct Opaque {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn rampage_decomp_open(
        sleighhome: *const c_char,
        langid: *const c_char,
        nseg: usize,
        bases: *const u64,
        ptrs: *const *const u8,
        lens: *const usize,
        writable: *const u8,
    ) -> *mut Opaque;
    fn rampage_decomp_add_symbol(handle: *mut Opaque, addr: u64, name: *const c_char);
    fn rampage_decomp_error(handle: *mut Opaque) -> *const c_char;
    fn rampage_decomp_function(handle: *mut Opaque, addr: u64, name: *const c_char) -> *mut c_char;
    fn rampage_decomp_free_string(text: *mut c_char);
    fn rampage_decomp_close(handle: *mut Opaque);
}

/// A segment of program bytes placed at a virtual address. Non-writable segments are treated as read-only, so
/// the decompiler can fold their contents (strings, constant pointers) into its output.
pub struct Segment<'a> {
    pub base: u64,
    pub bytes: &'a [u8],
    pub writable: bool,
}

#[derive(Debug)]
pub enum Error {
    /// No Ghidra specification maps to this architecture.
    UnsupportedArch(Arch),
    /// A Ghidra install was not found; set `GHIDRA_INSTALL_DIR`.
    NoSleighHome,
    /// Ghidra reported a problem while setting up or decompiling.
    Ghidra(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::UnsupportedArch(arch) => write!(f, "no decompiler specification for {arch:?}"),
            Error::NoSleighHome => {
                write!(f, "no Ghidra install found; set GHIDRA_INSTALL_DIR to one containing Ghidra/Processors")
            }
            Error::Ghidra(message) => write!(f, "decompiler: {message}"),
        }
    }
}

impl std::error::Error for Error {}

/// Ghidra's 5-part language id (processor:endian:size:variant:compiler) for an architecture, or `None` when
/// Ghidra has no specification for it (s390x).
pub fn language_id(arch: Arch, big_endian: bool) -> Option<String> {
    let endian = if big_endian { "BE" } else { "LE" };
    let id = match arch {
        Arch::X86 => "x86:LE:32:default:gcc".to_owned(),
        Arch::X86_64 => "x86:LE:64:default:gcc".to_owned(),
        Arch::Aarch64 => format!("AARCH64:{endian}:64:v8A:default"),
        Arch::Arm => format!("ARM:{endian}:32:v8:default"),
        Arch::Mips => format!("MIPS:{endian}:32:default:default"),
        Arch::Mips64 => format!("MIPS:{endian}:64:default:default"),
        Arch::PowerPc => format!("PowerPC:{endian}:32:default:default"),
        Arch::PowerPc64 => format!("PowerPC:{endian}:64:default:default"),
        Arch::Riscv32 => "RISCV:LE:32:default:gcc".to_owned(),
        Arch::Riscv64 => "RISCV:LE:64:default:gcc".to_owned(),
        Arch::Sparc => "sparc:BE:32:default:default".to_owned(),
        Arch::Sparc64 => "sparc:BE:64:default:default".to_owned(),
        Arch::M68k => "68000:BE:32:default:default".to_owned(),
        Arch::S390x => return None,
    };
    Some(id)
}

/// Locates a directory holding Ghidra's `Ghidra/Processors` specification tree: `GHIDRA_INSTALL_DIR` if set,
/// otherwise a Homebrew install.
pub fn sleigh_home() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("GHIDRA_INSTALL_DIR") {
        return Some(PathBuf::from(dir));
    }
    let output = Command::new("brew").args(["--prefix", "ghidra"]).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let prefix = String::from_utf8(output.stdout).ok()?;
    let libexec = PathBuf::from(prefix.trim()).join("libexec");
    libexec.join("Ghidra").is_dir().then_some(libexec)
}

/// A decompiler over one program's executable segments.
pub struct Decompiler {
    handle: *mut Opaque,
}

// SAFETY: the handle is only ever used while holding FFI_LOCK, so it is touched by one thread at a time.
unsafe impl Send for Decompiler {}

impl Decompiler {
    /// Opens a decompiler for `arch` over `segments`. Each segment's bytes stay mapped at its base for the life
    /// of the decompiler, so functions anywhere in the loaded code can be decompiled.
    pub fn open(arch: Arch, big_endian: bool, segments: &[Segment]) -> Result<Decompiler, Error> {
        let langid = language_id(arch, big_endian).ok_or(Error::UnsupportedArch(arch))?;
        let home = sleigh_home().ok_or(Error::NoSleighHome)?;
        let home = CString::new(home.as_os_str().to_string_lossy().as_bytes()).map_err(|_| Error::NoSleighHome)?;
        let langid = CString::new(langid).map_err(|_| Error::UnsupportedArch(arch))?;

        let bases: Vec<u64> = segments.iter().map(|segment| segment.base).collect();
        let ptrs: Vec<*const u8> = segments.iter().map(|segment| segment.bytes.as_ptr()).collect();
        let lens: Vec<usize> = segments.iter().map(|segment| segment.bytes.len()).collect();
        let writable: Vec<u8> = segments.iter().map(|segment| u8::from(segment.writable)).collect();

        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: the pointers and lengths describe `segments`, which outlive this call; the shim copies the
        // bytes before returning.
        let handle = unsafe {
            rampage_decomp_open(
                home.as_ptr(),
                langid.as_ptr(),
                segments.len(),
                bases.as_ptr(),
                ptrs.as_ptr(),
                lens.as_ptr(),
                writable.as_ptr(),
            )
        };
        if handle.is_null() {
            return Err(Error::Ghidra("could not allocate decompiler".to_owned()));
        }
        // SAFETY: handle is non-null; the error string, if any, is owned by the handle and valid until close.
        let error = unsafe { rampage_decomp_error(handle) };
        if !error.is_null() {
            let message = unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned();
            unsafe { rampage_decomp_close(handle) };
            return Err(Error::Ghidra(message));
        }
        Ok(Decompiler { handle })
    }

    /// Registers a known function address with a name, so calls to it render by name. Call before decompiling
    /// callers; names that fail to apply (e.g. a bad address) are silently skipped.
    pub fn add_symbol(&mut self, address: u64, name: &str) {
        let Ok(name) = CString::new(name) else { return };
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: handle is valid for the life of self; name is a valid C string for the call.
        unsafe { rampage_decomp_add_symbol(self.handle, address, name.as_ptr()) };
    }

    /// Decompiles the function at `address` to C. `name`, when non-empty, is used as the function's name.
    pub fn decompile(&mut self, address: u64, name: &str) -> Result<String, Error> {
        let name = CString::new(name).unwrap_or_default();
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: handle is valid; the returned string is malloc'd by the shim and freed below.
        let text = unsafe { rampage_decomp_function(self.handle, address, name.as_ptr()) };
        if text.is_null() {
            let error = unsafe { rampage_decomp_error(self.handle) };
            let message = if error.is_null() {
                "decompilation failed".to_owned()
            } else {
                unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned()
            };
            return Err(Error::Ghidra(message));
        }
        let result = unsafe { CStr::from_ptr(text) }.to_string_lossy().into_owned();
        unsafe { rampage_decomp_free_string(text) };
        Ok(result)
    }
}

impl Drop for Decompiler {
    fn drop(&mut self) {
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: handle came from rampage_decomp_open and is closed exactly once.
        unsafe { rampage_decomp_close(self.handle) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // sum_to, max3, fnv1a compiled at -O2 for x86-64, extracted .text (see the decompiler design notes).
    const X64_TEXT: &[u8] = &[
        0x85, 0xff, 0x7e, 0x13, 0x8d, 0x47, 0xff, 0x8d, 0x4f, 0xfe, 0x48, 0x0f,
        0xaf, 0xc8, 0x48, 0xd1, 0xe9, 0x8d, 0x04, 0x79, 0xff, 0xc8, 0xc3, 0x31,
        0xc0, 0xc3, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x89, 0xf8, 0x39, 0xfe,
        0x0f, 0x4f, 0xc6, 0x39, 0xc2, 0x0f, 0x4f, 0xc2, 0xc3, 0x0f, 0x1f, 0x00,
        0x0f, 0xb6, 0x0f, 0x84, 0xc9, 0x74, 0x1f, 0x48, 0xff, 0xc7, 0xb8, 0xc5,
        0x9d, 0x1c, 0x81, 0x90, 0x0f, 0xb6, 0xc9, 0x31, 0xc1, 0x69, 0xc1, 0x93,
        0x01, 0x00, 0x01, 0x0f, 0xb6, 0x0f, 0x48, 0xff, 0xc7, 0x84, 0xc9, 0x75,
        0xeb, 0xc3, 0xb8, 0xc5, 0x9d, 0x1c, 0x81, 0xc3,
    ];

    #[test]
    fn decompiles_x86_64_when_ghidra_is_present() {
        if sleigh_home().is_none() {
            return;
        }
        let segments = [Segment { base: 0x1000, bytes: X64_TEXT, writable: false }];
        let mut decompiler = Decompiler::open(Arch::X86_64, false, &segments).expect("open");
        let text = decompiler.decompile(0x1000, "sum_to").expect("decompile");
        assert!(text.contains("sum_to"), "{text}");
        assert!(text.contains("return"), "{text}");
    }

    #[test]
    fn s390x_is_unsupported() {
        assert!(language_id(Arch::S390x, true).is_none());
    }
}
