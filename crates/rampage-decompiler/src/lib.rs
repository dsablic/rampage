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

/// Prototypes for common C library functions, so their calls show typed arguments (a `char *` argument renders
/// the string it points at). Ghidra's C parser only accepts its sized core types (`int4`, `uint8`, `char`, ...),
/// and a prototype binds only to a function symbol that already exists, so these are applied by name after the
/// known symbols are registered. Size-typed parameters use `uint8`, correct for the 64-bit targets this matters
/// most for.
const C_PROTOTYPES: &[(&str, &str)] = &[
    // stdio
    ("puts", "int4 puts(char *s)"),
    ("fputs", "int4 fputs(char *s, void *stream)"),
    ("printf", "int4 printf(char *fmt, ...)"),
    ("fprintf", "int4 fprintf(void *stream, char *fmt, ...)"),
    ("dprintf", "int4 dprintf(int4 fd, char *fmt, ...)"),
    ("sprintf", "int4 sprintf(char *str, char *fmt, ...)"),
    ("snprintf", "int4 snprintf(char *str, uint8 n, char *fmt, ...)"),
    ("vprintf", "int4 vprintf(char *fmt, void *ap)"),
    ("vfprintf", "int4 vfprintf(void *stream, char *fmt, void *ap)"),
    ("vsnprintf", "int4 vsnprintf(char *str, uint8 n, char *fmt, void *ap)"),
    ("scanf", "int4 scanf(char *fmt, ...)"),
    ("fscanf", "int4 fscanf(void *stream, char *fmt, ...)"),
    ("sscanf", "int4 sscanf(char *str, char *fmt, ...)"),
    ("putchar", "int4 putchar(int4 c)"),
    ("getchar", "int4 getchar(void)"),
    ("fputc", "int4 fputc(int4 c, void *stream)"),
    ("fgetc", "int4 fgetc(void *stream)"),
    ("putc", "int4 putc(int4 c, void *stream)"),
    ("getc", "int4 getc(void *stream)"),
    ("fgets", "char * fgets(char *s, int4 n, void *stream)"),
    ("perror", "void perror(char *s)"),
    ("fopen", "void * fopen(char *path, char *mode)"),
    ("fdopen", "void * fdopen(int4 fd, char *mode)"),
    ("freopen", "void * freopen(char *path, char *mode, void *stream)"),
    ("fclose", "int4 fclose(void *stream)"),
    ("fflush", "int4 fflush(void *stream)"),
    ("fseek", "int4 fseek(void *stream, int8 off, int4 whence)"),
    ("ftell", "int8 ftell(void *stream)"),
    ("rewind", "void rewind(void *stream)"),
    ("fread", "uint8 fread(void *ptr, uint8 size, uint8 n, void *stream)"),
    ("fwrite", "uint8 fwrite(void *ptr, uint8 size, uint8 n, void *stream)"),
    ("setvbuf", "int4 setvbuf(void *stream, char *buf, int4 mode, uint8 size)"),
    ("remove", "int4 remove(char *path)"),
    ("rename", "int4 rename(char *from, char *to)"),
    ("tmpfile", "void * tmpfile(void)"),
    // string
    ("strlen", "uint8 strlen(char *s)"),
    ("strnlen", "uint8 strnlen(char *s, uint8 n)"),
    ("strcpy", "char * strcpy(char *dst, char *src)"),
    ("strncpy", "char * strncpy(char *dst, char *src, uint8 n)"),
    ("strcat", "char * strcat(char *dst, char *src)"),
    ("strncat", "char * strncat(char *dst, char *src, uint8 n)"),
    ("strcmp", "int4 strcmp(char *a, char *b)"),
    ("strncmp", "int4 strncmp(char *a, char *b, uint8 n)"),
    ("strcasecmp", "int4 strcasecmp(char *a, char *b)"),
    ("strncasecmp", "int4 strncasecmp(char *a, char *b, uint8 n)"),
    ("strchr", "char * strchr(char *s, int4 c)"),
    ("strrchr", "char * strrchr(char *s, int4 c)"),
    ("strstr", "char * strstr(char *haystack, char *needle)"),
    ("strtok", "char * strtok(char *str, char *delim)"),
    ("strspn", "uint8 strspn(char *s, char *accept)"),
    ("strcspn", "uint8 strcspn(char *s, char *reject)"),
    ("strpbrk", "char * strpbrk(char *s, char *accept)"),
    ("strdup", "char * strdup(char *s)"),
    ("strndup", "char * strndup(char *s, uint8 n)"),
    ("strerror", "char * strerror(int4 errnum)"),
    ("strtol", "int8 strtol(char *s, char **end, int4 base)"),
    ("strtoul", "uint8 strtoul(char *s, char **end, int4 base)"),
    ("strtod", "float8 strtod(char *s, char **end)"),
    // memory
    ("memcpy", "void * memcpy(void *dst, void *src, uint8 n)"),
    ("memmove", "void * memmove(void *dst, void *src, uint8 n)"),
    ("memset", "void * memset(void *s, int4 c, uint8 n)"),
    ("memcmp", "int4 memcmp(void *a, void *b, uint8 n)"),
    ("memchr", "void * memchr(void *s, int4 c, uint8 n)"),
    ("bzero", "void bzero(void *s, uint8 n)"),
    ("bcopy", "void bcopy(void *src, void *dst, uint8 n)"),
    // stdlib
    ("malloc", "void * malloc(uint8 n)"),
    ("calloc", "void * calloc(uint8 count, uint8 size)"),
    ("realloc", "void * realloc(void *p, uint8 n)"),
    ("reallocarray", "void * reallocarray(void *p, uint8 count, uint8 size)"),
    ("free", "void free(void *p)"),
    ("aligned_alloc", "void * aligned_alloc(uint8 align, uint8 n)"),
    ("posix_memalign", "int4 posix_memalign(void **p, uint8 align, uint8 n)"),
    ("exit", "void exit(int4 status)"),
    ("_exit", "void _exit(int4 status)"),
    ("abort", "void abort(void)"),
    ("atexit", "int4 atexit(void *fn)"),
    ("getenv", "char * getenv(char *name)"),
    ("setenv", "int4 setenv(char *name, char *value, int4 overwrite)"),
    ("system", "int4 system(char *command)"),
    ("atoi", "int4 atoi(char *s)"),
    ("atol", "int8 atol(char *s)"),
    ("atof", "float8 atof(char *s)"),
    ("abs", "int4 abs(int4 x)"),
    ("labs", "int8 labs(int8 x)"),
    ("qsort", "void qsort(void *base, uint8 n, uint8 size, void *cmp)"),
    ("bsearch", "void * bsearch(void *key, void *base, uint8 n, uint8 size, void *cmp)"),
    ("rand", "int4 rand(void)"),
    ("srand", "void srand(uint4 seed)"),
    // ctype
    ("isalpha", "int4 isalpha(int4 c)"),
    ("isdigit", "int4 isdigit(int4 c)"),
    ("isalnum", "int4 isalnum(int4 c)"),
    ("isspace", "int4 isspace(int4 c)"),
    ("isupper", "int4 isupper(int4 c)"),
    ("islower", "int4 islower(int4 c)"),
    ("toupper", "int4 toupper(int4 c)"),
    ("tolower", "int4 tolower(int4 c)"),
    // unistd / POSIX I/O
    ("read", "int8 read(int4 fd, void *buf, uint8 n)"),
    ("write", "int8 write(int4 fd, void *buf, uint8 n)"),
    ("close", "int4 close(int4 fd)"),
    ("open", "int4 open(char *path, int4 flags, ...)"),
    ("lseek", "int8 lseek(int4 fd, int8 off, int4 whence)"),
    ("unlink", "int4 unlink(char *path)"),
    ("access", "int4 access(char *path, int4 mode)"),
    ("dup", "int4 dup(int4 fd)"),
    ("dup2", "int4 dup2(int4 old, int4 new)"),
    ("pipe", "int4 pipe(void *fds)"),
    ("fork", "int4 fork(void)"),
    ("execv", "int4 execv(char *path, char **argv)"),
    ("execve", "int4 execve(char *path, char **argv, char **envp)"),
    ("execvp", "int4 execvp(char *file, char **argv)"),
    ("getpid", "int4 getpid(void)"),
    ("sleep", "uint4 sleep(uint4 seconds)"),
    ("usleep", "int4 usleep(uint4 usec)"),
    ("getcwd", "char * getcwd(char *buf, uint8 size)"),
    ("chdir", "int4 chdir(char *path)"),
    // math
    ("pow", "float8 pow(float8 x, float8 y)"),
    ("sqrt", "float8 sqrt(float8 x)"),
    ("fabs", "float8 fabs(float8 x)"),
    ("floor", "float8 floor(float8 x)"),
    ("ceil", "float8 ceil(float8 x)"),
    ("sin", "float8 sin(float8 x)"),
    ("cos", "float8 cos(float8 x)"),
    // time
    ("time", "int8 time(void *t)"),
    ("clock", "int8 clock(void)"),
    // pthread (basics)
    ("pthread_create", "int4 pthread_create(void *thread, void *attr, void *start, void *arg)"),
    ("pthread_join", "int4 pthread_join(void *thread, void **retval)"),
    ("pthread_mutex_lock", "int4 pthread_mutex_lock(void *mutex)"),
    ("pthread_mutex_unlock", "int4 pthread_mutex_unlock(void *mutex)"),
    // assert / error helpers
    ("__assert_fail", "void __assert_fail(char *assertion, char *file, uint4 line, char *fn)"),
];

/// The C prototype for a well-known library function, spelled with `name` as the function's name so it binds to
/// a symbol registered under that exact name. `None` when the name is not one rampage carries a prototype for, or
/// is not a plain C identifier (so it cannot be parsed). The library function is matched after stripping a leading
/// underscore and any `@plt`/`@got` suffix, so stub spellings like `puts@plt` and `_malloc` resolve.
pub fn c_prototype(name: &str) -> Option<String> {
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    let find = |key: &str| C_PROTOTYPES.iter().find(|(known, _)| *known == key);
    // Prefer an exact match (so names that really start with an underscore, like `_exit`, resolve), then fall
    // back to the stripped spelling (so a Mach-O `_puts` stub or a `puts@plt` thunk matches `puts`).
    let bare = name.trim_start_matches('_').split('@').next().unwrap_or(name);
    let (known, decl) = find(name).or_else(|| find(bare))?;
    // The stored declaration spells the canonical name; substitute the actual symbol name so it binds to it.
    Some(format!("extern {};", decl.replacen(known, name, 1)))
}

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
        sizes: *const u64,
        readable: *const u8,
        executable: *const u8,
        writable: *const u8,
    ) -> *mut Opaque;
    fn rampage_decomp_add_symbol(handle: *mut Opaque, addr: u64, name: *const c_char);
    fn rampage_decomp_parse_c(handle: *mut Opaque, text: *const c_char) -> *const c_char;
    fn rampage_decomp_error(handle: *mut Opaque) -> *const c_char;
    fn rampage_decomp_set_modes(
        handle: *mut Opaque,
        count: usize,
        addresses: *const u64,
        thumb: *const u8,
    ) -> *const c_char;
    fn rampage_decomp_function(handle: *mut Opaque, addr: u64, name: *const c_char, thumb: u8) -> *mut c_char;
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

/// An explicit mapping. Bytes beyond `bytes` up to `size` are declared zero-fill, not missing file data.
pub struct MemoryRegion<'a> {
    pub base: u64,
    pub bytes: &'a [u8],
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

fn validate_regions(arch: Arch, regions: &[MemoryRegion]) -> Result<(), Error> {
    if regions.len() > 4096 {
        return Err(Error::Ghidra("memory region limit exceeded (4096)".to_owned()));
    }
    let mut ranges = Vec::with_capacity(regions.len());
    for region in regions {
        if region.size == 0 || region.bytes.len() as u64 > region.size {
            return Err(Error::Ghidra("invalid memory region size".to_owned()));
        }
        let last = region
            .base
            .checked_add(region.size - 1)
            .ok_or_else(|| Error::Ghidra("memory region overflows address space".to_owned()))?;
        if arch.pointer_size() == 4 && last > u64::from(u32::MAX) {
            return Err(Error::Ghidra("memory region exceeds the target address space".to_owned()));
        }
        ranges.push((region.base, last));
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 >= pair[1].0) {
        return Err(Error::Ghidra("overlapping decompiler memory regions".to_owned()));
    }
    Ok(())
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

/// Locates a directory holding a `Ghidra/Processors` specification tree, in order of preference:
/// `GHIDRA_INSTALL_DIR` if set, then the specifications vendored with this crate, then a Homebrew Ghidra install.
/// The vendored specifications mean a source build needs no external Ghidra install.
pub fn sleigh_home() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("GHIDRA_INSTALL_DIR") {
        return Some(PathBuf::from(dir));
    }
    let bundled = PathBuf::from(env!("RAMPAGE_BUNDLED_SPECS"));
    if bundled.join("Ghidra").is_dir() {
        return Some(bundled);
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
    arch: Arch,
}

// SAFETY: the handle is only ever used while holding FFI_LOCK, so it is touched by one thread at a time.
unsafe impl Send for Decompiler {}

impl Decompiler {
    /// Opens a decompiler for `arch` over `segments`. Each segment's bytes stay mapped at its base for the life
    /// of the decompiler, so functions anywhere in the loaded code can be decompiled.
    pub fn open(arch: Arch, big_endian: bool, segments: &[Segment]) -> Result<Decompiler, Error> {
        let regions: Vec<_> = segments
            .iter()
            .map(|segment| MemoryRegion {
                base: segment.base,
                bytes: segment.bytes,
                size: segment.bytes.len() as u64,
                readable: true,
                writable: segment.writable,
                executable: true,
            })
            .collect();
        Self::open_regions(arch, big_endian, &regions)
    }

    /// Opens explicitly permissioned mappings, retaining zero-fill without allocating its entire virtual size.
    pub fn open_regions(arch: Arch, big_endian: bool, regions: &[MemoryRegion]) -> Result<Decompiler, Error> {
        validate_regions(arch, regions)?;
        let langid = language_id(arch, big_endian).ok_or(Error::UnsupportedArch(arch))?;
        let home = sleigh_home().ok_or(Error::NoSleighHome)?;
        let home = CString::new(home.as_os_str().to_string_lossy().as_bytes()).map_err(|_| Error::NoSleighHome)?;
        let langid = CString::new(langid).map_err(|_| Error::UnsupportedArch(arch))?;

        let bases: Vec<u64> = regions.iter().map(|region| region.base).collect();
        let ptrs: Vec<*const u8> = regions.iter().map(|region| region.bytes.as_ptr()).collect();
        let lens: Vec<usize> = regions.iter().map(|region| region.bytes.len()).collect();
        let sizes: Vec<u64> = regions.iter().map(|region| region.size).collect();
        let readable: Vec<u8> = regions.iter().map(|region| u8::from(region.readable)).collect();
        let executable: Vec<u8> = regions.iter().map(|region| u8::from(region.executable)).collect();
        let writable: Vec<u8> = regions.iter().map(|region| u8::from(region.writable)).collect();

        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: the pointers and lengths describe `segments`, which outlive this call; the shim copies the
        // bytes before returning.
        let handle = unsafe {
            rampage_decomp_open(
                home.as_ptr(),
                langid.as_ptr(),
                regions.len(),
                bases.as_ptr(),
                ptrs.as_ptr(),
                lens.as_ptr(),
                sizes.as_ptr(),
                readable.as_ptr(),
                executable.as_ptr(),
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
        Ok(Decompiler { handle, arch })
    }

    /// Registers a known function address with a name, so calls to it render by name. Call before decompiling
    /// callers; names that fail to apply (e.g. a bad address) are silently skipped.
    pub fn add_symbol(&mut self, address: u64, name: &str) {
        let Ok(name) = CString::new(name) else { return };
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: handle is valid for the life of self; name is a valid C string for the call.
        unsafe { rampage_decomp_add_symbol(self.handle, address, name.as_ptr()) };
    }

    /// Parses C declarations (typedefs and prototypes) into the type database, so matching functions get typed
    /// signatures. Returns an error only when the text does not parse.
    pub fn parse_c(&mut self, declarations: &str) -> Result<(), Error> {
        let text = CString::new(declarations).map_err(|_| Error::Ghidra("declarations contain a NUL".to_owned()))?;
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: handle is valid for the life of self; text is a valid C string for the call.
        let error = unsafe { rampage_decomp_parse_c(self.handle, text.as_ptr()) };
        if error.is_null() {
            Ok(())
        } else {
            Err(Error::Ghidra(unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned()))
        }
    }

    /// Installs ARM context boundaries, which need not be aligned instruction addresses.
    pub fn set_code_modes(&mut self, modes: &[(u64, bool)]) -> Result<(), Error> {
        if modes.is_empty() {
            return Ok(());
        }
        if self.arch != Arch::Arm
            || modes.iter().any(|&(address, _)| address > u64::from(u32::MAX))
            || modes.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        {
            return Err(Error::Ghidra("mode points require sorted, unique ARM context boundaries".to_owned()));
        }
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        for batch in modes.chunks(4096) {
            let addresses: Vec<_> = batch.iter().map(|&(address, _)| address).collect();
            let thumb: Vec<_> = batch.iter().map(|&(_, thumb)| u8::from(thumb)).collect();
            // SAFETY: arrays have identical lengths and remain valid throughout the serialized call.
            let error =
                unsafe { rampage_decomp_set_modes(self.handle, batch.len(), addresses.as_ptr(), thumb.as_ptr()) };
            if !error.is_null() {
                return Err(Error::Ghidra(unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned()));
            }
        }
        Ok(())
    }

    /// Decompiles the function at `address` to C. `name`, when non-empty, is used as the function's name.
    /// `thumb` decodes the function as Thumb on 32-bit ARM; it is ignored on other targets.
    pub fn decompile(&mut self, address: u64, name: &str, thumb: bool) -> Result<String, Error> {
        let name = CString::new(name).unwrap_or_default();
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: handle is valid; the returned string is malloc'd by the shim and freed below.
        let text = unsafe { rampage_decomp_function(self.handle, address, name.as_ptr(), u8::from(thumb)) };
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
        0x85, 0xff, 0x7e, 0x13, 0x8d, 0x47, 0xff, 0x8d, 0x4f, 0xfe, 0x48, 0x0f, 0xaf, 0xc8, 0x48, 0xd1, 0xe9, 0x8d,
        0x04, 0x79, 0xff, 0xc8, 0xc3, 0x31, 0xc0, 0xc3, 0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00, 0x89, 0xf8, 0x39, 0xfe,
        0x0f, 0x4f, 0xc6, 0x39, 0xc2, 0x0f, 0x4f, 0xc2, 0xc3, 0x0f, 0x1f, 0x00, 0x0f, 0xb6, 0x0f, 0x84, 0xc9, 0x74,
        0x1f, 0x48, 0xff, 0xc7, 0xb8, 0xc5, 0x9d, 0x1c, 0x81, 0x90, 0x0f, 0xb6, 0xc9, 0x31, 0xc1, 0x69, 0xc1, 0x93,
        0x01, 0x00, 0x01, 0x0f, 0xb6, 0x0f, 0x48, 0xff, 0xc7, 0x84, 0xc9, 0x75, 0xeb, 0xc3, 0xb8, 0xc5, 0x9d, 0x1c,
        0x81, 0xc3,
    ];

    #[test]
    fn decompiles_x86_64_when_ghidra_is_present() {
        if sleigh_home().is_none() {
            return;
        }
        let segments = [Segment { base: 0x1000, bytes: X64_TEXT, writable: false }];
        let mut decompiler = Decompiler::open(Arch::X86_64, false, &segments).expect("open");
        let text = decompiler.decompile(0x1000, "sum_to", false).expect("decompile");
        assert!(text.contains("sum_to"), "{text}");
        assert!(text.contains("return"), "{text}");
    }

    #[test]
    fn s390x_is_unsupported() {
        assert!(language_id(Arch::S390x, true).is_none());
    }

    #[test]
    fn bundled_specifications_are_found_without_an_install() {
        // With no override, the specifications vendored with the crate should be used, so decompilation works
        // out of the box.
        if std::env::var_os("GHIDRA_INSTALL_DIR").is_some() {
            return;
        }
        let home = sleigh_home().expect("bundled specifications");
        assert!(home.ends_with("specs"), "{home:?}");
        assert!(home.join("Ghidra/Processors/x86/data/languages/x86.sla").is_file());
    }

    #[test]
    fn known_prototypes_apply_to_registered_symbols() {
        if sleigh_home().is_none() {
            return;
        }
        let segments = [Segment { base: 0x1000, bytes: X64_TEXT, writable: false }];
        let mut decompiler = Decompiler::open(Arch::X86_64, false, &segments).expect("open");
        // A prototype binds only to an existing symbol, so register the name first.
        decompiler.add_symbol(0x1000, "_puts");
        // The Mach-O stub name (_puts) keeps its exact spelling in the generated prototype.
        let prototype = c_prototype("_puts").expect("known prototype");
        assert!(prototype.contains("_puts"));
        decompiler.parse_c(&prototype).expect("prototype applies");
    }

    #[test]
    fn prototype_name_matching() {
        assert!(c_prototype("my_custom_function").is_none());
        // Non-identifier spellings cannot be parsed, so they get no prototype.
        assert!(c_prototype("puts@plt").is_none());
        assert!(c_prototype("malloc").unwrap().contains("malloc"));
    }

    #[test]
    fn every_bundled_prototype_parses() {
        if sleigh_home().is_none() {
            return;
        }
        // A buffer large enough to give every prototype its own symbol address.
        let code = vec![0xc3u8; C_PROTOTYPES.len() * 8 + 16];
        let segments = [Segment { base: 0x1000, bytes: &code, writable: false }];
        let mut decompiler = Decompiler::open(Arch::X86_64, false, &segments).expect("open");
        for (index, (name, _)) in C_PROTOTYPES.iter().enumerate() {
            let address = 0x1000 + (index as u64) * 8;
            decompiler.add_symbol(address, name);
            let prototype = c_prototype(name).expect("table entries have prototypes");
            decompiler.parse_c(&prototype).unwrap_or_else(|error| panic!("{name}: {error}"));
        }
    }
}
