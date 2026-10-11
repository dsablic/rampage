//! A safe wrapper over Ghidra's decompiler, embedded through a C ABI shim (see `src/shim.cc`). A `Decompiler`
//! holds one Ghidra architecture over the program's executable segments and decompiles functions on demand.
//!
//! Ghidra's processor specifications (the compiled `.sla` files) are found at a "sleigh home": a directory that
//! contains a `Ghidra/Processors` tree. `sleigh_home` prefers the bundled specifications; set
//! `GHIDRA_INSTALL_DIR` to override that tree.

mod abi;
pub mod results;
mod specs;
pub mod worker;
pub use results::{StructuredResult, parse_results};

pub use abi::{DataOrganization, DecompilerOptions, Platform, language_id, language_id_with_options};
pub use specs::sleigh_home;

use std::ffi::{CStr, CString, c_char};
use std::sync::Mutex;

use rampage_arch::Arch;

/// Ghidra's decompiler library keeps process-global state and is not built for concurrent use, so every call
/// into it is serialized.
static FFI_LOCK: Mutex<()> = Mutex::new(());

/// Prototypes for common C library functions, so their calls show typed arguments (a `char *` argument renders
/// the string it points at). Ghidra's C parser only accepts its sized core types (`int4`, `uint8`, `char`, ...),
/// and a prototype binds only to a function symbol that already exists, so these are applied by name after the
/// known symbols are registered. Placeholders are resolved using the selected compiler's data organization.
const C_PROTOTYPES: &[(&str, &str)] = &[
    // stdio
    ("puts", "int4 puts(char *s)"),
    ("fputs", "int4 fputs(char *s, void *stream)"),
    ("printf", "int4 printf(char *fmt, ...)"),
    ("fprintf", "int4 fprintf(void *stream, char *fmt, ...)"),
    ("dprintf", "int4 dprintf(int4 fd, char *fmt, ...)"),
    ("sprintf", "int4 sprintf(char *str, char *fmt, ...)"),
    ("snprintf", "int4 snprintf(char *str, {size_t} n, char *fmt, ...)"),
    ("vprintf", "int4 vprintf(char *fmt, void *ap)"),
    ("vfprintf", "int4 vfprintf(void *stream, char *fmt, void *ap)"),
    ("vsnprintf", "int4 vsnprintf(char *str, {size_t} n, char *fmt, void *ap)"),
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
    ("fseek", "int4 fseek(void *stream, {long} off, int4 whence)"),
    ("ftell", "{long} ftell(void *stream)"),
    ("rewind", "void rewind(void *stream)"),
    ("fread", "{size_t} fread(void *ptr, {size_t} size, {size_t} n, void *stream)"),
    ("fwrite", "{size_t} fwrite(void *ptr, {size_t} size, {size_t} n, void *stream)"),
    ("setvbuf", "int4 setvbuf(void *stream, char *buf, int4 mode, {size_t} size)"),
    ("remove", "int4 remove(char *path)"),
    ("rename", "int4 rename(char *from, char *to)"),
    ("tmpfile", "void * tmpfile(void)"),
    // string
    ("strlen", "{size_t} strlen(char *s)"),
    ("strnlen", "{size_t} strnlen(char *s, {size_t} n)"),
    ("strcpy", "char * strcpy(char *dst, char *src)"),
    ("strncpy", "char * strncpy(char *dst, char *src, {size_t} n)"),
    ("strcat", "char * strcat(char *dst, char *src)"),
    ("strncat", "char * strncat(char *dst, char *src, {size_t} n)"),
    ("strcmp", "int4 strcmp(char *a, char *b)"),
    ("strncmp", "int4 strncmp(char *a, char *b, {size_t} n)"),
    ("strcasecmp", "int4 strcasecmp(char *a, char *b)"),
    ("strncasecmp", "int4 strncasecmp(char *a, char *b, {size_t} n)"),
    ("strchr", "char * strchr(char *s, int4 c)"),
    ("strrchr", "char * strrchr(char *s, int4 c)"),
    ("strstr", "char * strstr(char *haystack, char *needle)"),
    ("strtok", "char * strtok(char *str, char *delim)"),
    ("strspn", "{size_t} strspn(char *s, char *accept)"),
    ("strcspn", "{size_t} strcspn(char *s, char *reject)"),
    ("strpbrk", "char * strpbrk(char *s, char *accept)"),
    ("strdup", "char * strdup(char *s)"),
    ("strndup", "char * strndup(char *s, {size_t} n)"),
    ("strerror", "char * strerror(int4 errnum)"),
    ("strtol", "{long} strtol(char *s, char **end, int4 base)"),
    ("strtoul", "{ulong} strtoul(char *s, char **end, int4 base)"),
    ("strtod", "float8 strtod(char *s, char **end)"),
    // memory
    ("memcpy", "void * memcpy(void *dst, void *src, {size_t} n)"),
    ("memmove", "void * memmove(void *dst, void *src, {size_t} n)"),
    ("memset", "void * memset(void *s, int4 c, {size_t} n)"),
    ("memcmp", "int4 memcmp(void *a, void *b, {size_t} n)"),
    ("memchr", "void * memchr(void *s, int4 c, {size_t} n)"),
    ("bzero", "void bzero(void *s, {size_t} n)"),
    ("bcopy", "void bcopy(void *src, void *dst, {size_t} n)"),
    // stdlib
    ("malloc", "void * malloc({size_t} n)"),
    ("calloc", "void * calloc({size_t} count, {size_t} size)"),
    ("realloc", "void * realloc(void *p, {size_t} n)"),
    ("reallocarray", "void * reallocarray(void *p, {size_t} count, {size_t} size)"),
    ("free", "void free(void *p)"),
    ("aligned_alloc", "void * aligned_alloc({size_t} align, {size_t} n)"),
    ("posix_memalign", "int4 posix_memalign(void **p, {size_t} align, {size_t} n)"),
    ("exit", "void exit(int4 status)"),
    ("_exit", "void _exit(int4 status)"),
    ("abort", "void abort(void)"),
    ("atexit", "int4 atexit(void *fn)"),
    ("getenv", "char * getenv(char *name)"),
    ("setenv", "int4 setenv(char *name, char *value, int4 overwrite)"),
    ("system", "int4 system(char *command)"),
    ("atoi", "int4 atoi(char *s)"),
    ("atol", "{long} atol(char *s)"),
    ("atof", "float8 atof(char *s)"),
    ("abs", "int4 abs(int4 x)"),
    ("labs", "{long} labs({long} x)"),
    ("qsort", "void qsort(void *base, {size_t} n, {size_t} size, void *cmp)"),
    ("bsearch", "void * bsearch(void *key, void *base, {size_t} n, {size_t} size, void *cmp)"),
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
    ("read", "{ssize_t} read(int4 fd, void *buf, {size_t} n)"),
    ("write", "{ssize_t} write(int4 fd, void *buf, {size_t} n)"),
    ("close", "int4 close(int4 fd)"),
    ("open", "int4 open(char *path, int4 flags, ...)"),
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
    ("getcwd", "char * getcwd(char *buf, {size_t} size)"),
    ("chdir", "int4 chdir(char *path)"),
    // math
    ("pow", "float8 pow(float8 x, float8 y)"),
    ("sqrt", "float8 sqrt(float8 x)"),
    ("fabs", "float8 fabs(float8 x)"),
    ("floor", "float8 floor(float8 x)"),
    ("ceil", "float8 ceil(float8 x)"),
    ("sin", "float8 sin(float8 x)"),
    ("cos", "float8 cos(float8 x)"),
    // pthread (basics)
    ("pthread_create", "int4 pthread_create(void *thread, void *attr, void *start, void *arg)"),
    ("pthread_mutex_lock", "int4 pthread_mutex_lock(void *mutex)"),
    ("pthread_mutex_unlock", "int4 pthread_mutex_unlock(void *mutex)"),
    // assert / error helpers
    ("__assert_fail", "void __assert_fail(char *assertion, char *file, uint4 line, char *fn)"),
    // stdio (more)
    ("vsprintf", "int4 vsprintf(char *str, char *fmt, void *ap)"),
    ("fileno", "int4 fileno(void *stream)"),
    ("ungetc", "int4 ungetc(int4 c, void *stream)"),
    ("fseeko", "int4 fseeko(void *stream, {long} off, int4 whence)"),
    ("ftello", "{long} ftello(void *stream)"),
    ("getline", "{ssize_t} getline(char **line, {size_t} *n, void *stream)"),
    ("getdelim", "{ssize_t} getdelim(char **line, {size_t} *n, int4 delim, void *stream)"),
    // string / memory (more)
    ("strsep", "char * strsep(char **stringp, char *delim)"),
    ("strtok_r", "char * strtok_r(char *str, char *delim, char **saveptr)"),
    ("strlcpy", "{size_t} strlcpy(char *dst, char *src, {size_t} size)"),
    ("strlcat", "{size_t} strlcat(char *dst, char *src, {size_t} size)"),
    ("memccpy", "void * memccpy(void *dst, void *src, int4 c, {size_t} n)"),
    ("strcasestr", "char * strcasestr(char *haystack, char *needle)"),
    ("memrchr", "void * memrchr(void *s, int4 c, {size_t} n)"),
    // stdlib (more)
    ("strtoll", "{long} strtoll(char *s, char **end, int4 base)"),
    ("strtoull", "{ulong} strtoull(char *s, char **end, int4 base)"),
    ("mkstemp", "int4 mkstemp(char *template)"),
    ("getopt", "int4 getopt(int4 argc, char **argv, char *optstring)"),
    ("setlocale", "char * setlocale(int4 category, char *locale)"),
    ("putenv", "int4 putenv(char *entry)"),
    ("unsetenv", "int4 unsetenv(char *name)"),
    // unistd / files (more)
    ("fcntl", "int4 fcntl(int4 fd, int4 cmd, ...)"),
    ("ioctl", "int4 ioctl(int4 fd, {ulong} request, ...)"),
    ("stat", "int4 stat(char *path, void *buf)"),
    ("fstat", "int4 fstat(int4 fd, void *buf)"),
    ("lstat", "int4 lstat(char *path, void *buf)"),
    ("mmap", "void * mmap(void *addr, {size_t} length, int4 prot, int4 flags, int4 fd, {long} offset)"),
    ("munmap", "int4 munmap(void *addr, {size_t} length)"),
    ("mprotect", "int4 mprotect(void *addr, {size_t} length, int4 prot)"),
    ("readlink", "{ssize_t} readlink(char *path, char *buf, {size_t} size)"),
    ("symlink", "int4 symlink(char *target, char *linkpath)"),
    ("kill", "int4 kill(int4 pid, int4 sig)"),
    ("waitpid", "int4 waitpid(int4 pid, void *status, int4 options)"),
    ("signal", "void * signal(int4 signum, void *handler)"),
    ("getuid", "uint4 getuid(void)"),
    ("geteuid", "uint4 geteuid(void)"),
    ("socket", "int4 socket(int4 domain, int4 type, int4 protocol)"),
    ("connect", "int4 connect(int4 fd, void *addr, uint4 addrlen)"),
    ("send", "{ssize_t} send(int4 fd, void *buf, {size_t} n, int4 flags)"),
    ("recv", "{ssize_t} recv(int4 fd, void *buf, {size_t} n, int4 flags)"),
    // C++ runtime (Itanium ABI)
    ("_Znwm", "void * _Znwm({size_t} size)"),
    ("_Znam", "void * _Znam({size_t} size)"),
    ("_ZdlPv", "void _ZdlPv(void *p)"),
    ("_ZdaPv", "void _ZdaPv(void *p)"),
    ("__cxa_throw", "void __cxa_throw(void *thrown, void *type, void *destructor)"),
    ("__cxa_begin_catch", "void * __cxa_begin_catch(void *exception)"),
    ("__cxa_end_catch", "void __cxa_end_catch(void)"),
    ("__cxa_atexit", "int4 __cxa_atexit(void *fn, void *arg, void *dso)"),
    ("__cxa_guard_acquire", "int4 __cxa_guard_acquire(void *guard)"),
    ("__cxa_guard_release", "void __cxa_guard_release(void *guard)"),
    ("__stack_chk_fail", "void __stack_chk_fail(void)"),
    ("__errno_location", "int4 * __errno_location(void)"),
    // Win32 (common)
    ("GetProcAddress", "void * GetProcAddress(void *module, char *name)"),
    ("LoadLibraryA", "void * LoadLibraryA(char *name)"),
    ("GetModuleHandleA", "void * GetModuleHandleA(char *name)"),
    ("VirtualAlloc", "void * VirtualAlloc(void *addr, {size_t} size, uint4 type, uint4 protect)"),
    ("VirtualProtect", "int4 VirtualProtect(void *addr, {size_t} size, uint4 protect, uint4 *old)"),
    ("WriteFile", "int4 WriteFile(void *file, void *buf, uint4 n, uint4 *written, void *overlapped)"),
    ("ReadFile", "int4 ReadFile(void *file, void *buf, uint4 n, uint4 *read, void *overlapped)"),
    ("CloseHandle", "int4 CloseHandle(void *handle)"),
    ("GetLastError", "uint4 GetLastError(void)"),
    ("ExitProcess", "void ExitProcess(uint4 exit_code)"),
    ("MessageBoxA", "int4 MessageBoxA(void *wnd, char *text, char *caption, uint4 type)"),
];

/// The C prototype for a well-known library function, spelled with `name` as the function's name so it binds to
/// a symbol registered under that exact name. `None` when the name is not one rampage carries a prototype for, or
/// is not a plain C identifier (so it cannot be parsed). The library function is matched after stripping a leading
/// underscore. Non-identifier stub spellings require address-based binding rather than this helper.
/// This legacy helper assumes LP64. Use `Decompiler::c_prototype` for the selected target's widths.
pub fn c_prototype(name: &str) -> Option<String> {
    render_prototype(name, DataOrganization { pointer: 8, int: 4, long: 8 }, false)
}

fn render_prototype(name: &str, sizes: DataOrganization, cdecl: bool) -> Option<String> {
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
        return None;
    }
    let find = |key: &str| C_PROTOTYPES.iter().find(|(known, _)| *known == key);
    // Prefer an exact match (so names that really start with an underscore, like `_exit`, resolve), then fall
    // back to the stripped spelling (so a Mach-O `_puts` stub matches `puts`).
    let bare = name.trim_start_matches('_');
    let (known, decl) = find(name).or_else(|| find(bare))?;
    // The stored declaration spells the canonical name; substitute the actual symbol name so it binds to it.
    let decl = decl
        .replacen(known, name, 1)
        .replace("{size_t}", &format!("uint{}", sizes.pointer))
        .replace("{ssize_t}", &format!("int{}", sizes.pointer))
        .replace("{long}", &format!("int{}", sizes.long))
        .replace("{ulong}", &format!("uint{}", sizes.long));
    let convention = if cdecl { "__cdecl " } else { "" };
    Some(format!("extern {convention}{decl};"))
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
    fn rampage_decomp_symbol(handle: *mut Opaque, addr: u64, name: *const c_char) -> *const c_char;
    fn rampage_decomp_import(
        handle: *mut Opaque,
        slot: u64,
        target: u64,
        has_target: u8,
        name: *const c_char,
    ) -> *const c_char;
    fn rampage_decomp_prototype(handle: *mut Opaque, addr: u64, indirect: u8, text: *const c_char) -> *const c_char;
    fn rampage_decomp_global(handle: *mut Opaque, addr: u64, text: *const c_char) -> *const c_char;
    fn rampage_decomp_parse_c(handle: *mut Opaque, text: *const c_char) -> *const c_char;
    fn rampage_decomp_error(handle: *mut Opaque) -> *const c_char;
    fn rampage_decomp_import_target(handle: *mut Opaque, slot: u64) -> u64;
    fn rampage_decomp_data_organization(handle: *mut Opaque, pointer: *mut i32, int: *mut i32, long: *mut i32);
    fn rampage_decomp_set_modes(
        handle: *mut Opaque,
        count: usize,
        addresses: *const u64,
        thumb: *const u8,
    ) -> *const c_char;
    fn rampage_decomp_function(handle: *mut Opaque, addr: u64, name: *const c_char, thumb: u8) -> *mut c_char;
    fn rampage_decomp_free_string(text: *mut c_char);
    fn rampage_decomp_token_count(handle: *mut Opaque) -> usize;
    fn rampage_decomp_token_span(handle: *mut Opaque, index: usize, start: *mut usize, end: *mut usize) -> u8;
    fn rampage_decomp_results(handle: *mut Opaque) -> *const c_char;
    fn rampage_decomp_token(
        handle: *mut Opaque,
        index: usize,
        kind: *mut *const c_char,
        address: *mut u64,
        has_address: *mut u8,
    ) -> *const c_char;
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

/// A decompiler over one program's executable segments.
pub struct Decompiler {
    handle: *mut Opaque,
    arch: Arch,
    data_organization: DataOrganization,
    language_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    pub text: String,
    pub kind: String,
    pub address: Option<u64>,
    pub span: Option<(usize, usize)>,
}

// SAFETY: the handle is only ever used while holding FFI_LOCK, so it is touched by one thread at a time.
unsafe impl Send for Decompiler {}

impl Decompiler {
    pub fn structured_result(&self) -> Result<StructuredResult, Error> {
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: valid handle under FFI_LOCK; JSON is owned by the handle until its next decompilation.
        let text = unsafe { rampage_decomp_results(self.handle) };
        if text.is_null() {
            return Err(Error::Ghidra("no successful structured decompilation result".to_owned()));
        }
        parse_results(&unsafe { CStr::from_ptr(text) }.to_string_lossy())
    }
    /// Registers a typed global; overlaps are rejected rather than replacing another symbol.
    pub fn add_global(&mut self, address: u64, declaration: &str) -> Result<(), Error> {
        self.valid_address(address)?;
        let declaration = CString::new(declaration).map_err(|_| Error::Ghidra("global contains NUL".to_owned()))?;
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: checked address, valid handle and C declaration throughout the serialized call.
        ffi_result(unsafe { rampage_decomp_global(self.handle, address, declaration.as_ptr()) })
    }
    /// Copies address-linked semantic tokens from the most recent successful decompilation.
    pub fn tokens(&self) -> Vec<Token> {
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: valid handle under FFI_LOCK; indices remain valid while the lock is held.
        let count = unsafe { rampage_decomp_token_count(self.handle) };
        (0..count)
            .filter_map(|index| {
                let (mut kind, mut address, mut present) = (std::ptr::null(), 0, 0);
                let text = unsafe { rampage_decomp_token(self.handle, index, &mut kind, &mut address, &mut present) };
                if text.is_null() || kind.is_null() {
                    return None;
                }
                let (mut start, mut end) = (0, 0);
                let span = unsafe { rampage_decomp_token_span(self.handle, index, &mut start, &mut end) };
                Some(Token {
                    text: unsafe { CStr::from_ptr(text) }.to_string_lossy().into_owned(),
                    kind: unsafe { CStr::from_ptr(kind) }.to_string_lossy().into_owned(),
                    address: (present != 0).then_some(address),
                    span: (span != 0).then_some((start, end)),
                })
            })
            .collect()
    }
    /// Returns the registered import target, including an external-only address reserved outside the image.
    pub fn import_target(&self, slot: u64) -> Option<u64> {
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: read-only query over a valid handle under the global FFI lock.
        let target = unsafe { rampage_decomp_import_target(self.handle, slot) };
        (target != 0).then_some(target)
    }
    fn valid_address(&self, address: u64) -> Result<(), Error> {
        if self.arch.pointer_size() == 4 && address > u64::from(u32::MAX) {
            return Err(Error::Ghidra("address exceeds target width".to_owned()));
        }
        Ok(())
    }

    /// Registers or updates a function's display name, independent of its signature identity.
    pub fn set_symbol(&mut self, address: u64, name: &str) -> Result<(), Error> {
        self.valid_address(address)?;
        let name = CString::new(name).map_err(|_| Error::Ghidra("symbol contains NUL".to_owned()))?;
        if name.as_bytes().is_empty() {
            return Err(Error::Ghidra("empty symbol".to_owned()));
        }
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: handle, name and address are valid throughout this serialized call.
        ffi_result(unsafe { rampage_decomp_symbol(self.handle, address, name.as_ptr()) })
    }

    /// Binds an import slot to a known stub or an external-only function. Slot bytes are not interpreted as code.
    pub fn add_import(&mut self, slot: u64, target: Option<u64>, name: &str) -> Result<(), Error> {
        self.valid_address(slot)?;
        if let Some(target) = target {
            self.valid_address(target)?;
        }
        let name = CString::new(name).map_err(|_| Error::Ghidra("symbol contains NUL".to_owned()))?;
        if name.as_bytes().is_empty() {
            return Err(Error::Ghidra("empty import name".to_owned()));
        }
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: valid serialized handle, checked addresses and a live C string.
        ffi_result(unsafe {
            rampage_decomp_import(self.handle, slot, target.unwrap_or(0), u8::from(target.is_some()), name.as_ptr())
        })
    }

    /// Applies one C signature by address, not by its declaration's name. `indirect` addresses an import slot.
    pub fn apply_prototype(&mut self, address: u64, indirect: bool, declaration: &str) -> Result<(), Error> {
        self.valid_address(address)?;
        let declaration = CString::new(declaration).map_err(|_| Error::Ghidra("prototype contains NUL".to_owned()))?;
        let _guard = FFI_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
        // SAFETY: valid serialized handle and a live C declaration; the returned error belongs to the handle.
        ffi_result(unsafe { rampage_decomp_prototype(self.handle, address, u8::from(indirect), declaration.as_ptr()) })
    }
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
        Self::open_with_options(arch, big_endian, regions, &DecompilerOptions::default())
    }

    /// Opens mappings with an explicit platform/compiler specification. Unknown IDs and inconsistent C data
    /// models are rejected instead of silently selecting another compiler or applying incorrect prototypes.
    pub fn open_with_options(
        arch: Arch,
        big_endian: bool,
        regions: &[MemoryRegion],
        options: &DecompilerOptions,
    ) -> Result<Decompiler, Error> {
        validate_regions(arch, regions)?;
        let language_id = language_id_with_options(arch, big_endian, options)?;
        let home = sleigh_home().ok_or(Error::NoSleighHome)?;
        let home = CString::new(home.as_os_str().to_string_lossy().as_bytes()).map_err(|_| Error::NoSleighHome)?;
        let langid = CString::new(language_id.as_str()).map_err(|_| Error::UnsupportedArch(arch))?;

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
        let (mut pointer, mut int, mut long) = (0, 0, 0);
        // SAFETY: the initialized handle and output field pointers are valid throughout the locked call.
        unsafe {
            rampage_decomp_data_organization(handle, &mut pointer, &mut int, &mut long);
        }
        let compiler = language_id.rsplit(':').next().expect("compiler field");
        let checked = abi::checked_data_organization([pointer, int, long]).and_then(|organization| {
            abi::validate_data_organization(arch, compiler, organization).map(|()| organization)
        });
        let data_organization = match checked {
            Ok(organization) => organization,
            Err(error) => {
                // SAFETY: initialization succeeded, but the selected C data model is incompatible with the target.
                unsafe {
                    rampage_decomp_close(handle);
                }
                return Err(error);
            }
        };
        Ok(Decompiler { handle, arch, data_organization, language_id })
    }

    pub fn data_organization(&self) -> DataOrganization {
        self.data_organization
    }

    pub fn language_id(&self) -> &str {
        &self.language_id
    }

    /// Renders a common runtime prototype with this handle's compiler-specific widths and calling convention.
    /// OS/library-dependent typedefs (`off_t`, `time_t`, `clock_t`, `pthread_t`) are intentionally not guessed.
    pub fn c_prototype(&self, name: &str) -> Option<String> {
        let compiler = self.language_id.rsplit(':').next()?;
        if !abi::has_c_runtime(compiler) {
            return None;
        }
        let cdecl = self.arch == Arch::X86 && abi::is_windows(compiler);
        if abi::is_windows(compiler) && matches!(name.trim_start_matches('_'), "read" | "write" | "getcwd") {
            return None;
        }
        render_prototype(name, self.data_organization, cdecl)
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

fn ffi_result(error: *const c_char) -> Result<(), Error> {
    if error.is_null() {
        Ok(())
    } else {
        // SAFETY: callers hold FFI_LOCK while copying the shim-owned, NUL-terminated error string.
        Err(Error::Ghidra(unsafe { CStr::from_ptr(error) }.to_string_lossy().into_owned()))
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
        assert!(home.file_name().unwrap().to_string_lossy().starts_with("specs-"), "{home:?}");
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
        let regions: Vec<_> = segments
            .iter()
            .map(|segment| MemoryRegion {
                base: segment.base,
                bytes: segment.bytes,
                size: segment.bytes.len() as u64,
                readable: true,
                writable: false,
                executable: true,
            })
            .collect();
        for (arch, platform) in [
            (Arch::X86, Platform::Default),
            (Arch::X86, Platform::Windows),
            (Arch::X86_64, Platform::Default),
            (Arch::X86_64, Platform::Windows),
            (Arch::Aarch64, Platform::Windows),
        ] {
            let options = DecompilerOptions { platform, compiler: None, arm_be8: false };
            let mut decompiler = Decompiler::open_with_options(arch, false, &regions, &options).expect("open");
            for (index, (name, _)) in C_PROTOTYPES.iter().enumerate() {
                let address = 0x1000 + (index as u64) * 8;
                decompiler.add_symbol(address, name);
                if let Some(prototype) = decompiler.c_prototype(name) {
                    decompiler
                        .parse_c(&prototype)
                        .unwrap_or_else(|error| panic!("{arch}/{platform:?}/{name}: {error}"));
                }
            }
        }
    }
}
