//! Windows stubs for the fake (step 9.6a): MinGW-w64 `gdbserver.exe` and `lldb-server gdbserver` on Windows x64,
//! with a WoW64 (32-bit) process under gdbserver. No Windows host was available when these were written, so they
//! are built from the stubs' sources rather than recorded:
//!
//! - gdbserver: `gdbserver/server.cc` (`qSupported`, `qXfer:libraries:read`, `qXfer:exec-file:read`,
//!   `qGetTIBAddr`), `gdbserver/remote-utils.cc` (`prepare_resume_reply`: the signal, `swbreak`/`watch`, the
//!   expedited `rbp`, `rsp` and `rip`, then `thread`), `gdbserver/win32-low.cc` (DLLs at their base plus 0x1000,
//!   the executable left out, int3 stops with the pc moved back onto the int3) and `gdbserver/win32-i386-low.cc`
//!   (the `i386:x86-64` or `i386` description with the `Windows` OS ABI, `Z0`, `Z1`, `Z2` and `Z4` but not `Z3`),
//!   `gdb/nat/windows-nat.c` (exceptions as signals; `EXCEPTION_RECORD` as `qXfer:siginfo:read`).
//! - lldb-server: `lldb/source/Plugins/Process/gdb-remote/GDBRemoteCommunicationServerLLGS.cpp` (features, stop
//!   replies with `reason` and a hex `description`, `<library-list>` with `<section address>` at each image's
//!   base) and `lldb/source/Plugins/Process/Windows/Common/NativeProcessWindows.cpp` (the executable listed,
//!   exceptions described as `Exception 0x... encountered at address 0x...`, interrupts as SIGSTOP in the thread
//!   `DebugBreakProcess` creates, no hardware breakpoints).
//!
//! gdbserver sends one thread ID per `qfThreadInfo`/`qsThreadInfo` reply; the fake lists them in one reply, which
//! the client reads the same way.

use super::{Action, Script, le_hex};
use crate::packet::{self, encode_hex};

pub const MAIN_THREAD: u64 = 0x1a2c;
pub const SECOND_THREAD: u64 = 0x1b30;
/// The thread Windows creates to deliver an interrupt (`DebugBreakProcess` or a console Ctrl-Break).
pub const BREAKIN_THREAD: u64 = 0x1c44;
pub const PID: u64 = 0x2f8;
/// The main thread's TIB (TEB), and the process environment block it points to. A WoW64 process's 32-bit TEB is
/// 0x2000 above its 64-bit one, which gdbserver reports (`win32-low.cc`, `child_add_thread`).
pub const TIB: u64 = 0xd1_2345_e000;
pub const TIB32: u64 = 0x0030_2000;
pub const PEB: u64 = 0xd1_2345_d000;
pub const PEB32: u64 = 0x0030_0000;
/// The `qXfer:siginfo:read` request the client sends at gdbserver's packet size (`PacketSize=2001f`).
pub const SIGINFO_REQUEST: &str = "qXfer:siginfo:read::0,10000";

/// An image mapped in the fake process: the path the stub reports, the runtime base and the mapped bytes.
#[derive(Debug, Clone)]
pub struct WindowsImage {
    pub path: String,
    pub base: u64,
    pub mapped: Vec<u8>,
}

/// The process the Windows transcripts serve.
#[derive(Debug, Clone)]
pub struct WindowsProcess {
    /// The main executable first, then the DLLs.
    pub images: Vec<WindowsImage>,
    /// The main thread's general registers in GDB's order: `rax rbx rcx rdx rsi rdi rbp rsp r8..r15 rip` on x64,
    /// `eax ecx edx ebx esp ebp esi edi eip` in a WoW64 process.
    pub registers: Vec<u64>,
    /// A 32-bit process under a 64-bit gdbserver: the `i386` description, 32-bit DLLs from SysWOW64.
    pub wow64: bool,
    /// What `qXfer:exec-file:read` (gdbserver) answers.
    pub exec_file: String,
    /// Extra memory: `(address, bytes)`, such as the stack.
    pub memory: Vec<(u64, Vec<u8>)>,
    /// Whether gdbserver names the `Windows` OS ABI in its description, as gdbserver 16 and later do; earlier ones
    /// name none.
    pub osabi: bool,
}

impl WindowsProcess {
    /// An x64 process with `images` (the executable first), stopped at `pc` with the stack at `sp`.
    pub fn x64(images: Vec<WindowsImage>, pc: u64, sp: u64) -> Self {
        let mut registers: Vec<u64> = (0..17).map(|index| 0x100 + index).collect();
        registers[6] = sp + 0x40;
        registers[7] = sp;
        registers[16] = pc;
        let exec_file = images.first().map(|image| image.path.clone()).unwrap_or_default();
        Self { images, registers, wow64: false, exec_file, memory: Vec::new(), osabi: true }
    }

    /// A WoW64 process with `images`, stopped at `pc` with the stack at `sp`.
    pub fn wow64(images: Vec<WindowsImage>, pc: u64, sp: u64) -> Self {
        let mut registers: Vec<u64> = (0..9).map(|index| 0x100 + index).collect();
        registers[4] = sp;
        registers[5] = sp + 0x40;
        registers[8] = pc;
        let exec_file = images.first().map(|image| image.path.clone()).unwrap_or_default();
        Self { images, registers, wow64: true, exec_file, memory: Vec::new(), osabi: true }
    }

    fn width(&self) -> usize {
        if self.wow64 { 4 } else { 8 }
    }

    /// The registers gdbserver expedites, `rbp`, `rsp`, `rip` (`ebp`, `esp`, `eip`), as `regnum:value;` fields.
    fn expedited(&self, registers: &[u64]) -> String {
        let fields: [(u32, usize); 3] = if self.wow64 { [(5, 5), (4, 4), (8, 8)] } else { [(6, 6), (7, 7), (16, 16)] };
        fields
            .iter()
            .map(|(regnum, index)| format!("{regnum:02x}:{};", le_hex(registers[*index], self.width())))
            .collect()
    }

    /// With the pc at `pc`.
    pub fn at(&self, pc: u64) -> Vec<u64> {
        let mut registers = self.registers.clone();
        let pc_index = if self.wow64 { 8 } else { 16 };
        registers[pc_index] = pc;
        registers
    }
}

/// A gdbserver stop reply for `thread` with `registers` (see [`WindowsProcess::registers`]), in gdbserver's field
/// order: the signal, `extra` (`swbreak:;`, `watch:<address>;`), the expedited registers, `thread`.
pub fn gdbserver_stop(process: &WindowsProcess, registers: &[u64], thread: u64, signal: u8, extra: &str) -> String {
    format!("T{signal:02x}{extra}{}thread:{thread:x};", process.expedited(registers))
}

/// An lldb-server stop reply: the signal, `thread`, the expedited registers, `reason` and a hex `description`.
pub fn lldb_stop(
    process: &WindowsProcess,
    registers: &[u64],
    thread: u64,
    signal: u8,
    reason: &str,
    text: &str,
) -> String {
    let mut reply = format!("T{signal:02x}thread:{thread:x};{}", process.expedited(registers));
    if !reason.is_empty() {
        reply += &format!("reason:{reason};");
    }
    if !text.is_empty() {
        reply += &format!("description:{};", encode_hex(text.as_bytes()));
    }
    reply
}

/// The bytes of an `EXCEPTION_RECORD`: 152 of the 64-bit layout, or 80 of `EXCEPTION_RECORD32` (`wide` false).
pub fn exception_record(wide: bool, code: u32, address: u64, parameters: &[u64]) -> Vec<u8> {
    let mut record = vec![0u8; if wide { 152 } else { 80 }];
    record[..4].copy_from_slice(&code.to_le_bytes());
    if wide {
        record[16..24].copy_from_slice(&address.to_le_bytes());
        record[24..28].copy_from_slice(&(parameters.len() as u32).to_le_bytes());
        for (index, parameter) in parameters.iter().enumerate() {
            record[32 + 8 * index..40 + 8 * index].copy_from_slice(&parameter.to_le_bytes());
        }
    } else {
        record[12..16].copy_from_slice(&(address as u32).to_le_bytes());
        record[16..20].copy_from_slice(&(parameters.len() as u32).to_le_bytes());
        for (index, parameter) in parameters.iter().enumerate() {
            record[20 + 4 * index..24 + 4 * index].copy_from_slice(&(*parameter as u32).to_le_bytes());
        }
    }
    record
}

/// gdbserver's answer to [`SIGINFO_REQUEST`]: the whole record in one `l` reply, binary-escaped.
pub fn siginfo(record: &[u8]) -> Action {
    let mut reply = vec![b'l'];
    reply.extend_from_slice(record);
    Action::Raw(packet::encode(&reply))
}

/// The mapped bytes of a minimal PE image (headers and an empty `.text`), as a DLL the fake lists: `wide` PE32+,
/// `dll`, the header's `ImageBase` and `SizeOfImage`, and a CodeView record when given.
pub fn synthetic_image(
    wide: bool,
    dll: bool,
    image_base: u64,
    size: u32,
    codeview: Option<([u8; 16], u32)>,
) -> Vec<u8> {
    let mut bytes = vec![0u8; 0x2000];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    let (coff, optional) = (0x84, 0x98);
    let optional_size: u16 = if wide { 240 } else { 224 };
    bytes[coff..coff + 2].copy_from_slice(&(if wide { 0x8664u16 } else { 0x14c }).to_le_bytes());
    bytes[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
    bytes[coff + 4..coff + 8].copy_from_slice(&0x6553_0000u32.to_le_bytes());
    bytes[coff + 16..coff + 18].copy_from_slice(&optional_size.to_le_bytes());
    let characteristics: u16 = 0x22 | if dll { 0x2000 } else { 0 };
    bytes[coff + 18..coff + 20].copy_from_slice(&characteristics.to_le_bytes());
    bytes[optional..optional + 2].copy_from_slice(&(if wide { 0x20bu16 } else { 0x10b }).to_le_bytes());
    if wide {
        bytes[optional + 24..optional + 32].copy_from_slice(&image_base.to_le_bytes());
    } else {
        bytes[optional + 28..optional + 32].copy_from_slice(&(image_base as u32).to_le_bytes());
    }
    bytes[optional + 32..optional + 36].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[optional + 56..optional + 60].copy_from_slice(&size.to_le_bytes());
    bytes[optional + 60..optional + 64].copy_from_slice(&0x400u32.to_le_bytes());
    bytes[optional + 70..optional + 72].copy_from_slice(&0x4160u16.to_le_bytes());
    let directories = optional + if wide { 112 } else { 96 };
    bytes[directories - 4..directories].copy_from_slice(&16u32.to_le_bytes());
    let table = optional + optional_size as usize;
    bytes[table..table + 8].copy_from_slice(b".text\0\0\0");
    bytes[table + 8..table + 12].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[table + 12..table + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[table + 16..table + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[table + 20..table + 24].copy_from_slice(&0x400u32.to_le_bytes());
    if let Some((guid, age)) = codeview {
        // The debug directory at RVA 0x1800 and its RSDS record at 0x1820, both in `.text`.
        bytes[directories + 48..directories + 52].copy_from_slice(&0x1800u32.to_le_bytes());
        bytes[directories + 52..directories + 56].copy_from_slice(&28u32.to_le_bytes());
        bytes[0x1800 + 12..0x1800 + 16].copy_from_slice(&2u32.to_le_bytes());
        bytes[0x1800 + 16..0x1800 + 20].copy_from_slice(&32u32.to_le_bytes());
        bytes[0x1800 + 20..0x1800 + 24].copy_from_slice(&0x1820u32.to_le_bytes());
        bytes[0x1820..0x1824].copy_from_slice(b"RSDS");
        bytes[0x1824..0x1834].copy_from_slice(&guid);
        bytes[0x1834..0x1838].copy_from_slice(&age.to_le_bytes());
        bytes[0x1838..0x1840].copy_from_slice(b"lib.pdb\0");
    }
    bytes
}

fn u16_at(bytes: &[u8], at: usize) -> usize {
    u16::from_le_bytes([bytes[at], bytes[at + 1]]) as usize
}

fn u32_at(bytes: &[u8], at: usize) -> usize {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes")) as usize
}

/// Maps a PE file at `base` as the Windows loader does: the headers and each section at its RVA, the base
/// relocations applied for the move (DIR64 and HIGHLOW), and the runtime base written into
/// `OptionalHeader.ImageBase`. Written apart from the client's PE reader, so the two check each other.
pub fn map_pe(file: &[u8], base: u64) -> Vec<u8> {
    let lfanew = u32_at(file, 0x3c);
    let sections = u16_at(file, lfanew + 6);
    let optional = lfanew + 24;
    let wide = u16_at(file, optional) == 0x20b;
    let preferred = if wide {
        u64::from_le_bytes(file[optional + 24..optional + 32].try_into().expect("eight bytes"))
    } else {
        u32_at(file, optional + 28) as u64
    };
    let size = u32_at(file, optional + 56);
    let headers = u32_at(file, optional + 60);
    let mut image = vec![0u8; size];
    image[..headers].copy_from_slice(&file[..headers]);
    let table = optional + u16_at(file, lfanew + 20);
    for index in 0..sections {
        let at = table + 40 * index;
        let (rva, raw_size, raw) = (u32_at(file, at + 12), u32_at(file, at + 16), u32_at(file, at + 20));
        let virtual_size = u32_at(file, at + 8);
        let length = raw_size.min(virtual_size.max(raw_size)).min(file.len() - raw);
        image[rva..rva + length].copy_from_slice(&file[raw..raw + length]);
    }
    let delta = base.wrapping_sub(preferred);
    let directories = optional + if wide { 112 } else { 96 };
    let (reloc_rva, reloc_size) = (u32_at(&image, directories + 40), u32_at(&image, directories + 44));
    let mut at = reloc_rva;
    while reloc_size > 0 && at + 8 <= reloc_rva + reloc_size {
        let (page, block) = (u32_at(&image, at), u32_at(&image, at + 4));
        for entry in (at + 8..at + block).step_by(2) {
            let entry = u16_at(&image, entry);
            let target = page + (entry & 0xfff);
            match entry >> 12 {
                10 => {
                    let value = u64::from_le_bytes(image[target..target + 8].try_into().expect("eight bytes"));
                    image[target..target + 8].copy_from_slice(&value.wrapping_add(delta).to_le_bytes());
                }
                3 => {
                    let value = u32_at(&image, target) as u32;
                    image[target..target + 4].copy_from_slice(&value.wrapping_add(delta as u32).to_le_bytes());
                }
                _ => {}
            }
        }
        at += block.max(8);
    }
    if wide {
        image[optional + 24..optional + 32].copy_from_slice(&base.to_le_bytes());
    } else {
        image[optional + 28..optional + 32].copy_from_slice(&(base as u32).to_le_bytes());
    }
    image
}

/// GDB's x86 registers as gdbserver describes them (`gdb/features/i386/64bit-core.xml` and `64bit-sse.xml`, or
/// the 32-bit ones): name and bitsize, in register-number order.
fn gdb_registers(wow64: bool) -> Vec<(String, u32)> {
    let mut registers: Vec<(String, u32)> = Vec::new();
    let general: &[&str] = if wow64 {
        &["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "eip"]
    } else {
        &[
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14",
            "r15", "rip",
        ]
    };
    let width = if wow64 { 32 } else { 64 };
    registers.extend(general.iter().map(|name| ((*name).to_owned(), width)));
    registers.extend(["eflags", "cs", "ss", "ds", "es", "fs", "gs"].iter().map(|name| ((*name).to_owned(), 32)));
    registers.extend((0..8).map(|index| (format!("st{index}"), 80)));
    registers.extend(
        ["fctrl", "fstat", "ftag", "fiseg", "fioff", "foseg", "fooff", "fop"].map(|name| (name.to_owned(), 32)),
    );
    registers.extend((0..if wow64 { 8 } else { 16 }).map(|index| (format!("xmm{index}"), 128)));
    registers.push(("mxcsr".into(), 32));
    registers
}

/// The `g` reply for `registers` in gdbserver's layout: the general registers, `eflags` and the selectors, the
/// rest zero.
pub fn gdbserver_g(process: &WindowsProcess, registers: &[u64]) -> String {
    let layout = gdb_registers(process.wow64);
    let general = registers.len();
    let selectors = [0x246u64, 0x33, 0x2b, 0x2b, 0x2b, 0x53, 0x2b];
    layout
        .iter()
        .enumerate()
        .map(|(index, (_, bits))| {
            let bytes = *bits as usize / 8;
            match index {
                _ if index < general => le_hex(registers[index], bytes),
                _ if index < general + 7 => le_hex(selectors[index - general], bytes),
                _ => "00".repeat(bytes),
            }
        })
        .collect()
}

/// The target description gdbserver generates (`gdbserver/tdesc.cc`, `tdesc_get_features_xml`, printed by
/// `gdbsupport/tdesc.cc`, `print_xml_feature`): one document, `i386:x86-64` (or `i386`) with the `Windows` OS ABI,
/// and the core and SSE features inline.
fn gdb_description(script: Script, wow64: bool, osabi: bool) -> Script {
    let architecture = if wow64 { "i386" } else { "i386:x86-64" };
    let registers = gdb_registers(wow64);
    let split = registers.iter().position(|(name, _)| name == "xmm0").expect("SSE registers");
    let feature = |name: &str, registers: &[(String, u32)], first: usize| {
        let mut xml = format!("  <feature name=\"{name}\">\n");
        for (offset, (register, bits)) in registers.iter().enumerate() {
            let kind = match *bits {
                128 => "vec128",
                80 => "i387_ext",
                _ => "int",
            };
            xml += &format!(
                "    <reg name=\"{register}\" bitsize=\"{bits}\" type=\"{kind}\" regnum=\"{}\"/>\n",
                first + offset
            );
        }
        xml + "  </feature>\n"
    };
    script.xfer(
        "features",
        "target.xml",
        &format!(
            "<?xml version=\"1.0\"?>\n<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n<target>\n  \
             <architecture>{architecture}</architecture>\n{}{}{}</target>\n",
            if osabi { "  <osabi>Windows</osabi>\n" } else { "" },
            feature("org.gnu.gdb.i386.core", &registers[..split], 0),
            feature("org.gnu.gdb.i386.sse", &registers[split..], split)
        ),
    )
}

/// Adds every image, the TIB and PEB, and the extra memory to `script`.
fn map_memory(mut script: Script, process: &WindowsProcess) -> Script {
    for image in &process.images {
        script = script.memory(image.base, &image.mapped);
    }
    let (tib, peb, width) = if process.wow64 { (TIB32, PEB32, 4) } else { (TIB, PEB, 8) };
    let peb_at = if process.wow64 { 0x30 } else { 0x60 };
    let base_at = if process.wow64 { 0x8 } else { 0x10 };
    let mut teb = vec![0u8; 0x100];
    teb[peb_at..peb_at + width].copy_from_slice(&peb.to_le_bytes()[..width]);
    let mut environment = vec![0u8; 0x100];
    if let Some(main) = process.images.first() {
        environment[base_at..base_at + width].copy_from_slice(&main.base.to_le_bytes()[..width]);
    }
    script = script.memory(tib, &teb).memory(peb, &environment);
    for (address, bytes) in &process.memory {
        script = script.memory(*address, bytes);
    }
    script
}

/// MinGW-w64 `gdbserver.exe` (GDB 17) attached to `process`, stopped at its initial breakpoint: features, the
/// generated description, DLLs at base + 0x1000 without the executable, the executable's path, the TIB, and two
/// threads (a third, [`BREAKIN_THREAD`], appears after an interrupt).
pub fn gdbserver_windows(process: &WindowsProcess) -> Script {
    let mut libraries = String::from("<library-list version=\"1.0\">\n");
    for image in process.images.iter().skip(1) {
        libraries += &format!(
            "  <library name=\"{}\"><segment address=\"0x{:x}\"/></library>\n",
            image.path,
            image.base + crate::pe::GDBSERVER_SEGMENT_OFFSET
        );
    }
    libraries += "</library-list>\n";
    let mut second = process.registers.clone();
    let sp = if process.wow64 { 4 } else { 7 };
    second[sp] = process.registers[sp] + 0x10_0000;
    let tib = if process.wow64 { TIB32 } else { TIB };
    let script = Script::new()
        .thread_continues()
        .on(
            "qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386,arm",
            "PacketSize=2001f;QPassSignals+;QProgramSignals+;QStartupWithShell+;QEnvironmentHexEncoded+;\
             QEnvironmentReset+;QEnvironmentUnset+;QSetWorkingDir+;binary-upload+;qXfer:libraries:read+;\
             qXfer:siginfo:read+;qXfer:siginfo:write+;qXfer:features:read+;QStartNoAckMode+;qXfer:threads:read+;\
             ConditionalBreakpoints+;BreakpointCommands+;swbreak+;qXfer:exec-file:read+;vContSupported+;\
             QThreadEvents+;no-resumed+",
        )
        .on("QStartNoAckMode", "OK");
    let script = gdb_description(script, process.wow64, process.osabi)
        .on("?", &gdbserver_stop(process, &process.registers, MAIN_THREAD, 5, ""))
        .on("qfThreadInfo", &format!("m{MAIN_THREAD:x},{SECOND_THREAD:x}"))
        .after_interrupt("qfThreadInfo", &format!("m{MAIN_THREAD:x},{SECOND_THREAD:x},{BREAKIN_THREAD:x}"))
        .on("qsThreadInfo", "l")
        .on(&format!("qThreadExtraInfo,{MAIN_THREAD:x}"), "")
        .on(&format!("Hg{MAIN_THREAD:x}"), "OK")
        .on(&format!("Hg{SECOND_THREAD:x}"), "OK")
        .on(&format!("Hg{BREAKIN_THREAD:x}"), "OK")
        .on_thread(&format!("{SECOND_THREAD:x}"), "g", &gdbserver_g(process, &second))
        .on("g", &gdbserver_g(process, &process.registers))
        .xfer("libraries", "", &libraries)
        .xfer("exec-file", "", &process.exec_file)
        .on(&format!("qGetTIBAddr:{MAIN_THREAD:x}"), &format!("{tib:x}"))
        .on(&format!("qGetTIBAddr:{SECOND_THREAD:x}"), &format!("{:x}", tib + 0x2000))
        .on("qOffsets", "")
        .on("D", "OK");
    map_memory(script, process)
}

/// The registers lldb-server describes for an x64 Windows process (`NativeRegisterContextWindows_x86_64.cpp`):
/// name, bitsize, generic role, and for a view the register it views.
fn lldb_registers() -> Vec<(String, u32, Option<&'static str>, Option<u32>)> {
    let mut registers = Vec::new();
    let names =
        ["rax", "rbx", "rcx", "rdx", "rdi", "rsi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"];
    for name in names {
        let generic = match name {
            "rcx" => Some("arg1"),
            "rdx" => Some("arg2"),
            "r8" => Some("arg3"),
            "r9" => Some("arg4"),
            "rbp" => Some("fp"),
            "rsp" => Some("sp"),
            _ => None,
        };
        registers.push((name.to_owned(), 64, generic, None));
    }
    registers.push(("rip".into(), 64, Some("pc"), None));
    registers.push(("rflags".into(), 64, Some("flags"), None));
    for name in ["cs", "fs", "gs", "ss", "ds", "es"] {
        registers.push((name.to_owned(), 64, None, None));
    }
    registers.push(("eax".into(), 32, None, Some(0)));
    for index in 0..16 {
        registers.push((format!("xmm{index}"), 128, None, None));
    }
    registers
}

/// GDB's general registers ([`WindowsProcess::registers`]) in lldb-server's order (`rdi` before `rsi`).
fn lldb_values(registers: &[u64]) -> Vec<u64> {
    let order = [0usize, 1, 2, 3, 5, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let mut values: Vec<u64> = order.iter().map(|index| registers[*index]).collect();
    values.extend([0x246, 0x33, 0x53, 0x2b, 0x2b, 0x2b, 0x2b]);
    values
}

fn lldb_g(registers: &[u64]) -> String {
    let values = lldb_values(registers);
    let mut g: String = values.iter().map(|value| le_hex(*value, 8)).collect();
    g += &"00".repeat(16 * 16);
    g
}

/// `lldb-server gdbserver` on Windows x64 attached to `process` (an x64 one), stopped at the loader breakpoint:
/// LLDB's features, `qHostInfo` and `qProcessInfo` with a Windows triple, a description with offsets and a view,
/// every image (the executable first) as `<section address>` at its base, `qMemoryRegionInfo`, and two threads (a
/// third, [`BREAKIN_THREAD`], appears after an interrupt).
pub fn lldb_server_windows(process: &WindowsProcess) -> Script {
    let triple = encode_hex(b"x86_64-pc-windows-msvc");
    let mut libraries = String::from("<library-list>");
    for image in &process.images {
        libraries += &format!("<library name=\"{}\"><section address=\"0x{:x}\"/></library>", image.path, image.base);
    }
    libraries += "</library-list>";
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<target version=\"1.0\">\n<architecture>i386:x86-64</architecture>\n<feature>\n",
    );
    let mut offset = 0usize;
    for (regnum, (name, bits, generic, view)) in lldb_registers().iter().enumerate() {
        let at = match view {
            Some(viewed) => *viewed as usize * 8,
            None => offset,
        };
        xml += &format!(
            "<reg name=\"{name}\" bitsize=\"{bits}\" regnum=\"{regnum}\" offset=\"{at}\" encoding=\"uint\" format=\"hex\""
        );
        if let Some(generic) = generic {
            xml += &format!(" generic=\"{generic}\"");
        }
        if let Some(view) = view {
            xml += &format!(" value_regnums=\"{view}\"");
        } else {
            offset += *bits as usize / 8;
        }
        xml += " />\n";
    }
    xml += "</feature>\n</target>\n";
    let mut second = process.registers.clone();
    second[7] += 0x10_0000;
    let threads = format!(r#"[{{"tid":{MAIN_THREAD},"signal":5,"reason":"breakpoint"}},{{"tid":{SECOND_THREAD}}}]"#);
    let mut script = Script::new()
        .on(
            "qSupported:multiprocess+;swbreak+;hwbreak+;xmlRegisters=i386,arm",
            "PacketSize=131072;QStartNoAckMode+;qEcho+;native-signals+;QThreadSuffixSupported+;\
             QListThreadsInStopReply+;qXfer:features:read+;QNonStop+;jMultiBreakpoint+;qXfer:libraries:read+",
        )
        .on("QStartNoAckMode", "OK")
        .on(
            "qHostInfo",
            &format!(
                "triple:{triple};ptrsize:8;watchpoint_exceptions_received:after;endian:little;os_version:10.0.22631;"
            ),
        )
        .on(
            "qProcessInfo",
            &format!(
                "pid:{PID:x};parent-pid:1f0;real-uid:0;real-gid:0;effective-uid:0;effective-gid:0;triple:{triple};\
                 ostype:windows;endian:little;ptrsize:8;"
            ),
        )
        .xfer("features", "target.xml", &xml)
        .on("?", &lldb_stop(process, &process.registers, MAIN_THREAD, 5, "breakpoint", ""))
        .on("qfThreadInfo", &format!("m{MAIN_THREAD:x},{SECOND_THREAD:x}"))
        .after_interrupt("qfThreadInfo", &format!("m{MAIN_THREAD:x},{SECOND_THREAD:x},{BREAKIN_THREAD:x}"))
        .on("qsThreadInfo", "l")
        .on(&format!("qThreadExtraInfo,{MAIN_THREAD:x}"), "")
        .on("jThreadsInfo", &threads)
        .on(&format!("Hg{MAIN_THREAD:x}"), "OK")
        .on(&format!("Hg{SECOND_THREAD:x}"), "OK")
        .on(&format!("Hg{BREAKIN_THREAD:x}"), "OK")
        .on_thread(&format!("{SECOND_THREAD:x}"), "g", &lldb_g(&second))
        .on("g", &lldb_g(&process.registers))
        .on(crate::lldb::FETCH_ALL_SOLIBS, "")
        .xfer("libraries", "", &libraries)
        .on("qOffsets", "")
        .on("D", "OK");
    // Memory regions from 0, as VirtualQueryEx reports them: each image, the extra memory, and the gaps.
    let mut mapped: Vec<(u64, u64, &str)> = process
        .images
        .iter()
        .map(|image| (image.base, (image.mapped.len() as u64).next_multiple_of(0x1000), "rx"))
        .chain(
            process
                .memory
                .iter()
                .map(|(address, bytes)| (*address & !0xfff, (bytes.len() as u64 + 0xfff) & !0xfff, "rw")),
        )
        .collect();
    mapped.sort();
    let mut at = 0u64;
    for (start, size, permissions) in mapped {
        if start > at {
            script = script.on(&format!("qMemoryRegionInfo:{at:x}"), &format!("start:{at:x};size:{:x};", start - at));
        }
        script = script.on(
            &format!("qMemoryRegionInfo:{start:x}"),
            &format!("start:{start:x};size:{size:x};permissions:{permissions};"),
        );
        at = start + size;
    }
    script =
        script.on(&format!("qMemoryRegionInfo:{at:x}"), &format!("start:{at:x};size:{:x};", 0x8000_0000_0000 - at));
    script = script.on("qMemoryRegionInfo:800000000000", "start:800000000000;");
    map_memory(script, process)
}
