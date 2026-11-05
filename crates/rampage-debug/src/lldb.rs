//! LLDB's protocol extensions, as Apple's `debugserver` (and `lldb-server`) serve them: `qHostInfo`,
//! `qProcessInfo`, `qRegisterInfo<n>`, `jThreadsInfo`, `jGetLoadedDynamicLibrariesInfos` and
//! `qMemoryRegionInfo`. A session uses them only when the stub offers them, and only to add information; every
//! reply is parsed with strict limits. Formats follow LLDB's `lldbgdbremote.md` and debugserver's `RNBRemote.cpp`.

use serde::{Deserialize, Serialize};

use crate::maps::{Module, Region};
use crate::packet::{self, decode_hex, parse_hex_u64};
use crate::stop::{MachException, hex_address};

/// The first `jGetLoadedDynamicLibrariesInfos` request, as LLDB's `DynamicLoaderMacOS` sends it: every loaded
/// image's header address only, so the reply stays small however many images there are.
pub const FETCH_ALL_SOLIBS: &str =
    "jGetLoadedDynamicLibrariesInfos:{\"fetch_all_solibs\":true,\"report_load_commands\":false}";
/// The prefix of the follow-up requests, `{"solib_addresses":[<decimal>,...]}`: full information for a batch.
pub const SOLIB_ADDRESSES: &str = "jGetLoadedDynamicLibrariesInfos:{\"solib_addresses\":[";
/// Images whose full information one `solib_addresses` request asks for, keeping each reply well inside a packet.
pub const SOLIB_BATCH: usize = 64;
/// Most addresses one `solib_addresses` request names.
pub const MAX_SOLIB_ADDRESSES: usize = 512;
/// Most `key:value;` pairs read from one reply.
const MAX_PAIRS: usize = 64;
/// Longest `qHostInfo` or `qProcessInfo` reply read.
const MAX_PAIRS_REPLY: usize = 4096;
/// Most threads read from one `jThreadsInfo` reply.
const MAX_THREAD_DETAILS: usize = 4096;
/// Most images read from one `jGetLoadedDynamicLibrariesInfos` reply.
const MAX_IMAGES: usize = crate::maps::MAX_ENTRIES;
/// Most segments kept per image.
const MAX_SEGMENTS: usize = 32;
/// `MH_DYLIB_IN_CACHE`: a Mach-O header flag set on images that live in the dyld shared cache (macOS 11 and later).
pub const MH_DYLIB_IN_CACHE: u64 = 0x8000_0000;
/// User-space address bits assumed for arm64 Apple targets when the stub states none: macOS and iOS user addresses
/// fit in 47 bits (`addressing_bits:47` is what debugserver reports on Apple silicon Macs).
pub const DEFAULT_APPLE_ADDRESSING_BITS: u8 = 47;

/// `qHostInfo` or `qProcessInfo`, as far as rampage reads them. Unknown keys are ignored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HostInfo {
    pub cputype: Option<u64>,
    pub cpusubtype: Option<u64>,
    pub ostype: Option<String>,
    pub vendor: Option<String>,
    /// `little`, `big` or `pdp`, as stated.
    pub endian: Option<String>,
    pub ptrsize: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// Bits of a virtual address: the rest of a pointer may hold a pointer authentication code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addressing_bits: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub low_mem_addressing_bits: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub high_mem_addressing_bits: Option<u8>,
    /// `before` when a watchpoint stops the thread before its access executes (debugserver on ARM), so a continue
    /// must step past it; `after` otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchpoint_exceptions_received: Option<String>,
    /// lldb-server's target triple (`x86_64-pc-windows-msvc`), sent hex-encoded in place of a Mach-O CPU type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub triple: Option<String>,
}

impl HostInfo {
    /// The architecture's GDB name, from the Mach-O CPU type, else from the triple's architecture.
    pub fn architecture(&self) -> Option<&'static str> {
        match self.cputype {
            Some(cputype) => cpu_architecture(cputype),
            None => triple_architecture(self.triple.as_deref()?),
        }
    }

    /// Whether the target is Windows: `ostype:windows` or a `*-windows-*` triple (lldb-server).
    pub fn windows(&self) -> bool {
        self.ostype.as_deref() == Some("windows")
            || self.triple.as_deref().is_some_and(|triple| triple.split('-').any(|part| part.starts_with("windows")))
    }

    /// Whether the CPU subtype is arm64e, whose code signs return addresses.
    pub fn arm64e(&self) -> bool {
        self.cputype == Some(CPU_TYPE_ARM64) && self.cpusubtype.is_some_and(|subtype| subtype & 0x00ff_ffff == 2)
    }

    /// Whether the target is an Apple platform (`vendor:apple`, or an Apple `ostype`).
    pub fn apple(&self) -> bool {
        self.vendor.as_deref() == Some("apple")
            || self.ostype.as_deref().is_some_and(|os| {
                matches!(os, "macosx" | "ios" | "tvos" | "watchos" | "bridgeos" | "xros" | "maccatalyst")
            })
    }
}

const CPU_TYPE_ARM64: u64 = 0x0100_000c;

/// The GDB architecture name of a Mach-O CPU type: x86 (7), x86-64, ARM (12) and arm64. `arm64_32` and others
/// have no rampage equivalent.
pub fn cpu_architecture(cputype: u64) -> Option<&'static str> {
    match cputype {
        7 => Some("i386"),
        0x0100_0007 => Some("i386:x86-64"),
        12 => Some("arm"),
        CPU_TYPE_ARM64 => Some("aarch64"),
        _ => None,
    }
}

/// The GDB architecture name of a target triple's architecture: x86, x86-64, ARM and AArch64.
pub fn triple_architecture(triple: &str) -> Option<&'static str> {
    match triple.split('-').next()? {
        "i386" | "i486" | "i586" | "i686" => Some("i386"),
        "x86_64" | "amd64" => Some("i386:x86-64"),
        "aarch64" | "arm64" => Some("aarch64"),
        "arm" | "armv7" | "thumbv7" | "thumb" => Some("arm"),
        _ => None,
    }
}

/// Parses a `qHostInfo` (numbers in decimal) or `qProcessInfo` (numbers in hex, `ptrsize` in decimal) reply.
/// Addressing bits are decimal in both.
pub fn parse_host_info(reply: &[u8], hex_numbers: bool) -> Result<HostInfo, String> {
    let pairs = pairs(reply, MAX_PAIRS_REPLY)?;
    let mut info = HostInfo::default();
    let number = |value: &str, hex: bool| -> Result<u64, String> {
        let parsed = if hex { parse_hex_u64(value) } else { value.parse().ok() };
        parsed.ok_or_else(|| format!("`{}` is not a number", value.chars().take(32).collect::<String>()))
    };
    let bits = |value: &str| -> Result<u8, String> {
        value.parse::<u8>().ok().filter(|bits| (1..=64).contains(bits)).ok_or_else(|| "invalid addressing bits".into())
    };
    let text = |value: &str| -> Result<String, String> {
        (value.len() <= 64 && value.bytes().all(|byte| byte.is_ascii_graphic()))
            .then(|| value.to_owned())
            .ok_or_else(|| "invalid text value".into())
    };
    for (key, value) in pairs {
        match key {
            "cputype" => info.cputype = Some(number(value, hex_numbers)?),
            "cpusubtype" => info.cpusubtype = Some(number(value, hex_numbers)?),
            "pid" => info.pid = Some(number(value, true)?),
            "ptrsize" => {
                let size = number(value, false)?;
                info.ptrsize =
                    Some(u8::try_from(size).ok().filter(|size| matches!(size, 2 | 4 | 8)).ok_or("invalid ptrsize")?);
            }
            "ostype" => info.ostype = Some(text(value)?),
            "vendor" => info.vendor = Some(text(value)?),
            "endian" => info.endian = Some(text(value)?),
            "os_version" => info.os_version = Some(text(value)?),
            "addressing_bits" => info.addressing_bits = Some(bits(value)?),
            "low_mem_addressing_bits" => info.low_mem_addressing_bits = Some(bits(value)?),
            "high_mem_addressing_bits" => info.high_mem_addressing_bits = Some(bits(value)?),
            "watchpoint_exceptions_received" => info.watchpoint_exceptions_received = Some(text(value)?),
            "triple" => {
                let decoded = decode_hex(value.as_bytes()).ok_or("the triple is not hex")?;
                info.triple = Some(text(&String::from_utf8_lossy(&decoded))?);
            }
            _ => {}
        }
    }
    Ok(info)
}

/// The `key:value;` pairs of a reply of at most `limit` bytes. Keys are ASCII words; values may be empty.
fn pairs(reply: &[u8], limit: usize) -> Result<Vec<(&str, &str)>, String> {
    if reply.len() > limit {
        return Err(format!("reply exceeds {limit} bytes"));
    }
    let text = std::str::from_utf8(reply).map_err(|_| "reply is not ASCII")?;
    let mut pairs = Vec::new();
    for field in text.split(';').filter(|field| !field.is_empty()) {
        if pairs.len() == MAX_PAIRS {
            return Err("reply has too many fields".into());
        }
        let (key, value) = field.split_once(':').ok_or("field without `:`")?;
        if key.is_empty() || key.len() > 64 || !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err("invalid key".into());
        }
        pairs.push((key, value));
    }
    Ok(pairs)
}

/// How rampage takes pointer authentication codes off code addresses (return addresses in lr/x30 or on the
/// stack): the address bits it keeps, and where that number came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddressMask {
    /// Bits of a user-space (low) address; the bits above are cleared.
    pub low_bits: u8,
    /// Bits of a kernel-space (high, bit 55 set) address; the bits above are set.
    pub high_bits: u8,
    pub source: String,
}

impl AddressMask {
    /// `value` without its pointer authentication code: bits above the address width cleared for a low address
    /// (bit 55 clear), set for a high one. Values that carry no code come back unchanged.
    pub fn strip(&self, value: u64) -> u64 {
        if value >> 55 & 1 == 0 { value & low_mask(self.low_bits) } else { value | !low_mask(self.high_bits) }
    }

    /// The mask for an arm64 target: the stub's stated addressing bits (`qProcessInfo` before `qHostInfo`,
    /// `low_mem_addressing_bits` before `addressing_bits`), else the Apple default for an Apple target. `None`
    /// for other targets without stated bits: their address width is unknown, and stripping with a guess could
    /// cut real address bits.
    pub fn for_target(process: Option<&HostInfo>, host: Option<&HostInfo>) -> Option<Self> {
        let sources = [("qProcessInfo", process), ("qHostInfo", host)];
        for (name, info) in sources {
            let Some(info) = info else { continue };
            let low = info.low_mem_addressing_bits.map(|bits| (bits, "low_mem_addressing_bits"));
            if let Some((bits, key)) = low.or(info.addressing_bits.map(|bits| (bits, "addressing_bits"))) {
                let high = info.high_mem_addressing_bits.unwrap_or(bits);
                return Some(Self { low_bits: bits, high_bits: high, source: format!("{name} {key}:{bits}") });
            }
        }
        let apple = process.is_some_and(HostInfo::apple) || host.is_some_and(HostInfo::apple);
        apple.then(|| Self {
            low_bits: DEFAULT_APPLE_ADDRESSING_BITS,
            high_bits: DEFAULT_APPLE_ADDRESSING_BITS,
            source: format!(
                "the stub states no addressing bits; Apple user-space addresses fit in \
                 {DEFAULT_APPLE_ADDRESSING_BITS} bits"
            ),
        })
    }
}

fn low_mask(bits: u8) -> u64 {
    if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 }
}

/// One `qRegisterInfo<n>` reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterInfo {
    pub name: String,
    pub alt_name: Option<String>,
    pub bitsize: u32,
    /// Where the register's bytes start in a `g` reply.
    pub offset: usize,
    pub encoding: Option<String>,
    pub set: Option<String>,
    pub generic: Option<String>,
    /// The registers this one is a view of (`w0` of `x0`); such a register has no bytes of its own in `g`.
    pub container: Vec<u32>,
    /// Registers a write to this one changes too.
    pub invalidate: Vec<u32>,
}

/// Most register numbers listed in `container-regs` or `invalidate-regs`.
const MAX_RELATED_REGISTERS: usize = 64;

/// Parses a `qRegisterInfo<n>` reply: `name`, `bitsize` and `offset` are required.
pub fn parse_register_info(reply: &[u8]) -> Result<RegisterInfo, String> {
    let mut info = RegisterInfo {
        name: String::new(),
        alt_name: None,
        bitsize: 0,
        offset: usize::MAX,
        encoding: None,
        set: None,
        generic: None,
        container: Vec::new(),
        invalidate: Vec::new(),
    };
    let name = |value: &str| -> Result<String, String> {
        (!value.is_empty() && value.len() <= 64 && value.bytes().all(|byte| byte.is_ascii_graphic()))
            .then(|| value.to_owned())
            .ok_or_else(|| "invalid register name".into())
    };
    let list = |value: &str| -> Result<Vec<u32>, String> {
        let numbers: Vec<&str> = value.split(',').collect();
        if numbers.len() > MAX_RELATED_REGISTERS {
            return Err("too many related registers".into());
        }
        numbers
            .iter()
            .map(|number| {
                parse_hex_u64(number)
                    .and_then(|number| u32::try_from(number).ok())
                    .ok_or_else(|| "invalid register list".into())
            })
            .collect()
    };
    for (key, value) in pairs(reply, MAX_PAIRS_REPLY)? {
        match key {
            "name" => info.name = name(value)?,
            "alt-name" => info.alt_name = Some(name(value)?),
            "bitsize" => info.bitsize = value.parse().map_err(|_| "invalid bitsize")?,
            "offset" => info.offset = value.parse().map_err(|_| "invalid offset")?,
            "encoding" => info.encoding = Some(name(value)?),
            "set" => info.set = Some(value.chars().take(64).collect()),
            "generic" => info.generic = Some(name(value)?),
            "container-regs" => info.container = list(value)?,
            "invalidate-regs" => info.invalidate = list(value)?,
            _ => {}
        }
    }
    if info.name.is_empty() || info.offset == usize::MAX {
        return Err("qRegisterInfo reply without name or offset".into());
    }
    if info.bitsize == 0 || !info.bitsize.is_multiple_of(8) {
        return Err(format!("register `{}` has unsupported bitsize {}", info.name, info.bitsize));
    }
    Ok(info)
}

/// The JSON of a `j` packet's reply. debugserver binary-escapes these replies (`}` as `}]`); a reply that does not
/// parse unescaped is tried as sent.
fn json<T: for<'de> Deserialize<'de>>(reply: &[u8]) -> Result<T, String> {
    if let Ok(unescaped) = packet::unescape(reply)
        && let Ok(value) = serde_json::from_slice(&unescaped)
    {
        return Ok(value);
    }
    serde_json::from_slice(reply).map_err(|error| format!("malformed JSON: {error}"))
}

/// A thread as `jThreadsInfo` describes it: its name, dispatch queue and why it stopped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ThreadDetail {
    #[serde(skip)]
    pub tid: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The libdispatch queue the thread runs, such as `com.apple.main-thread`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub queue: Option<String>,
    /// debugserver's stop reason: `exception`, `breakpoint`, `watchpoint`, `trace`, `signal`...
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception: Option<MachException>,
}

#[derive(Deserialize)]
struct RawThread {
    tid: u64,
    name: Option<String>,
    qname: Option<String>,
    reason: Option<String>,
    description: Option<String>,
    metype: Option<u32>,
    medata: Option<Vec<u64>>,
}

fn clip(text: Option<String>, limit: usize) -> Option<String> {
    text.filter(|text| !text.is_empty()).map(|text| text.chars().filter(|c| !c.is_control()).take(limit).collect())
}

/// Parses a `jThreadsInfo` reply: an array of thread objects with a decimal `tid`. Registers and memory the stub
/// expedites are ignored.
pub fn parse_threads_info(reply: &[u8]) -> Result<Vec<ThreadDetail>, String> {
    let threads: Vec<RawThread> = json(reply)?;
    if threads.len() > MAX_THREAD_DETAILS {
        return Err("jThreadsInfo lists too many threads".into());
    }
    Ok(threads
        .into_iter()
        .map(|thread| ThreadDetail {
            tid: thread.tid,
            name: clip(thread.name, 128),
            queue: clip(thread.qname, 128),
            reason: clip(thread.reason, 32),
            description: clip(thread.description, 256),
            exception: thread.metype.map(|kind| MachException::new(kind, &thread.medata.unwrap_or_default())),
        })
        .collect())
}

#[derive(Deserialize)]
struct RawImages {
    images: Vec<RawImage>,
}

#[derive(Deserialize)]
struct RawImage {
    load_address: u64,
    pathname: Option<String>,
    uuid: Option<String>,
    mach_header: Option<RawHeader>,
    #[serde(default)]
    segments: Vec<RawSegment>,
}

#[derive(Deserialize)]
struct RawHeader {
    filetype: Option<u32>,
    flags: Option<u64>,
}

#[derive(Deserialize)]
struct RawSegment {
    name: String,
    vmaddr: u64,
    vmsize: u64,
}

/// A segment of a Mach-O image as `jGetLoadedDynamicLibrariesInfos` reports it: its link-time address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MachSegment {
    pub name: String,
    #[serde(serialize_with = "hex_address")]
    pub vmaddr: u64,
    pub vmsize: u64,
}

/// A loaded Mach-O image from `jGetLoadedDynamicLibrariesInfos`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DyldImage {
    /// The runtime address of the image's Mach-O header.
    #[serde(serialize_with = "hex_address")]
    pub load_address: u64,
    /// `LC_UUID`, as the stub formats it (upper case with dashes).
    pub uuid: Option<String>,
    /// `MH_EXECUTE` (2), `MH_DYLIB` (6), `MH_DYLINKER` (7), `MH_BUNDLE` (8)...
    pub filetype: Option<u32>,
    /// Whether the header carries `MH_DYLIB_IN_CACHE`: the image lives in the dyld shared cache, not in a file at
    /// its path.
    pub in_shared_cache: bool,
    /// The image's `__TEXT` link-time address; the slide is `load_address - text_vmaddr`.
    pub text_vmaddr: Option<u64>,
    pub segments: Vec<MachSegment>,
}

/// Parses a `jGetLoadedDynamicLibrariesInfos` reply into modules.
pub fn parse_dyld_images(reply: &[u8]) -> Result<Vec<Module>, String> {
    let raw: RawImages = json(reply)?;
    if raw.images.len() > MAX_IMAGES {
        return Err("the image list is too long".into());
    }
    let mut modules = Vec::with_capacity(raw.images.len());
    for image in raw.images {
        let uuid = match image.uuid {
            Some(uuid) if uuid.is_empty() => None,
            Some(uuid) => Some(canonical_uuid(&uuid).ok_or("malformed image UUID")?),
            None => None,
        };
        let segments: Vec<MachSegment> = image
            .segments
            .into_iter()
            .take(MAX_SEGMENTS)
            .map(|segment| MachSegment {
                name: segment.name.chars().take(16).collect(),
                vmaddr: segment.vmaddr,
                vmsize: segment.vmsize,
            })
            .collect();
        let text_vmaddr = segments.iter().find(|segment| segment.name == "__TEXT").map(|segment| segment.vmaddr);
        let filetype = image.mach_header.as_ref().and_then(|header| header.filetype);
        let flags = image.mach_header.as_ref().and_then(|header| header.flags).unwrap_or(0);
        let mut name = image.pathname.unwrap_or_default();
        if name.len() > 4096 {
            let mut end = 4096;
            while !name.is_char_boundary(end) {
                end -= 1;
            }
            name.truncate(end);
        }
        modules.push(Module {
            name,
            source: "dyld",
            l_addr: None,
            l_ld: None,
            lm: None,
            segments: Vec::new(),
            sections: Vec::new(),
            build_id: None,
            main: filetype == Some(2),
            dyld: Some(DyldImage {
                load_address: image.load_address,
                uuid,
                filetype,
                in_shared_cache: flags & MH_DYLIB_IN_CACHE != 0,
                text_vmaddr,
                segments,
            }),
            pe: None,
        });
    }
    Ok(modules)
}

#[derive(Deserialize)]
struct RawAddresses {
    images: Vec<RawAddress>,
}

#[derive(Deserialize)]
struct RawAddress {
    load_address: u64,
}

/// Parses the reply to [`FETCH_ALL_SOLIBS`]: the header address of every loaded image, at most 4096.
pub fn parse_image_addresses(reply: &[u8]) -> Result<Vec<u64>, String> {
    let raw: RawAddresses = json(reply)?;
    if raw.images.len() > MAX_IMAGES {
        return Err("the image list is too long".into());
    }
    Ok(raw.images.into_iter().map(|image| image.load_address).collect())
}

/// The `solib_addresses` request for `addresses` (at most [`MAX_SOLIB_ADDRESSES`]).
pub fn solib_request(addresses: &[u64]) -> String {
    let list: Vec<String> = addresses.iter().map(u64::to_string).collect();
    format!("{SOLIB_ADDRESSES}{}]}}", list.join(","))
}

/// A UUID as 32 hex digits in upper case with dashes (8-4-4-4-12), from any spelling with or without dashes.
pub fn canonical_uuid(text: &str) -> Option<String> {
    let digits: String = text.chars().filter(|c| *c != '-').collect();
    if digits.len() != 32 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let digits = digits.to_ascii_uppercase();
    Some(format!("{}-{}-{}-{}-{}", &digits[..8], &digits[8..12], &digits[12..16], &digits[16..20], &digits[20..]))
}

/// One `qMemoryRegionInfo` reply: the region holding the address asked for, or the unmapped gap around it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegionInfo {
    pub start: u64,
    /// `None` when the stub gives no size (an unmapped address past the last region).
    pub size: Option<u64>,
    /// `r`, `w` and `x` as stated; empty for unmapped memory.
    pub permissions: String,
    pub name: Option<String>,
}

/// Parses a `qMemoryRegionInfo:<address>` reply. An `error` key is reported as an error. debugserver always lists
/// a region's dirty pages, which make a busy writable region's reply long, so the reply may be as long as a packet;
/// the dirty pages are skipped.
pub fn parse_region_info(reply: &[u8]) -> Result<RegionInfo, String> {
    let mut region = RegionInfo { start: u64::MAX, size: None, permissions: String::new(), name: None };
    let mut seen_start = false;
    for (key, value) in pairs(reply, packet::MAX_PACKET_BYTES)? {
        match key {
            "start" => {
                region.start = parse_hex_u64(value).ok_or("invalid region start")?;
                seen_start = true;
            }
            "size" => region.size = Some(parse_hex_u64(value).ok_or("invalid region size")?),
            "permissions" => {
                if value.len() > 3 || !value.bytes().all(|b| matches!(b, b'r' | b'w' | b'x')) {
                    return Err("invalid region permissions".into());
                }
                region.permissions = value.to_owned();
            }
            "name" => {
                let bytes = decode_hex(value.as_bytes()).ok_or("region name is not hex")?;
                region.name = Some(String::from_utf8_lossy(&bytes).chars().take(256).collect());
            }
            "error" => {
                let text = decode_hex(value.as_bytes()).map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
                return Err(text.unwrap_or_else(|| value.chars().take(64).collect()));
            }
            _ => {}
        }
    }
    if !seen_start {
        return Err("region reply without start".into());
    }
    Ok(region)
}

impl RegionInfo {
    /// The region as `debug_modules` lists it, when it is mapped and has a size.
    pub fn mapped(&self) -> Option<Region> {
        let length = self.size.filter(|size| *size > 0)?;
        (!self.permissions.is_empty()).then(|| Region {
            start: self.start,
            length,
            kind: "mapped".into(),
            flash_block_size: None,
            permissions: Some(self.permissions.clone()),
            name: self.name.clone(),
        })
    }
}

/// Whether `payload` is one of the LLDB queries this client sends, in exactly the form it sends them. These are
/// read-class packets.
pub(crate) fn read_query(payload: &str) -> bool {
    let hex = |text: &str, digits: usize| {
        !text.is_empty() && text.len() <= digits && text.bytes().all(|byte| byte.is_ascii_hexdigit())
    };
    match payload {
        "qHostInfo" | "qProcessInfo" | "jThreadsInfo" | FETCH_ALL_SOLIBS => true,
        _ => {
            if let Some(number) = payload.strip_prefix("qRegisterInfo") {
                return hex(number, 8);
            }
            if let Some(address) = payload.strip_prefix("qMemoryRegionInfo:") {
                return hex(address, 16);
            }
            payload
                .strip_prefix("jGetLoadedDynamicLibrariesInfos:{\"solib_addresses\":[")
                .and_then(|rest| rest.strip_suffix("]}"))
                .is_some_and(|list| {
                    let addresses: Vec<&str> = list.split(',').collect();
                    addresses.len() <= MAX_SOLIB_ADDRESSES
                        && addresses.iter().all(|address| {
                            !address.is_empty()
                                && address.len() <= 20
                                && address.bytes().all(|byte| byte.is_ascii_digit())
                                && address.parse::<u64>().is_ok()
                        })
                })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_and_process_info() {
        let host = parse_host_info(
            b"cputype:16777228;cpusubtype:2;addressing_bits:47;ostype:macosx;watchpoint_exceptions_received:before;\
              vendor:apple;os_version:15.1;endian:little;ptrsize:8;vm-page-size:16384;",
            false,
        )
        .unwrap();
        assert_eq!(host.architecture(), Some("aarch64"));
        assert!(host.arm64e() && host.apple());
        assert_eq!((host.addressing_bits, host.ptrsize, host.endian.as_deref()), (Some(47), Some(8), Some("little")));
        let process = parse_host_info(
            b"pid:1a2b;parent-pid:1;real-uid:1f5;real-gid:14;effective-uid:1f5;effective-gid:14;cputype:100000c;\
              cpusubtype:0;ptrsize:8;ostype:macosx;vendor:apple;endian:little;",
            true,
        )
        .unwrap();
        assert_eq!((process.pid, process.cputype), (Some(0x1a2b), Some(0x100_000c)));
        assert!(!process.arm64e());
        for reply in [&b"cputype:zz;"[..], b"ptrsize:3;", b"addressing_bits:65;", b"noval;", b"\xff:1;"] {
            assert!(parse_host_info(reply, false).is_err(), "{reply:?}");
        }
        assert!(parse_host_info(&vec![b'a'; 5000], false).is_err());
    }

    #[test]
    fn strips_pointer_authentication_codes() {
        let host = parse_host_info(b"vendor:apple;ostype:macosx;", false).unwrap();
        let mask = AddressMask::for_target(None, Some(&host)).unwrap();
        assert_eq!(mask.low_bits, 47);
        assert_eq!(mask.strip(0x0022_8001_0000_3f5c), 0x0000_0001_0000_3f5c);
        assert_eq!(mask.strip(0x1_0000_3f5c), 0x1_0000_3f5c);
        assert_eq!(mask.strip(0xffff_ff80_1234_5678), 0xffff_ff80_1234_5678);
        let stated = parse_host_info(b"addressing_bits:39;", false).unwrap();
        let mask = AddressMask::for_target(Some(&stated), Some(&host)).unwrap();
        assert_eq!((mask.low_bits, mask.source.as_str()), (39, "qProcessInfo addressing_bits:39"));
        assert_eq!(mask.strip(0x002b_0040_0000_1000), 0x40_0000_1000);
        let linux = parse_host_info(b"ostype:linux;vendor:unknown;", false).unwrap();
        assert_eq!(AddressMask::for_target(None, Some(&linux)), None);
    }

    #[test]
    fn parses_register_info() {
        let info = parse_register_info(
            b"name:lr;alt-name:x30;bitsize:64;offset:240;encoding:uint;format:hex;set:General Purpose Registers;\
              ehframe:30;dwarf:30;generic:ra;",
        )
        .unwrap();
        assert_eq!((info.name.as_str(), info.alt_name.as_deref(), info.offset), ("lr", Some("x30"), 240));
        assert_eq!(info.generic.as_deref(), Some("ra"));
        let view = parse_register_info(
            b"name:w0;bitsize:32;offset:0;encoding:uint;format:hex;set:General Purpose Registers;container-regs:0;\
              invalidate-regs:0,22;",
        )
        .unwrap();
        assert_eq!((view.container, view.invalidate), (vec![0], vec![0, 0x22]));
        for reply in [&b"bitsize:64;offset:0;"[..], b"name:x;bitsize:12;offset:0;", b"name:x;bitsize:64;", b"E45"] {
            assert!(parse_register_info(reply).is_err(), "{reply:?}");
        }
    }

    #[test]
    fn parses_threads_and_images_escaped_or_not() {
        let threads = r#"[{"tid":1580681,"metype":6,"medata":[2,0],"reason":"exception","qaddr":140735118423168,"registers":{"0":"0000000000000000"},"memory":[{"address":140734799804592,"bytes":"c8f8"}],"name":"main","qname":"com.apple.main-thread"}]"#;
        for reply in [threads.as_bytes().to_vec(), packet::encode(threads.as_bytes())] {
            let reply = if reply.starts_with(b"$") { reply[1..reply.len() - 3].to_vec() } else { reply };
            let parsed = parse_threads_info(&reply).unwrap();
            assert_eq!(parsed[0].tid, 1580681);
            assert_eq!(parsed[0].queue.as_deref(), Some("com.apple.main-thread"));
            assert_eq!(parsed[0].exception.as_ref().map(|e| e.name), Some("EXC_BREAKPOINT"));
        }
        let images = r#"{"images":[{"load_address":4294967296,"mod_date":0,"pathname":"/tmp/a.out","uuid":"02CF262C-ED6F-3965-9E14-63538B465CFF","mach_header":{"magic":4277009103,"cputype":16777228,"cpusubtype":0,"filetype":2,"flags":2162821},"segments":[{"name":"__PAGEZERO","vmaddr":0,"vmsize":4294967296,"fileoff":0,"filesize":0,"maxprot":0},{"name":"__TEXT","vmaddr":4294967296,"vmsize":16384,"fileoff":0,"filesize":16384,"maxprot":5}]},{"load_address":6442450944,"pathname":"/usr/lib/system/libsystem_c.dylib","uuid":"aaaaaaaabbbbccccddddeeeeeeeeeeee","mach_header":{"magic":4277009103,"cputype":16777228,"cpusubtype":2,"filetype":6,"flags":2147483648},"segments":[{"name":"__TEXT","vmaddr":6442450944,"vmsize":16384,"fileoff":0,"filesize":16384,"maxprot":5}]}]}"#;
        let modules = parse_dyld_images(images.as_bytes()).unwrap();
        let main = modules[0].dyld.as_ref().unwrap();
        assert!(modules[0].main && !main.in_shared_cache);
        assert_eq!((main.load_address, main.text_vmaddr), (0x1_0000_0000, Some(0x1_0000_0000)));
        let cached = modules[1].dyld.as_ref().unwrap();
        assert!(cached.in_shared_cache);
        assert_eq!(cached.uuid.as_deref(), Some("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"));
        assert!(parse_dyld_images(br#"{"images":[{"load_address":1,"uuid":"xyz"}]}"#).is_err());
        assert!(parse_dyld_images(b"{").is_err());
    }

    #[test]
    fn parses_memory_regions() {
        let region = parse_region_info(b"start:100000000;size:4000;permissions:rx;dirty-pages:;type:;").unwrap();
        let mapped = region.mapped().unwrap();
        assert_eq!((mapped.start, mapped.length, mapped.permissions.as_deref()), (0x1_0000_0000, 0x4000, Some("rx")));
        let gap = parse_region_info(b"start:0;size:100000000;").unwrap();
        assert!(gap.mapped().is_none());
        assert_eq!(parse_region_info(b"start:300000000;").unwrap().size, None);
        assert!(parse_region_info(b"error:6164647265737320696e20756e6d617070656420726567696f6e;").is_err());
        assert!(parse_region_info(b"start:1;permissions:rwz;").is_err());
        assert!(parse_region_info(b"size:1;").is_err());
    }

    #[test]
    fn read_queries_take_exactly_their_documented_arguments() {
        for packet in [
            "qHostInfo",
            "qProcessInfo",
            "jThreadsInfo",
            "qRegisterInfo0",
            "qRegisterInfoa3",
            "qMemoryRegionInfo:100000000",
            FETCH_ALL_SOLIBS,
            "jGetLoadedDynamicLibrariesInfos:{\"solib_addresses\":[4294967296,6442450944]}",
        ] {
            assert!(read_query(packet), "{packet}");
        }
        for packet in [
            "qRegisterInfo",
            "qRegisterInfozz",
            "qMemoryRegionInfo:",
            "qMemoryRegionInfo:1,2",
            "jGetLoadedDynamicLibrariesInfos:",
            "jGetLoadedDynamicLibrariesInfos:{\"fetch_all_solibs\":false}",
            "jGetLoadedDynamicLibrariesInfos:{\"fetch_all_solibs\":true}",
            "jGetLoadedDynamicLibrariesInfos:{\"fetch_all_solibs\":true,\"x\":1}",
            "jGetLoadedDynamicLibrariesInfos:{\"solib_addresses\":[]}",
            "jGetLoadedDynamicLibrariesInfos:{\"solib_addresses\":[-1]}",
            "jGetLoadedDynamicLibrariesInfos:{\"solib_addresses\":[0x10]}",
            "jGetLoadedDynamicLibrariesInfos:{\"image_count\":1,\"image_list_address\":140734800075128}",
            "jThreadExtendedInfo:{\"thread\":1}",
            "jThreadsInfo:",
            "qHostInfo:",
        ] {
            assert!(!read_query(packet), "{packet}");
        }
    }
}
