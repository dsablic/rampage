//! Espressif ESP8266 and ESP32-family firmware: the app image format (magic 0xE9) the ROM and second-stage
//! bootloader load, the partition table (0xAA50 entries and an MD5 entry, at flash 0x8000 by default), the
//! `esp_app_desc_t` record at the start of an application's first flash data segment, and the flash layout a whole
//! dump has (bootloader image at 0x1000 on ESP32 and ESP32-S2, at 0 on ESP32-S3; partition table; partitions).
//!
//! Every count and length is bounded by the bytes present: at most 16 segments, each inside the image, and segments
//! that overlap are refused. Nothing here decides what code does; it reports what the headers state, and whether the
//! checksum and the appended SHA-256 agree with the bytes.

use md5::{Digest as _, Md5};
use serde::Serialize;
use sha2::Sha256;

use crate::LoadError;
use crate::raw::RawRegionKind;

pub const ESP_IMAGE_MAGIC: u8 = 0xe9;
pub const ESP_APP_DESC_MAGIC: u32 = 0xabcd_5432;
/// Most segments an image may state (esptool's limit).
pub const MAX_ESP_SEGMENTS: usize = 16;
/// Where ESP-IDF puts the partition table unless configured otherwise.
pub const DEFAULT_PARTITION_TABLE_OFFSET: u64 = 0x8000;
const PARTITION_TABLE_BYTES: usize = 0xc00;
const PARTITION_MAGIC: [u8; 2] = [0xaa, 0x50];
const PARTITION_MD5_MAGIC: [u8; 2] = [0xeb, 0xeb];

/// The chip an image is built for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EspChip {
    Esp8266,
    Esp32,
    Esp32S2,
    Esp32S3,
    /// An ESP32-family chip id rampage has no memory map for, or one with a RISC-V core (C2, C3, C5, C6, H2, P4).
    Other,
}

impl EspChip {
    fn from_id(id: u16) -> Self {
        match id {
            0 => EspChip::Esp32,
            2 => EspChip::Esp32S2,
            9 => EspChip::Esp32S3,
            _ => EspChip::Other,
        }
    }

    /// Whether the chip's cores are Xtensa (LX106, LX6 or LX7).
    pub fn xtensa(self) -> bool {
        self != EspChip::Other
    }

    /// Whether code for the chip uses the call0 ABI (the ESP8266's LX106 has no register windows).
    pub fn call0(self) -> bool {
        self == EspChip::Esp8266
    }

    /// The chip's name as Espressif writes it (`ESP32-S3`).
    pub fn label(self) -> &'static str {
        match self {
            EspChip::Esp8266 => "ESP8266",
            EspChip::Esp32 => "ESP32",
            EspChip::Esp32S2 => "ESP32-S2",
            EspChip::Esp32S3 => "ESP32-S3",
            EspChip::Other => "ESP",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            EspChip::Esp8266 => "esp8266",
            EspChip::Esp32 => "esp32",
            EspChip::Esp32S2 => "esp32-s2",
            EspChip::Esp32S3 => "esp32-s3",
            EspChip::Other => "other",
        }
    }

    /// The memory a load address lies in, by the chip's memory map: its name and what a Raw region of it holds.
    pub fn memory(self, address: u64) -> Option<(&'static str, RawRegionKind)> {
        use RawRegionKind::{Code, Data, Ram};
        let map: &[(u64, u64, &str, RawRegionKind)] = match self {
            EspChip::Esp8266 => &[
                (0x3ffe_8000, 0x4000_0000, "dram", Ram),
                (0x4010_0000, 0x4011_0000, "iram", Code),
                (0x4020_0000, 0x4030_0000, "irom", Code),
            ],
            EspChip::Esp32 => &[
                (0x3f40_0000, 0x3f80_0000, "drom", Data),
                (0x3ff8_0000, 0x3ff8_2000, "rtc_dram", Ram),
                (0x3ffa_e000, 0x4000_0000, "dram", Ram),
                (0x4007_0000, 0x400a_0000, "iram", Code),
                (0x400c_0000, 0x400c_2000, "rtc_iram", Code),
                (0x400c_2000, 0x40c0_0000, "irom", Code),
                (0x5000_0000, 0x5000_2000, "rtc_slow", Ram),
            ],
            EspChip::Esp32S2 => &[
                (0x3f00_0000, 0x3ff8_0000, "drom", Data),
                (0x3ff9_e000, 0x3ffa_0000, "rtc_dram", Ram),
                (0x3ffb_0000, 0x4000_0000, "dram", Ram),
                (0x4002_0000, 0x4007_0000, "iram", Code),
                (0x4007_0000, 0x4007_2000, "rtc_iram", Code),
                (0x4008_0000, 0x4080_0000, "irom", Code),
                (0x5000_0000, 0x5000_2000, "rtc_slow", Ram),
            ],
            EspChip::Esp32S3 => &[
                (0x3c00_0000, 0x3e00_0000, "drom", Data),
                (0x3fc8_8000, 0x3fd0_0000, "dram", Ram),
                (0x4037_0000, 0x403e_0000, "iram", Code),
                (0x4200_0000, 0x4400_0000, "irom", Code),
                (0x5000_0000, 0x5000_2000, "rtc_slow", Ram),
                (0x600f_e000, 0x6010_0000, "rtc_fast", Code),
            ],
            EspChip::Other => &[],
        };
        map.iter().find(|(start, end, ..)| (*start..*end).contains(&address)).map(|(.., name, kind)| (*name, *kind))
    }
}

/// One segment an image states.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EspSegment {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub load_address: u64,
    pub length: u64,
    /// Offset of the segment's bytes from the start of the image.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub image_offset: u64,
    /// The memory it loads into (`iram`, `dram`, `irom`, `drom`, ...); absent for esptool's padding segments and
    /// addresses outside the chip's memory map, which are not mapped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<&'static str>,
    #[serde(skip)]
    pub kind: Option<RawRegionKind>,
}

/// A stored digest and whether the bytes agree with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EspDigest {
    pub stored: String,
    pub computed: String,
    pub valid: bool,
}

/// `esp_app_desc_t`: what ESP-IDF records about an application build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EspAppDesc {
    pub project_name: String,
    pub version: String,
    pub idf_version: String,
    pub compile_date: String,
    pub compile_time: String,
    pub secure_version: u32,
    /// The SHA-256 of the application's ELF file, as the build recorded it; all zeros when it did not.
    pub elf_sha256: String,
}

/// `esp_bootloader_desc_t` (ESP-IDF 5.1 and later): the bootloader's build record at the start of its first DRAM
/// segment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EspBootloaderDesc {
    pub version: u32,
    pub idf_version: String,
    pub date_time: String,
}

/// What an app image's headers state, with the checks of its checksum and appended digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EspImage {
    pub chip: EspChip,
    /// `windowed` or `call0`.
    pub abi: &'static str,
    /// The image's offset in the file read.
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub offset: u64,
    /// Bytes from the header through the checksum byte and, when appended, the SHA-256.
    pub length: u64,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub entry: u64,
    pub flash_mode: &'static str,
    pub flash_size: &'static str,
    pub flash_frequency: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_chip_revision: Option<u16>,
    pub segments: Vec<EspSegment>,
    pub checksum: EspDigest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<EspDigest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_desc: Option<EspAppDesc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootloader_desc: Option<EspBootloaderDesc>,
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn hex(bytes: &[u8]) -> String {
    rampage_arch::hex::bytes(bytes)
}

fn flash_mode(byte: u8) -> &'static str {
    ["qio", "qout", "dio", "dout", "fast_read", "slow_read"].get(usize::from(byte)).copied().unwrap_or("unknown")
}

fn flash_size(chip: EspChip, code: u8) -> &'static str {
    let sizes: &[&str] = if chip == EspChip::Esp8266 {
        &["512KB", "256KB", "1MB", "2MB", "4MB", "2MB-c1", "4MB-c1", "8MB", "16MB"]
    } else {
        &["1MB", "2MB", "4MB", "8MB", "16MB", "32MB", "64MB", "128MB"]
    };
    sizes.get(usize::from(code)).copied().unwrap_or("unknown")
}

fn flash_frequency(chip: EspChip, code: u8) -> &'static str {
    match (chip, code) {
        (_, 0) => "40m",
        (_, 1) => "26m",
        (_, 2) => "20m",
        (_, 0xf) => "80m",
        _ => "unknown",
    }
}

/// Whether `bytes` at `offset` start like an app image: the magic, 1..=16 segments, and an entry in a chip's
/// instruction memory. Cheap enough for sniffing and carving.
pub fn looks_like_app_image(bytes: &[u8], offset: usize) -> bool {
    let Some(header) = bytes.get(offset..offset + 8) else { return false };
    if header[0] != ESP_IMAGE_MAGIC || header[1] == 0 || usize::from(header[1]) > MAX_ESP_SEGMENTS {
        return false;
    }
    let entry = u64::from(u32::from_le_bytes(header[4..8].try_into().unwrap_or_default()));
    let chip = layout_chip(bytes, offset);
    chip.is_some_and(|chip| chip.memory(entry).is_some_and(|(_, kind)| kind == RawRegionKind::Code))
}

/// Which header layout the image at `offset` has: the ESP8266's (segments right after the 8-byte header) or the
/// ESP32 family's (a 16-byte extended header with the chip id first). The entry decides: ESP8266 code starts in
/// its IRAM at 0x40100000.
fn layout_chip(bytes: &[u8], offset: usize) -> Option<EspChip> {
    let entry = u64::from(u32_at(bytes, offset + 4)?);
    if EspChip::Esp8266.memory(entry).is_some_and(|(name, _)| name == "iram") {
        return Some(EspChip::Esp8266);
    }
    let chip = EspChip::from_id(u16_at(bytes, offset + 12)?);
    if chip == EspChip::Other {
        // RISC-V parts are recognised as images but not mapped.
        return Some(EspChip::Other);
    }
    Some(chip)
}

/// Reads the app image at `offset` of `bytes` (a whole file or flash dump).
pub fn parse_app_image(bytes: &[u8], offset: u64) -> Result<EspImage, LoadError> {
    let malformed = |message: String| LoadError::Malformed(format!("ESP app image at {offset:#x}: {message}"));
    let start = usize::try_from(offset).map_err(|_| malformed("offset out of range".into()))?;
    let image = bytes.get(start..).ok_or_else(|| malformed("offset past the end of the file".into()))?;
    if image.len() < 8 || image[0] != ESP_IMAGE_MAGIC {
        return Err(malformed(format!(
            "no image magic 0xe9 (found {})",
            image.first().map_or("end of file".to_owned(), |byte| format!("{byte:#04x}"))
        )));
    }
    let count = usize::from(image[1]);
    if count == 0 || count > MAX_ESP_SEGMENTS {
        return Err(malformed(format!("{count} segments; an image holds 1..=16")));
    }
    let chip = layout_chip(bytes, start).ok_or_else(|| malformed("truncated header".into()))?;
    let entry = u64::from(u32_at(image, 4).unwrap_or_default());
    let (mut at, min_chip_revision, hash_appended) = if chip == EspChip::Esp8266 {
        (8usize, None, false)
    } else {
        let extended = image.get(8..24).ok_or_else(|| malformed("truncated extended header".into()))?;
        (24usize, u16_at(extended, 5), extended[15] == 1)
    };
    let mut segments = Vec::with_capacity(count);
    let mut checksum = 0xefu8;
    for index in 0..count {
        let (Some(load_address), Some(length)) = (u32_at(image, at), u32_at(image, at + 4)) else {
            return Err(malformed(format!("segment {index} header past the end of the file")));
        };
        let data = at + 8;
        let end = data
            .checked_add(length as usize)
            .filter(|&end| end <= image.len())
            .ok_or_else(|| malformed(format!("segment {index} ({length} bytes) runs past the end of the file")))?;
        checksum = image[data..end].iter().fold(checksum, |sum, byte| sum ^ byte);
        let memory = chip.memory(load_address.into()).filter(|_| length > 0);
        segments.push(EspSegment {
            load_address: load_address.into(),
            length: length.into(),
            image_offset: data as u64,
            memory: memory.map(|(name, _)| name),
            kind: memory.map(|(_, kind)| kind),
        });
        at = end;
    }
    let mapped: Vec<&EspSegment> = segments.iter().filter(|segment| segment.kind.is_some()).collect();
    for (index, a) in mapped.iter().enumerate() {
        if let Some(b) = mapped[index + 1..]
            .iter()
            .find(|b| a.load_address < b.load_address + b.length && b.load_address < a.load_address + a.length)
        {
            return Err(malformed(format!(
                "segments at {:#x} ({} bytes) and {:#x} ({} bytes) overlap",
                a.load_address, a.length, b.load_address, b.length
            )));
        }
    }
    // The checksum byte ends the 16-byte block the segments end in.
    let checksum_at = at + (15 - at % 16);
    let stored = *image.get(checksum_at).ok_or_else(|| malformed("checksum byte past the end of the file".into()))?;
    let checksum =
        EspDigest { stored: format!("{stored:02x}"), computed: format!("{checksum:02x}"), valid: stored == checksum };
    let mut length = checksum_at as u64 + 1;
    let sha256 = if hash_appended {
        let hashed = &image[..checksum_at + 1];
        image.get(checksum_at + 1..checksum_at + 33).map(|stored| {
            length += 32;
            let computed = Sha256::digest(hashed);
            EspDigest { stored: hex(stored), computed: hex(&computed), valid: stored == computed.as_slice() }
        })
    } else {
        None
    };
    let first_data = |memory: &str| {
        segments.iter().find(|segment| segment.memory == Some(memory)).and_then(|segment| {
            let start = segment.image_offset as usize;
            image.get(start..start + segment.length as usize)
        })
    };
    let app_desc = first_data(if chip == EspChip::Esp8266 { "irom" } else { "drom" }).and_then(app_desc);
    let bootloader_desc = first_data("dram").and_then(bootloader_desc);
    Ok(EspImage {
        chip,
        abi: if chip.call0() { "call0" } else { "windowed" },
        offset,
        length,
        entry,
        flash_mode: flash_mode(image[2]),
        flash_size: flash_size(chip, image[3] >> 4),
        flash_frequency: flash_frequency(chip, image[3] & 0xf),
        min_chip_revision: min_chip_revision.filter(|_| chip != EspChip::Esp8266),
        segments,
        checksum,
        sha256,
        app_desc,
        bootloader_desc,
    })
}

fn app_desc(bytes: &[u8]) -> Option<EspAppDesc> {
    if u32_at(bytes, 0)? != ESP_APP_DESC_MAGIC || bytes.len() < 0xd0 {
        return None;
    }
    Some(EspAppDesc {
        secure_version: u32_at(bytes, 4)?,
        version: text(&bytes[0x10..0x30]),
        project_name: text(&bytes[0x30..0x50]),
        compile_time: text(&bytes[0x50..0x60]),
        compile_date: text(&bytes[0x60..0x70]),
        idf_version: text(&bytes[0x70..0x90]),
        elf_sha256: hex(&bytes[0x90..0xb0]),
    })
}

fn bootloader_desc(bytes: &[u8]) -> Option<EspBootloaderDesc> {
    if *bytes.first()? != 0x50 || bytes.len() < 0x40 {
        return None;
    }
    let idf_version = text(&bytes[8..0x28]);
    idf_version.starts_with('v').then(|| EspBootloaderDesc {
        version: u32_at(bytes, 4).unwrap_or_default(),
        idf_version,
        date_time: text(&bytes[0x28..0x40]),
    })
}

/// One partition table entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EspPartition {
    pub label: String,
    /// `app`, `data`, `bootloader`, `partition_table` or the number.
    #[serde(rename = "type")]
    pub kind: String,
    /// The subtype's name (`factory`, `ota_0`, `nvs`, `phy`, `spiffs`, ...) or its number.
    pub subtype: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub offset: u64,
    pub size: u64,
    pub encrypted: bool,
}

/// A partition table and its MD5 entry check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EspPartitionTable {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub offset: u64,
    pub partitions: Vec<EspPartition>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<EspDigest>,
}

fn partition_names(kind: u8, subtype: u8) -> (String, String) {
    let kind_name = match kind {
        0 => "app",
        1 => "data",
        2 => "bootloader",
        3 => "partition_table",
        _ => return (kind.to_string(), subtype.to_string()),
    };
    let subtype_name = match (kind, subtype) {
        (0, 0x00) => "factory".to_owned(),
        (0, 0x10..=0x1f) => format!("ota_{}", subtype - 0x10),
        (0, 0x20) => "test".to_owned(),
        (1, 0x00) => "ota".to_owned(),
        (1, 0x01) => "phy".to_owned(),
        (1, 0x02) => "nvs".to_owned(),
        (1, 0x03) => "coredump".to_owned(),
        (1, 0x04) => "nvs_keys".to_owned(),
        (1, 0x05) => "efuse".to_owned(),
        (1, 0x06) => "undefined".to_owned(),
        (1, 0x80) => "esphttpd".to_owned(),
        (1, 0x81) => "fat".to_owned(),
        (1, 0x82) => "spiffs".to_owned(),
        (1, 0x83) => "littlefs".to_owned(),
        (2, 0x00) => "primary".to_owned(),
        (2, 0x01) => "ota".to_owned(),
        _ => subtype.to_string(),
    };
    (kind_name.to_owned(), subtype_name)
}

/// Reads the partition table at `offset`: entries up to the first that is not one (erased flash ends the table),
/// and the MD5 entry over the entries before it when present. `None` when the first entry is not one.
pub fn parse_partition_table(bytes: &[u8], offset: u64) -> Option<EspPartitionTable> {
    let start = usize::try_from(offset).ok()?;
    let table = bytes.get(start..start.checked_add(PARTITION_TABLE_BYTES)?.min(bytes.len()))?;
    let mut partitions = Vec::new();
    let mut md5 = None;
    for (index, entry) in table.as_chunks::<32>().0.iter().enumerate() {
        if entry[..2] == PARTITION_MD5_MAGIC {
            let computed = Md5::digest(&table[..index * 32]);
            let stored = &entry[16..32];
            md5 =
                Some(EspDigest { stored: hex(stored), computed: hex(&computed), valid: stored == computed.as_slice() });
            break;
        }
        if entry[..2] != PARTITION_MAGIC {
            break;
        }
        let (kind, subtype) = partition_names(entry[2], entry[3]);
        partitions.push(EspPartition {
            label: text(&entry[12..28]),
            kind,
            subtype,
            offset: u32_at(entry, 4)?.into(),
            size: u32_at(entry, 8)?.into(),
            encrypted: u32_at(entry, 28)? & 1 != 0,
        });
    }
    (!partitions.is_empty()).then_some(EspPartitionTable { offset, partitions, md5 })
}

/// What a whole flash dump holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EspFlashLayout {
    pub chip: EspChip,
    /// The bootloader (ESP32 family) or boot image (ESP8266) at the start of flash.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootloader: Option<EspImage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partition_table: Option<EspPartitionTable>,
}

impl EspFlashLayout {
    /// The application partitions holding an app image, with that image's offset in the dump.
    pub fn app_images<'a>(&'a self, bytes: &'a [u8]) -> impl Iterator<Item = (&'a EspPartition, u64)> + 'a {
        self.partition_table.iter().flat_map(|table| &table.partitions).filter_map(move |partition| {
            let offset = usize::try_from(partition.offset).ok()?;
            (partition.kind == "app" && looks_like_app_image(bytes, offset)).then_some((partition, partition.offset))
        })
    }
}

/// Reads a flash dump's layout: a bootloader image at 0x1000 (ESP32, ESP32-S2) or 0 (ESP32-S3, ESP8266), and a
/// partition table at 0x8000 or at another 4 KiB boundary below 0x10000 (CONFIG_PARTITION_TABLE_OFFSET). `None`
/// when neither is there.
pub fn flash_layout(bytes: &[u8]) -> Option<EspFlashLayout> {
    let bootloader = [0x1000usize, 0]
        .into_iter()
        .filter(|&offset| looks_like_app_image(bytes, offset))
        .find_map(|offset| parse_app_image(bytes, offset as u64).ok());
    let partition_table = std::iter::once(DEFAULT_PARTITION_TABLE_OFFSET)
        .chain((0x1000..0x10000).step_by(0x1000).filter(|&offset| offset != DEFAULT_PARTITION_TABLE_OFFSET))
        .find_map(|offset| parse_partition_table(bytes, offset));
    // An image at 0 alone is an app image (or an ESP8266 boot image), not evidence of a flash layout.
    if partition_table.is_none() && bootloader.as_ref().is_none_or(|image| image.offset != 0x1000) {
        return None;
    }
    let chip = bootloader.as_ref().map_or(EspChip::Esp32, |image| image.chip);
    Some(EspFlashLayout { chip, bootloader, partition_table })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(format!("{}/../../tests/fixtures/xtensa/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
    }

    #[test]
    fn esp32_app_image_states_segments_digests_and_app_desc() {
        let image = parse_app_image(&fixture("esp32-app.bin"), 0).unwrap();
        assert_eq!(image.chip, EspChip::Esp32);
        assert_eq!(image.abi, "windowed");
        assert_eq!(image.entry, 0x4008_0004);
        assert_eq!((image.flash_mode, image.flash_size, image.flash_frequency), ("dio", "1MB", "40m"));
        let memories: Vec<_> = image.segments.iter().map(|segment| segment.memory).collect();
        assert_eq!(memories, [Some("drom"), Some("dram"), Some("iram"), None, Some("irom")]);
        assert!(image.checksum.valid);
        assert!(image.sha256.as_ref().unwrap().valid);
        let desc = image.app_desc.unwrap();
        assert_eq!((desc.project_name.as_str(), desc.version.as_str()), ("thermostat", "1.4.2"));
        assert_eq!(desc.idf_version, "v5.4-fixture");
        assert_ne!(desc.elf_sha256, "0".repeat(64));
    }

    #[test]
    fn esp8266_boot_image_has_no_extended_header() {
        let image = parse_app_image(&fixture("esp8266-app-0x00000.bin"), 0).unwrap();
        assert_eq!((image.chip, image.abi, image.entry), (EspChip::Esp8266, "call0", 0x4010_000c));
        assert_eq!(image.segments.len(), 2);
        assert!(image.checksum.valid && image.sha256.is_none());
    }

    #[test]
    fn flash_dump_layout_names_partitions_and_checks_the_table() {
        let flash = fixture("esp32-flash.bin");
        let layout = flash_layout(&flash).unwrap();
        assert_eq!(layout.chip, EspChip::Esp32);
        assert_eq!(layout.bootloader.as_ref().unwrap().offset, 0x1000);
        let table = layout.partition_table.as_ref().unwrap();
        let labels: Vec<_> = table.partitions.iter().map(|p| (p.label.as_str(), p.subtype.as_str())).collect();
        assert_eq!(labels, [("nvs", "nvs"), ("phy_init", "phy"), ("factory", "factory")]);
        assert!(table.md5.as_ref().unwrap().valid);
        let apps: Vec<_> =
            layout.app_images(&flash).map(|(partition, offset)| (partition.label.clone(), offset)).collect();
        assert_eq!(apps, [("factory".to_owned(), 0x10000)]);
    }

    #[test]
    fn hostile_headers_are_refused() {
        let mut image = fixture("esp32-app.bin");
        image[1] = 17;
        assert!(parse_app_image(&image, 0).unwrap_err().to_string().contains("1..=16"));
        let mut image = fixture("esp32-app.bin");
        image[24 + 4..24 + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_app_image(&image, 0).unwrap_err().to_string().contains("past the end"));
        // The second segment (DRAM) restated at the first one's address overlaps it.
        let mut image = fixture("esp32-app.bin");
        let second = 24 + 8 + 0x268;
        image[second..second + 4].copy_from_slice(&0x3f40_0030u32.to_le_bytes());
        assert!(parse_app_image(&image, 0).unwrap_err().to_string().contains("overlap"));
        let mut image = fixture("esp32-app.bin");
        image[0x30] ^= 1;
        let parsed = parse_app_image(&image, 0).unwrap();
        assert!(!parsed.checksum.valid && !parsed.sha256.unwrap().valid);
        assert!(parse_app_image(&image[..100], 0).is_err());
        assert!(parse_app_image(&[0xe9], 0).is_err());
    }
}
