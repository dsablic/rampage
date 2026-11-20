//! Carving: a bounded, read-only scan of a file for embedded executables (ELF, PE, Mach-O) and containers (zip,
//! gzip, xz, zstd, LZMA, bzip2, LZ4, LZOP, squashfs, ext2/3/4, UBI, UBIFS, JFFS2, CramFS, FAT, Android sparse images,
//! OTA payloads, cpio, tar, uImage, TRX, device trees, Android boot images, MBR and GPT disks, UEFI firmware volumes
//! and capsules), found by magic and checked against their headers. Nothing is extracted, decompressed or executed:
//! extents come from header tables alone.
//!
//! The ext, tar, bzip2, Android sparse, UBI, UBIFS, JFFS2, CramFS, TRX, device tree, LZ4, LZOP, MBR, GPT, FAT and
//! UEFI header checks follow binwalk's signatures (MIT, Copyright (c) 2024 devttys0), adapted to the scan's bounds;
//! see THIRD-PARTY-NOTICES.

use std::fs::File;
use std::path::Path;

use memmap2::Mmap;
use rampage_arch::Arch;
use rampage_arch::bytes::read_uint;
use serde::Serialize;

use crate::LoadError;

/// The most candidates one scan reports; the scan stops at the first candidate past it.
pub const MAX_CANDIDATES: usize = 4096;
/// The longest prefix of a file one scan reads.
pub const MAX_SCAN_BYTES: u64 = 4 << 30;
/// The most bytes one scan searches for the end of gzip header fields, whose terminator can be far from the header
/// that names them; past it, gzip headers carrying such fields are no longer checked.
pub const MAX_PROBE_BYTES: u64 = 64 << 20;
/// The most header bytes one scan reads walking tar headers, and again each for Android sparse chunk headers, OTA
/// payload manifests, UBI erase block headers and JFFS2 nodes, and the most bytes it checksums for CramFS images and
/// again for TRX containers; past a format's budget, its candidates are no longer walked or checksummed.
pub const MAX_WALK_BYTES: u64 = 64 << 20;
/// The most table entries (ELF program and section headers, Mach-O load commands, fat slices, archive members)
/// read for one candidate.
const MAX_TABLE_ENTRIES: usize = 4096;
/// The furthest `e_lfanew` may point; real linkers keep it within the first few hundred bytes.
const MAX_PE_HEADER_OFFSET: usize = 1 << 20;
const MAX_FAT_SLICES: u64 = 64;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_candidates: usize,
    pub max_scan_bytes: u64,
    pub max_probe_bytes: u64,
    pub max_walk_bytes: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_candidates: MAX_CANDIDATES,
            max_scan_bytes: MAX_SCAN_BYTES,
            max_probe_bytes: MAX_PROBE_BYTES,
            max_walk_bytes: MAX_WALK_BYTES,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Elf,
    Pe,
    MachO,
    MachOFat,
    Zip,
    Gzip,
    Xz,
    Zstd,
    Lzma,
    Squashfs,
    Cpio,
    UImage,
    AndroidBoot,
    /// An ext2, ext3 or ext4 file system.
    Ext,
    AndroidSparse,
    /// A POSIX ustar (or GNU) tar archive.
    Tar,
    Bzip2,
    /// An Android OTA `payload.bin` (update_engine).
    OtaPayload,
    /// A UBI image: a run of physical erase blocks, each starting with an erase counter header.
    Ubi,
    /// A UBIFS file system, found by its superblock node.
    Ubifs,
    Jffs2,
    Cramfs,
    /// A Broadcom TRX firmware container.
    Trx,
    /// A flattened device tree (also the format of U-Boot FIT images).
    Dtb,
    /// An LZ4 frame.
    Lz4,
    Lzop,
    /// A DOS master boot record with its partition table.
    Mbr,
    /// A GUID partition table disk: the protective MBR, then the GPT header.
    Gpt,
    /// A FAT12, FAT16 or FAT32 file system, found by its boot sector.
    Fat,
    /// A UEFI (PI) firmware volume.
    UefiVolume,
    UefiCapsule,
    /// An Espressif ESP8266/ESP32 app or bootloader image (magic 0xE9 and segment headers).
    EspImage,
    /// An ESP-IDF partition table (0xAA50 entries and their MD5 entry), on a 4 KiB boundary of a flash dump.
    EspPartitionTable,
}

/// What the scan reports inside an image or container, once its extent is validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Inside {
    /// Contents compressed or split into chunks (SquashFS, UBIFS, JFFS2 and CramFS blocks, OTA blobs, sparse
    /// chunks): only executables whose headers validate are reported, since anything else found there is a
    /// fragment of the image's own encoding.
    Executables,
    /// Contents stored whole in an image `fs_list` reads (ext, tar, cpio and zip files, UBI volumes, whose LEBs
    /// often hold a SquashFS image): every candidate whose header validates is reported; only magic-only matches
    /// are left out.
    Validated,
    /// Contents stored raw in a container `fs_list` does not read (TRX, device trees, MBR and GPT disks, FAT, UEFI
    /// volumes and capsules): every candidate is reported, since carving is the only way to find them, and marked
    /// with the container.
    All,
}

impl Kind {
    fn inside(self) -> Option<Inside> {
        match self {
            Self::Squashfs | Self::AndroidSparse | Self::OtaPayload | Self::Ubifs | Self::Jffs2 | Self::Cramfs => {
                Some(Inside::Executables)
            }
            Self::Ext | Self::Cpio | Self::Tar | Self::Zip | Self::Ubi => Some(Inside::Validated),
            Self::Trx | Self::Dtb | Self::Mbr | Self::Gpt | Self::Fat | Self::UefiVolume | Self::UefiCapsule => {
                Some(Inside::All)
            }
            _ => None,
        }
    }

    /// Whether `fs_list` lists this image's contents.
    fn listed_by_fs_list(self) -> bool {
        !matches!(self, Self::Jffs2 | Self::Cramfs) && self.inside() != Some(Inside::All)
    }

    fn is_executable(self) -> bool {
        matches!(self, Self::Elf | Self::Pe | Self::MachO | Self::MachOFat)
    }
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Elf => "elf",
            Self::Pe => "pe",
            Self::MachO => "mach_o",
            Self::MachOFat => "mach_o_fat",
            Self::Zip => "zip",
            Self::Gzip => "gzip",
            Self::Xz => "xz",
            Self::Zstd => "zstd",
            Self::Lzma => "lzma",
            Self::Squashfs => "squashfs",
            Self::Cpio => "cpio",
            Self::UImage => "u_image",
            Self::AndroidBoot => "android_boot",
            Self::Ext => "ext",
            Self::AndroidSparse => "android_sparse",
            Self::Tar => "tar",
            Self::Bzip2 => "bzip2",
            Self::OtaPayload => "ota_payload",
            Self::Ubi => "ubi",
            Self::Ubifs => "ubifs",
            Self::Jffs2 => "jffs2",
            Self::Cramfs => "cramfs",
            Self::Trx => "trx",
            Self::Dtb => "dtb",
            Self::Lz4 => "lz4",
            Self::Lzop => "lzop",
            Self::Mbr => "mbr",
            Self::Gpt => "gpt",
            Self::Fat => "fat",
            Self::UefiVolume => "uefi_volume",
            Self::UefiCapsule => "uefi_capsule",
            Self::EspImage => "esp_image",
            Self::EspPartitionTable => "esp_partition_table",
        })
    }
}

/// How far a candidate's header was checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// The header's fields and tables were checked for consistency within the file.
    Validated,
    /// Only the magic (or, for LZMA, a plausible header) matched; the header is truncated, inconsistent or
    /// carries no checkable structure, so no other facts are reported.
    MagicOnly,
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Validated => "validated",
            Self::MagicOnly => "magic_only",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Endianness {
    Little,
    Big,
}

impl std::fmt::Display for Endianness {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Little => "little-endian",
            Self::Big => "big-endian",
        })
    }
}

/// One architecture slice of a universal Mach-O; `offset` is in the scanned file, not relative to the header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FatSlice {
    pub arch: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Candidate {
    /// Where the candidate starts in the scanned file.
    pub offset: u64,
    pub kind: Kind,
    pub confidence: Confidence,
    pub arch: Option<String>,
    pub bits: Option<u8>,
    pub endianness: Option<Endianness>,
    /// The size the header records for the object as stored, where the format records one.
    pub declared_size: Option<u64>,
    /// The decompressed size the header records; not verified, since nothing is decompressed.
    pub uncompressed_size: Option<u64>,
    /// Estimated length in bytes from `offset`, from header tables; absent when only decompression or an
    /// unbounded walk could tell. It may run past the end of the file, which a note then says.
    pub extent: Option<u64>,
    /// Which header structures the extent was computed from.
    pub extent_source: Option<&'static str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub slices: Vec<FatSlice>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl Candidate {
    fn new(kind: Kind) -> Self {
        Self {
            offset: 0,
            kind,
            confidence: Confidence::Validated,
            arch: None,
            bits: None,
            endianness: None,
            declared_size: None,
            uncompressed_size: None,
            extent: None,
            extent_source: None,
            slices: Vec::new(),
            notes: Vec::new(),
        }
    }

    /// A candidate whose header did not validate: it keeps only the reason.
    fn magic_only(kind: Kind, reason: impl Into<String>) -> Self {
        Self { confidence: Confidence::MagicOnly, notes: vec![reason.into()], ..Self::new(kind) }
    }

    fn endian(mut self, big: bool) -> Self {
        self.endianness = Some(if big { Endianness::Big } else { Endianness::Little });
        self
    }

    fn extent(mut self, extent: u64, source: &'static str) -> Self {
        self.extent = Some(extent);
        self.extent_source = Some(source);
        self
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Carving {
    pub file_size: u64,
    /// How many leading bytes were searched for candidates (header tables may be read past it).
    pub scanned_bytes: u64,
    pub candidates: Vec<Candidate>,
    /// Whether a limit cut the scan short; `limitations` says which.
    pub truncated: bool,
    pub limitations: Vec<String>,
    /// Whether a candidate past `Limits::max_candidates` stopped the scan; its limitation comes first.
    #[serde(skip)]
    candidate_cap_reached: bool,
    /// Whether a limit other than the candidate cap cut the scan short.
    #[serde(skip)]
    otherwise_truncated: bool,
}

impl Carving {
    /// For a caller that set the candidate cap to end a page rather than to limit the scan: drops the cap's
    /// limitation, keeping `truncated` only for the other limits.
    pub fn treat_candidate_cap_as_page_end(&mut self) {
        if std::mem::take(&mut self.candidate_cap_reached) {
            self.limitations.remove(0);
            self.truncated = self.otherwise_truncated;
        }
    }
}

/// Carves the regular file at `path`, mapping it read-only.
pub fn carve_file(path: &Path, limits: &Limits) -> Result<Carving, LoadError> {
    Ok(match map_regular_file(path)? {
        Some(data) => scan(&data, limits),
        None => scan(&[], limits),
    })
}

/// Opens `path` for reading, refusing anything but a regular file.
pub(crate) fn open_regular_file(path: &Path) -> Result<File, LoadError> {
    let io_error = |source| LoadError::Io { path: path.to_owned(), source };
    // Checked before opening: opening a FIFO for reading blocks until a writer appears.
    if !std::fs::metadata(path).map_err(io_error)?.is_file() {
        return Err(io_error(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a regular file")));
    }
    File::open(path).map_err(io_error)
}

/// Maps the regular file at `path` read-only, or `None` when it is empty (an empty file cannot be mapped).
pub(crate) fn map_regular_file(path: &Path) -> Result<Option<Mmap>, LoadError> {
    let io_error = |source| LoadError::Io { path: path.to_owned(), source };
    let file = open_regular_file(path)?;
    if file.metadata().map_err(io_error)?.len() == 0 {
        return Ok(None);
    }
    // SAFETY: the mapping is read-only; a concurrent external truncation of the input is out of scope, the same
    // assumption `Binary::open` makes.
    Ok(Some(unsafe { Mmap::map(&file) }.map_err(io_error)?))
}

/// An image enclosing the scan's offset, and the candidates left out inside it so far.
struct Enclosing {
    end: usize,
    inside: Inside,
    /// The image's index among the candidates.
    index: usize,
    left_out: Vec<(Kind, usize)>,
}

impl Enclosing {
    fn leave_out(&mut self, kind: Kind) {
        match self.left_out.iter_mut().find(|(seen, _)| *seen == kind) {
            Some((_, count)) => *count += 1,
            None => self.left_out.push((kind, 1)),
        }
    }

    /// Notes on the image what was left out inside it.
    fn finish(self, candidates: &mut [Candidate]) {
        let total: usize = self.left_out.iter().map(|(_, count)| count).sum();
        let mut note = match self.inside {
            Inside::Executables => "inside it only executables whose headers validate are reported".to_owned(),
            Inside::Validated => "inside it only candidates whose headers validate are reported".to_owned(),
            // Nothing is left out, and each candidate inside names the container.
            Inside::All => return,
        };
        if total > 0 {
            let kinds: Vec<String> = self.left_out.iter().map(|(kind, count)| format!("{count} {kind}")).collect();
            let plural = if total == 1 { "" } else { "s" };
            note.push_str(&format!("; left out inside it: {total} candidate{plural} ({})", kinds.join(", ")));
        }
        let kind = candidates[self.index].kind;
        note.push_str(if kind.listed_by_fs_list() {
            "; fs_list lists its contents"
        } else {
            "; fs_list does not read it"
        });
        candidates[self.index].notes.push(note);
    }
}

/// Scans `data` for embedded executables and containers, in offset order.
pub fn scan(data: &[u8], limits: &Limits) -> Carving {
    let scanned = data.len().min(usize::try_from(limits.max_scan_bytes).unwrap_or(usize::MAX));
    let mut candidates = Vec::new();
    let mut limitations = Vec::new();
    let mut otherwise_truncated = false;
    let mut candidate_cap_reached = false;
    // Archive member headers inside an archive already reported are part of it, not new archives.
    let mut zip_members_until = 0;
    let mut cpio_members_until = 0;
    let mut tar_members_until = 0;
    // Likewise UBI erase block headers and JFFS2 nodes inside an image already walked.
    let mut ubi_blocks_until = 0;
    let mut jffs2_nodes_until = 0;
    // A FAT32 volume's backup boot sector is part of it, not another volume.
    let mut fat_backup_at = usize::MAX;
    // The images and containers that enclose the offset, outermost first; see `Inside` for what each reports.
    let mut enclosing: Vec<Enclosing> = Vec::new();
    let mut probe = Probe { left: limits.max_probe_bytes, exhausted: false };
    let mut probe_exhausted_at = None;
    // Each walked or checksummed format has its own budget, so that one long walk does not starve the others.
    let mut walks = [(); WALKS.len()].map(|()| Probe { left: limits.max_walk_bytes, exhausted: false });
    let mut walk_exhausted_at = [None; WALKS.len()];
    // Candidates left out inside images so far, and where a scan past the cap of those resumes.
    let (mut left_out, mut left_out_capped, mut skip_until) = (0usize, false, 0usize);
    let mut next = 0;
    while let Some(offset) = next_maybe(data, next, scanned) {
        next = offset + 1;
        if offset < skip_until {
            next = skip_until;
            continue;
        }
        let bytes = &data[offset..];
        while let Some(image) = enclosing.pop_if(|image| offset >= image.end) {
            image.finish(&mut candidates);
        }
        let [
            tar_walk,
            sparse_walk,
            ota_walk,
            ubi_walk,
            jffs2_walk,
            cramfs_sum,
            trx_sum,
            ubifs_sum,
            gpt_sum,
            fv_sum,
            esp_sum,
        ] = &mut walks;
        let mut found = match bytes[0] {
            0x7f | b'M' | 0xfe | 0xce | 0xcf | 0xca => executable(bytes),
            b'P' if offset >= zip_members_until => zip(bytes).map(|(candidate, walked)| {
                zip_members_until = offset.saturating_add(walked);
                candidate
            }),
            0x1f => {
                let found = gzip(bytes, &mut probe);
                if probe.exhausted {
                    probe_exhausted_at.get_or_insert(offset);
                }
                found
            }
            0xfd => xz(bytes),
            0x28 => zstd(bytes).or_else(|| cramfs(bytes, cramfs_sum)),
            0x45 => cramfs(bytes, cramfs_sum),
            0x5d => lzma(bytes),
            b'B' => bzip2(bytes),
            b'h' | b's' => squashfs(bytes),
            b'0' if offset >= cpio_members_until => cpio(bytes).map(|(candidate, walked)| {
                cpio_members_until = offset.saturating_add(walked);
                candidate
            }),
            0x27 => uimage(bytes),
            b'A' => android_boot(bytes),
            0x3a => android_sparse(bytes, sparse_walk),
            b'C' => ota_payload(bytes, ota_walk),
            b'U' if offset >= ubi_blocks_until => ubi(bytes, ubi_walk).map(|(candidate, walked)| {
                ubi_blocks_until = offset.saturating_add(walked);
                candidate
            }),
            0x31 => ubifs(bytes, ubifs_sum),
            0x19 | 0x85 if offset >= jffs2_nodes_until => jffs2(bytes, jffs2_walk).map(|(candidate, walked)| {
                jffs2_nodes_until = offset.saturating_add(walked);
                candidate
            }),
            b'H' => trx(bytes, trx_sum),
            0xd0 => dtb(bytes),
            0x04 => lz4(bytes),
            0x89 => lzop(bytes),
            0xeb | 0xe9 if offset != fat_backup_at => fat_fs(bytes)
                .map(|(candidate, backup)| {
                    if backup != 0 {
                        fat_backup_at = offset.saturating_add(backup);
                    }
                    candidate
                })
                .or_else(|| esp_image(bytes, offset, esp_sum)),
            0xaa if offset.is_multiple_of(ESP_PARTITION_TABLE_ALIGN) => esp_partition_table(bytes),
            0xbd | 0x8b | 0xb9 | 0xed => uefi_capsule(bytes),
            _ => None,
        };
        // ext, tar, UEFI volume and MBR headers have no magic at their start, so offsets are checked for theirs, also
        // where a magic at the start only matched: a tar member named "UBI#..." must not hide its tar header.
        let weak = |found: &Option<Candidate>| found.as_ref().is_none_or(|c| c.confidence == Confidence::MagicOnly);
        if weak(&found) && bytes.get(EXT_MAGIC_AT) == Some(&EXT_MAGIC[0]) {
            prefer(&mut found, ext(bytes));
        }
        if weak(&found) && bytes.get(FV_MAGIC_AT) == Some(&FV_MAGIC[0]) {
            prefer(&mut found, uefi_volume(bytes, fv_sum));
        }
        if weak(&found) && offset % SECTOR == 0 && bytes.get(BOOT_SIGNATURE_AT) == Some(&BOOT_SIGNATURE[0]) {
            prefer(&mut found, disk(bytes, gpt_sum));
        }
        if weak(&found) && bytes.get(TAR_MAGIC_AT) == Some(&TAR_MAGIC[0]) && offset >= tar_members_until {
            let archive = tar(bytes, tar_walk).map(|(candidate, walked)| {
                tar_members_until = offset.saturating_add(walked);
                candidate
            });
            prefer(&mut found, archive);
        }
        for (walk, exhausted_at) in walks.iter().zip(&mut walk_exhausted_at) {
            if walk.exhausted {
                exhausted_at.get_or_insert(offset);
            }
        }
        let Some(mut candidate) = found else { continue };
        if let Some(image) = enclosing.last_mut() {
            let validated = candidate.confidence == Confidence::Validated;
            let reported = match image.inside {
                Inside::Executables => validated && candidate.kind.is_executable(),
                Inside::Validated => validated,
                Inside::All => true,
            };
            if !reported {
                image.leave_out(candidate.kind);
                left_out += 1;
                // Each candidate left out cost a header check: past the cap, the rest of the outermost image is
                // skipped, so that an image forged to enclose repeated decoys costs no more than that.
                if left_out >= MAX_LEFT_OUT {
                    let outermost = &enclosing[0];
                    skip_until = outermost.end;
                    if !left_out_capped {
                        left_out_capped = true;
                        otherwise_truncated = true;
                        let image = &candidates[outermost.index];
                        limitations.push(format!(
                            "{MAX_LEFT_OUT} candidates were left out inside images by offset {offset:#x}: the rest of \
                             the {} at {:#x}, up to {:#x}, was not scanned, nor the rest of any image past the cap",
                            image.kind, image.offset, outermost.end
                        ));
                    }
                }
                continue;
            }
            let outer = &candidates[image.index];
            candidate.notes.push(format!("inside the {} at {:#x}", outer.kind, outer.offset));
        }
        if candidates.len() >= limits.max_candidates {
            candidate_cap_reached = true;
            limitations.push(format!(
                "stopped at the candidate cap ({}) at offset {offset:#x}; later offsets were not scanned",
                limits.max_candidates
            ));
            break;
        }
        candidate.offset = offset as u64;
        for slice in &mut candidate.slices {
            slice.offset = slice.offset.saturating_add(offset as u64);
        }
        if let Some(extent) = candidate.extent
            && extent > bytes.len() as u64
        {
            candidate
                .notes
                .push(format!("extent runs {:#x} bytes past the end of the file", extent - bytes.len() as u64));
        }
        if let Some(extent) = candidate.extent
            && extent <= bytes.len() as u64
            && candidate.confidence == Confidence::Validated
            && let Some(inside) = candidate.kind.inside()
        {
            let end = offset + extent as usize;
            enclosing.push(Enclosing { end, inside, index: candidates.len(), left_out: Vec::new() });
        }
        candidates.push(candidate);
    }
    while let Some(image) = enclosing.pop() {
        image.finish(&mut candidates);
    }
    if scanned < data.len() {
        otherwise_truncated = true;
        limitations.push(format!("scanned only the first {scanned:#x} of {:#x} bytes", data.len()));
    }
    if let Some(offset) = probe_exhausted_at {
        otherwise_truncated = true;
        limitations.push(format!(
            "the search for gzip header name and comment ends ran out of its {:#x}-byte budget at offset \
             {offset:#x}; gzip streams carrying those fields from there on were not reported",
            limits.max_probe_bytes
        ));
    }
    for (text, offset) in WALKS.iter().zip(walk_exhausted_at) {
        if let Some(offset) = offset {
            otherwise_truncated = true;
            limitations.push(
                text.replace("{budget}", &format!("{:#x}", limits.max_walk_bytes))
                    .replace("{offset}", &format!("{offset:#x}")),
            );
        }
    }
    limitations.push(
        "candidates are found by magic and header checks only: nothing is extracted, decompressed or executed, \
         and compressed streams have no extent unless their header records one"
            .to_owned(),
    );
    limitations.push(
        "zip, cpio and tar headers inside a reported archive, up to its end or its last member header read, are \
         taken as its members: an archive stored inside another archive's members is not reported separately; \
         likewise UBI erase blocks and JFFS2 nodes inside a reported image"
            .to_owned(),
    );
    limitations.push(
        "inside a squashfs, UBIFS, JFFS2, CramFS, Android sparse or OTA payload image whose validated extent lies \
         within the file, only executables whose headers validate are reported; inside such an ext, UBI, tar, cpio \
         or zip image, only candidates whose headers validate. Each image's notes count what was left out. Inside a \
         TRX, device tree, MBR, GPT, FAT or UEFI container every candidate is reported, marked with it"
            .to_owned(),
    );
    limitations.push(
        "MBR and GPT disks are looked for only at 512-byte-aligned file offsets, with 512-byte sectors".to_owned(),
    );
    Carving {
        file_size: data.len() as u64,
        scanned_bytes: scanned as u64,
        candidates,
        truncated: candidate_cap_reached || otherwise_truncated,
        limitations,
        candidate_cap_reached,
        otherwise_truncated,
    }
}

/// The first offset in `from..to` where a header may start, by a few byte loads: the formats with a magic at their
/// start, and those whose magic lies further in (ext, tar, UEFI volumes, and boot sectors at 512-byte boundaries).
/// Kept out of the scan's loop, so that the common case of no header compiles to a tight loop.
#[inline(never)]
fn next_maybe(data: &[u8], from: usize, to: usize) -> Option<usize> {
    let window_end = to.min(data.len().saturating_sub(PREFILTER_WINDOW - 1));
    let mut offset = from;
    while offset < window_end {
        let window = &data[offset..offset + PREFILTER_WINDOW];
        if starts_a_magic(window[0], window[1])
            | (window[EXT_MAGIC_AT] == EXT_MAGIC[0])
            | (window[TAR_MAGIC_AT] == TAR_MAGIC[0])
            | (window[FV_MAGIC_AT] == FV_MAGIC[0])
            | (offset.is_multiple_of(SECTOR) && window[BOOT_SIGNATURE_AT] == BOOT_SIGNATURE[0])
        {
            return Some(offset);
        }
        offset += 1;
    }
    (offset..to).find(|&offset| {
        let bytes = &data[offset..];
        starts_a_magic(bytes[0], bytes.get(1).copied().unwrap_or(0))
            || bytes.get(EXT_MAGIC_AT) == Some(&EXT_MAGIC[0])
            || bytes.get(TAR_MAGIC_AT) == Some(&TAR_MAGIC[0])
            || bytes.get(FV_MAGIC_AT) == Some(&FV_MAGIC[0])
            || (offset.is_multiple_of(SECTOR) && bytes.get(BOOT_SIGNATURE_AT) == Some(&BOOT_SIGNATURE[0]))
    })
}

/// Replaces a missing or magic-only candidate with `other` when that is found and does better.
fn prefer(found: &mut Option<Candidate>, other: Option<Candidate>) {
    if let Some(other) = other
        && (found.is_none() || other.confidence == Confidence::Validated)
    {
        *found = Some(other);
    }
}

/// The bytes from an offset the prefilter reads: through the ext superblock magic, the furthest it looks.
const PREFILTER_WINDOW: usize = EXT_MAGIC_AT + 1;

/// The most candidates one scan leaves out inside images before it skips the rest of them.
pub const MAX_LEFT_OUT: usize = 16 * MAX_CANDIDATES;

/// The executable (ELF, PE, Mach-O or universal Mach-O) whose header starts `bytes`, checked as a scan checks it,
/// with its offset 0.
pub fn executable(bytes: &[u8]) -> Option<Candidate> {
    match bytes.first()? {
        0x7f => elf(bytes),
        b'M' => pe(bytes),
        0xfe | 0xce | 0xcf => macho(bytes),
        0xca => fat(bytes),
        _ => None,
    }
}

/// The magics that start a header, as the scan's parsers check them: the scan dispatches only on their first two
/// bytes (see `STARTS_A_MAGIC`). A FAT boot sector starts with a jump whose second byte is its target, so 0xeb and
/// 0xe9 take any second byte.
const MAGICS: [&[u8]; 36] = [
    b"\x7fELF",
    b"MZ",
    b"\xfe\xed\xfa",
    b"\xce\xfa\xed\xfe",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"PK\x03\x04",
    b"\x1f\x8b\x08",
    b"\xfd7zXZ\0",
    b"\x28\xb5\x2f\xfd",
    b"\x28\xcd\x3d\x45",
    b"\x45\x3d\xcd\x28",
    b"\x5d\x00",
    b"BZh",
    b"hsqs",
    b"sqsh",
    b"0707",
    b"\x27\x05\x19\x56",
    b"ANDROID!",
    b"\x3a\xff\x26\xed",
    b"CrAU",
    UBI_EC_MAGIC,
    b"\x31\x18\x10\x06",
    b"\x19\x85",
    b"\x85\x19",
    b"HDR0",
    b"\xd0\x0d\xfe\xed",
    b"\x04\x22\x4d\x18",
    &LZOP_MAGIC,
    CAPSULE_GUIDS[0].0,
    CAPSULE_GUIDS[1].0,
    CAPSULE_GUIDS[2].0,
    CAPSULE_GUIDS[3].0,
    b"\xeb",
    b"\xe9",
    b"\xaa\x50",
];

/// The first two bytes of `MAGICS`, as a bit set indexed by the two bytes.
const STARTS_A_MAGIC: [u64; 1024] = {
    let mut table = [0u64; 1024];
    let mut index = 0;
    while index < MAGICS.len() {
        let magic = MAGICS[index];
        // A one-byte magic takes any second byte.
        let (mut second, last) = if magic.len() == 1 { (0, 255) } else { (magic[1] as usize, magic[1] as usize) };
        while second <= last {
            let bit = (magic[0] as usize) << 8 | second;
            table[bit >> 6] |= 1 << (bit & 63);
            second += 1;
        }
        index += 1;
    }
    table
};

/// Whether a format's magic starts with these two bytes.
fn starts_a_magic(first: u8, second: u8) -> bool {
    let bit = usize::from(first) << 8 | usize::from(second);
    STARTS_A_MAGIC[bit >> 6] >> (bit & 63) & 1 != 0
}

fn end_of(offset: u64, size: u64) -> Option<u64> {
    offset.checked_add(size)
}

/// A table of `count` entries of `size` bytes at `offset`, if it lies within `bytes`.
fn table_fits(bytes: &[u8], offset: u64, count: u64, size: u64) -> Option<u64> {
    let end = offset.checked_add(count.checked_mul(size)?)?;
    (end <= bytes.len() as u64).then_some(end)
}

fn table_note(what: &str, count: u64) -> Option<String> {
    (count > MAX_TABLE_ENTRIES as u64)
        .then(|| format!("read only the first {MAX_TABLE_ENTRIES} of {count} {what}; the extent may be low"))
}

fn elf_arch(machine: u64, bits: u8) -> String {
    let arch = match (machine, bits) {
        (3, _) => Arch::X86,
        (62, _) => Arch::X86_64,
        (183, _) => Arch::Aarch64,
        (40, _) => Arch::Arm,
        (8 | 10, 64) => Arch::Mips64,
        (8 | 10, _) => Arch::Mips,
        (20, _) => Arch::PowerPc,
        (21, _) => Arch::PowerPc64,
        (243, 64) => Arch::Riscv64,
        (243, _) => Arch::Riscv32,
        (2 | 18, _) => Arch::Sparc,
        (43, _) => Arch::Sparc64,
        (22, 64) => Arch::S390x,
        (4, _) => Arch::M68k,
        (94, _) => Arch::Xtensa,
        _ => return format!("elf machine {machine:#x}"),
    };
    arch.to_string()
}

fn elf(bytes: &[u8]) -> Option<Candidate> {
    if !bytes.starts_with(b"\x7fELF") {
        return None;
    }
    let (bits, wide) = match bytes.get(4)? {
        1 => (32, false),
        2 => (64, true),
        _ => return None,
    };
    let big = match bytes.get(5)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let read = |at: u64, width: usize| read_uint(bytes, usize::try_from(at).ok()?, width, big);
    let word = if wide { 8 } else { 4 };
    let at = |narrow: u64, wide_at: u64| if wide { wide_at } else { narrow };
    let header = || -> Option<[u64; 9]> {
        Some([
            read(16, 2)?,
            read(18, 2)?,
            read(20, 4)?,
            read(at(28, 32), word)?,
            read(at(32, 40), word)?,
            read(at(40, 52), 2)?,
            read(at(42, 54), 2)?,
            read(at(44, 56), 2)?,
            read(at(48, 60), 2)?,
        ])
    };
    let Some([kind, machine, version, phoff, shoff, ehsize, phentsize, phnum, shnum]) = header() else {
        return Some(Candidate::magic_only(Kind::Elf, "ELF header is truncated"));
    };
    let shentsize = read(at(46, 58), 2)?;
    let (ehsize_ok, phent_ok, shent_ok) = if wide { (64, 56, 64) } else { (52, 32, 40) };
    if bytes[6] != 1
        || version != 1
        || !(1..=4).contains(&kind)
        || ehsize != ehsize_ok
        || (phnum != 0 && phentsize != phent_ok)
        || (shnum != 0 && shentsize != shent_ok)
    {
        return Some(Candidate::magic_only(Kind::Elf, "ELF header fields are inconsistent"));
    }
    let Some(ph_end) = table_fits(bytes, phoff, phnum, phentsize) else {
        return Some(Candidate::magic_only(Kind::Elf, "ELF program header table lies outside the file"));
    };
    let Some(sh_end) = table_fits(bytes, shoff, shnum, shentsize) else {
        return Some(Candidate::magic_only(Kind::Elf, "ELF section header table lies outside the file"));
    };
    let mut candidate = Candidate::new(Kind::Elf).endian(big);
    candidate.bits = Some(bits);
    candidate.arch = Some(elf_arch(machine, bits));
    // A section header table starts with an all-zero entry and holds its own string table's index. One that does not
    // is not this file's: in a file system image, the file's later blocks need not follow its first.
    let sections_ok = shnum == 0
        || (usize::try_from(shoff)
            .ok()
            .and_then(|at| bytes.get(at..at + shentsize as usize))
            .is_some_and(|entry| entry.iter().all(|&byte| byte == 0))
            && read(at(50, 62), 2).is_some_and(|index| index < shnum));
    let shnum = if sections_ok { shnum } else { 0 };
    let mut end = ehsize.max(if phnum == 0 { 0 } else { ph_end }).max(if shnum == 0 { 0 } else { sh_end });
    let overflow = || Some(Candidate::magic_only(Kind::Elf, "an ELF segment or section ends past 2^64"));
    for index in 0..phnum.min(MAX_TABLE_ENTRIES as u64) {
        let entry = phoff + index * phentsize;
        let (offset, size) = (read(entry + at(4, 8), word)?, read(entry + at(16, 32), word)?);
        let Some(segment_end) = end_of(offset, size) else { return overflow() };
        end = end.max(segment_end);
    }
    for index in 0..shnum.min(MAX_TABLE_ENTRIES as u64) {
        let entry = shoff + index * shentsize;
        if matches!(read(entry + 4, 4)?, 0 | 8) {
            continue;
        }
        let (offset, size) = (read(entry + at(16, 24), word)?, read(entry + at(20, 32), word)?);
        let Some(section_end) = end_of(offset, size) else { return overflow() };
        end = end.max(section_end);
    }
    candidate.notes.extend(table_note("program headers", phnum));
    candidate.notes.extend(table_note("section headers", shnum));
    if !sections_ok {
        candidate.notes.push(
            "the section header table does not check out (no null first entry or string table index), so the \
             extent leaves it out: the file may be fragmented or cut short here"
                .to_owned(),
        );
        return Some(candidate.extent(end, "ELF header and program header table"));
    }
    Some(candidate.extent(end, "ELF header, program and section header tables"))
}

fn pe_arch(machine: u64) -> String {
    let arch = match machine {
        0x14c => Arch::X86,
        0x8664 => Arch::X86_64,
        0xaa64 => Arch::Aarch64,
        0x1c0 | 0x1c2 | 0x1c4 => Arch::Arm,
        0x166 | 0x168 | 0x169 => Arch::Mips,
        0x1f0 | 0x1f1 => Arch::PowerPc,
        0x5032 => Arch::Riscv32,
        0x5064 => Arch::Riscv64,
        _ => return format!("pe machine {machine:#x}"),
    };
    arch.to_string()
}

fn pe(bytes: &[u8]) -> Option<Candidate> {
    if !bytes.starts_with(b"MZ") {
        return None;
    }
    // "MZ" alone is too common to report: a candidate needs the PE signature `e_lfanew` points at.
    let lfanew = read_uint(bytes, 0x3c, 4, false)? as usize;
    if !(0x40..=MAX_PE_HEADER_OFFSET).contains(&lfanew) || bytes.get(lfanew..lfanew + 4)? != b"PE\0\0" {
        return None;
    }
    let read = |at: usize, width: usize| read_uint(bytes, at, width, false);
    let coff = lfanew + 4;
    let optional = coff + 20;
    let header = || Some([read(coff, 2)?, read(coff + 2, 2)?, read(coff + 16, 2)?, read(optional, 2)?]);
    let Some([machine, sections, optional_size, magic]) = header() else {
        return Some(Candidate::magic_only(Kind::Pe, "PE headers are truncated"));
    };
    let (bits, directories) = match magic {
        0x10b => (32, 96),
        0x20b => (64, 112),
        _ => return Some(Candidate::magic_only(Kind::Pe, "PE optional header magic is neither PE32 nor PE32+")),
    };
    let section_table = optional + optional_size as usize;
    if optional_size < directories || !(1..=96).contains(&sections) {
        return Some(Candidate::magic_only(Kind::Pe, "PE optional header or section count is inconsistent"));
    }
    if table_fits(bytes, section_table as u64, sections, 40).is_none() {
        return Some(Candidate::magic_only(Kind::Pe, "PE section table lies outside the file"));
    }
    let mut candidate = Candidate::new(Kind::Pe).endian(false);
    candidate.bits = Some(bits);
    candidate.arch = Some(pe_arch(machine));
    let mut end = read(optional + 60, 4)?.max(section_table as u64 + sections * 40);
    for index in 0..sections as usize {
        let entry = section_table + index * 40;
        let (size, offset) = (read(entry + 16, 4)?, read(entry + 20, 4)?);
        if size != 0 {
            end = end.max(offset + size);
        }
    }
    let mut source = "PE headers and section table";
    let (symbols, count) = (read(coff + 8, 4)?, read(coff + 12, 4)?);
    if symbols != 0 {
        let strings = symbols + count * 18;
        let string_size = usize::try_from(strings).ok().and_then(|at| read(at, 4)).unwrap_or(4);
        end = end.max(strings + string_size.max(4));
        source = "PE headers, section table and COFF symbol table";
    }
    // The Authenticode certificate table is the one data directory addressed by file offset, not RVA.
    let rva_count = read(optional + directories as usize - 4, 4)?;
    if rva_count > 4 && optional_size >= directories + 5 * 8 {
        let certificates = optional + directories as usize + 4 * 8;
        let (offset, size) = (read(certificates, 4)?, read(certificates + 4, 4)?);
        if offset != 0 && size != 0 {
            end = end.max(offset + size);
            source = "PE headers, section table and certificate table";
        }
    }
    Some(candidate.extent(end, source))
}

fn macho_arch(cputype: u64) -> String {
    let arch = match cputype {
        7 => Arch::X86,
        0x0100_0007 => Arch::X86_64,
        12 => Arch::Arm,
        0x0100_000c => Arch::Aarch64,
        0x0200_000c => return "arm64_32".to_owned(),
        18 => Arch::PowerPc,
        0x0100_0012 => Arch::PowerPc64,
        _ => return format!("mach-o cpu {cputype:#x}"),
    };
    arch.to_string()
}

fn macho_magic(bytes: &[u8]) -> Option<(u8, bool)> {
    match read_uint(bytes, 0, 4, true)? {
        0xfeed_face => Some((32, true)),
        0xcefa_edfe => Some((32, false)),
        0xfeed_facf => Some((64, true)),
        0xcffa_edfe => Some((64, false)),
        _ => None,
    }
}

fn macho(bytes: &[u8]) -> Option<Candidate> {
    let (bits, big) = macho_magic(bytes)?;
    let read = |at: u64, width: usize| read_uint(bytes, usize::try_from(at).ok()?, width, big);
    let header_size = if bits == 64 { 32 } else { 28 };
    let header = || Some([read(4, 4)?, read(12, 4)?, read(16, 4)?, read(20, 4)?]);
    let Some([cputype, filetype, commands, commands_size]) = header() else {
        return Some(Candidate::magic_only(Kind::MachO, "Mach-O header is truncated"));
    };
    if !(1..=12).contains(&filetype) || commands == 0 {
        return Some(Candidate::magic_only(Kind::MachO, "Mach-O header fields are inconsistent"));
    }
    let commands_end = header_size + commands_size;
    if commands_end > bytes.len() as u64 {
        return Some(Candidate::magic_only(Kind::MachO, "Mach-O load commands lie outside the file"));
    }
    let mut end = commands_end;
    let mut at = header_size;
    for _ in 0..commands.min(MAX_TABLE_ENTRIES as u64) {
        let Some((command, size)) = read(at, 4).zip(read(at + 4, 4)) else {
            return Some(Candidate::magic_only(Kind::MachO, "Mach-O load commands are truncated"));
        };
        if size < 8 || !size.is_multiple_of(4) || at + size > commands_end {
            return Some(Candidate::magic_only(Kind::MachO, "Mach-O load command sizes are inconsistent"));
        }
        let fields = match command {
            0x1 => Some((32, 36, 4)),
            0x19 => Some((40, 48, 8)),
            0x2 => Some((16, 20, 4)),
            0x1d => Some((8, 12, 4)),
            _ => None,
        };
        if let Some((offset_at, size_at, width)) = fields {
            let Some((offset, size)) = read(at + offset_at, width).zip(read(at + size_at, width)) else {
                return Some(Candidate::magic_only(Kind::MachO, "Mach-O load commands are truncated"));
            };
            let Some(range_end) = end_of(offset, size) else {
                return Some(Candidate::magic_only(Kind::MachO, "a Mach-O segment or table ends past 2^64"));
            };
            end = end.max(range_end);
        }
        at += size;
    }
    let mut candidate = Candidate::new(Kind::MachO).endian(big);
    candidate.bits = Some(bits);
    candidate.arch = Some(macho_arch(cputype));
    candidate.notes.extend(table_note("load commands", commands));
    Some(candidate.extent(end, "Mach-O segments, symbol table and code signature"))
}

fn fat(bytes: &[u8]) -> Option<Candidate> {
    let entry_size = match read_uint(bytes, 0, 4, true)? {
        0xcafe_babe => 20,
        0xcafe_babf => 32,
        _ => return None,
    };
    // Java class files share the 0xcafebabe magic, so a fat header must prove itself through its slices.
    let count = read_uint(bytes, 4, 4, true)?;
    if count == 0 || count > MAX_FAT_SLICES {
        return None;
    }
    let read = |at: usize, width: usize| read_uint(bytes, at, width, true);
    let mut candidate = Candidate::new(Kind::MachOFat).endian(true);
    let mut end = 8 + count * entry_size;
    let mut past_end = false;
    for index in 0..count as usize {
        let entry = 8 + index * entry_size as usize;
        let (cputype, offset, size, align) = if entry_size == 20 {
            (read(entry, 4)?, read(entry + 8, 4)?, read(entry + 12, 4)?, read(entry + 16, 4)?)
        } else {
            (read(entry, 4)?, read(entry + 8, 8)?, read(entry + 16, 8)?, read(entry + 24, 4)?)
        };
        if align > 20 || offset < 8 + count * entry_size || !offset.is_multiple_of(1 << align) || size == 0 {
            return None;
        }
        let slice_end = end_of(offset, size)?;
        match usize::try_from(offset).ok().and_then(|offset| bytes.get(offset..)).filter(|slice| slice.len() >= 4) {
            Some(slice) => _ = macho_magic(slice)?,
            None => past_end = true,
        }
        end = end.max(slice_end);
        candidate.slices.push(FatSlice { arch: macho_arch(cputype), offset, size });
    }
    if past_end {
        return Some(Candidate::magic_only(Kind::MachOFat, "universal Mach-O slices lie outside the file"));
    }
    candidate.notes.push(format!("{count} architecture slices"));
    Some(candidate.extent(end, "universal Mach-O slice table"))
}

const ZIP_METHODS: [u64; 13] = [0, 1, 6, 8, 9, 12, 14, 19, 93, 95, 96, 97, 98];
/// The most records (local and central directory headers) one zip walk reads.
const MAX_ZIP_RECORDS: usize = 2 * MAX_TABLE_ENTRIES;

/// A zip archive at its first local file header, and how many bytes from it the scan takes as the archive's own:
/// through its end when that is known, else through the last record header read whole.
fn zip(bytes: &[u8]) -> Option<(Candidate, usize)> {
    if !bytes.starts_with(b"PK\x03\x04") {
        return None;
    }
    let read = |at: usize, width: usize| read_uint(bytes, at, width, false);
    let header = || Some([read(4, 2)?, read(8, 2)?, read(26, 2)?]);
    let Some([version, method, name_len]) = header() else {
        return Some((Candidate::magic_only(Kind::Zip, "zip local header is truncated"), 4));
    };
    if version & 0xff > 63 || !ZIP_METHODS.contains(&method) || name_len == 0 || bytes.len() < 30 + name_len as usize {
        return Some((Candidate::magic_only(Kind::Zip, "zip local header fields are inconsistent"), 4));
    }
    let mut candidate = Candidate::new(Kind::Zip).endian(false);
    let past_end = "the archive runs past the end of the file";
    // `covered` ends the last record header read whole: a declared member size is not trusted past it.
    let (mut at, mut covered, mut members) = (0usize, 4usize, 0u64);
    let walk = 'walk: {
        for _ in 0..MAX_ZIP_RECORDS {
            let Some(signature) = read(at, 4) else { break 'walk Walk::Stopped(past_end) };
            let (header_end, data) = match signature {
                0x0403_4b50 => {
                    let fields =
                        (|| Some([read(at + 6, 2)?, read(at + 18, 4)?, read(at + 26, 2)?, read(at + 28, 2)?]))();
                    let Some([flags, compressed, name, extra]) = fields else { break 'walk Walk::Stopped(past_end) };
                    if flags & 8 != 0 || compressed == 0xffff_ffff {
                        break 'walk Walk::Stopped(
                            "a member's size is recorded after its data (data descriptor or zip64)",
                        );
                    }
                    (at + 30 + (name + extra) as usize, compressed as usize)
                }
                0x0201_4b50 => {
                    let fields = (|| Some([read(at + 28, 2)?, read(at + 30, 2)?, read(at + 32, 2)?]))();
                    let Some([name, extra, comment]) = fields else { break 'walk Walk::Stopped(past_end) };
                    (at + 46 + (name + extra + comment) as usize, 0)
                }
                0x0605_4b50 => {
                    let Some(comment) = read(at + 20, 2) else { break 'walk Walk::Stopped(past_end) };
                    let end = at + 22 + comment as usize;
                    candidate = candidate.extent(end as u64, "zip member headers and end of central directory");
                    covered = end.min(bytes.len());
                    break 'walk Walk::Ended;
                }
                _ => break 'walk Walk::Stopped("an unrecognized record follows the members"),
            };
            if header_end > bytes.len() {
                break 'walk Walk::Stopped(past_end);
            }
            members += u64::from(signature == 0x0403_4b50);
            covered = header_end;
            at = header_end.saturating_add(data);
        }
        Walk::Capped
    };
    match walk {
        Walk::Ended => {}
        Walk::Stopped(reason) => candidate.notes.push(format!("no extent: {reason}")),
        Walk::Capped => match zip_end(bytes, at.min(bytes.len())) {
            Some(end) => {
                candidate = candidate.extent(end as u64, "end of central directory found past the member walk's cap");
                candidate.notes.push(format!("the member walk stopped at its cap ({MAX_ZIP_RECORDS} records)"));
                covered = end.min(bytes.len());
            }
            None => {
                candidate.notes.push(format!(
                    "no extent: the member walk stopped at its cap ({MAX_ZIP_RECORDS} records) and no end of central \
                     directory follows; zip headers in the rest of the file are taken as its members"
                ));
                covered = bytes.len();
            }
        },
    }
    candidate.notes.push(format!("{members} members walked"));
    Some((candidate, covered))
}

/// The end of the first end-of-central-directory record from `from` on whose central directory ends right
/// before it, with offsets relative to the archive at the start of `bytes`.
fn zip_end(bytes: &[u8], mut from: usize) -> Option<usize> {
    while let Some(found) = bytes.get(from..)?.windows(4).position(|window| window == b"PK\x05\x06") {
        let record = from + found;
        let read = |at: usize, width: usize| read_uint(bytes, record + at, width, false);
        if let (Some(size), Some(start), Some(comment)) = (read(12, 4), read(16, 4), read(20, 2))
            && size + start == record as u64
        {
            return Some(record + 22 + comment as usize);
        }
        from = record + 1;
    }
    None
}

/// How an archive's member walk ended.
enum Walk {
    /// At the archive's terminating record, which gave the extent.
    Ended,
    Stopped(&'static str),
    Capped,
}

/// The longest zero-terminated gzip header field (original name, comment) read, terminator included: a file name
/// fits in it on common file systems, and a header with a longer field is not reported.
const MAX_GZIP_FIELD: usize = 256;

/// The bytes left for searching gzip header fields (`Limits::max_probe_bytes`) or for walking archive and image
/// headers (`Limits::max_walk_bytes`), so that a file of repeated plausible headers costs no more than that in all.
struct Probe {
    left: u64,
    exhausted: bool,
}

impl Probe {
    /// Charges `bytes` about to be read, or marks the budget exhausted and refuses when fewer are left.
    fn charge(&mut self, bytes: u64) -> bool {
        if bytes > self.left {
            self.exhausted = true;
            return false;
        }
        self.left -= bytes;
        true
    }

    /// Where the first NUL in `field`'s first `MAX_GZIP_FIELD` bytes is, charging the bytes examined.
    fn nul(&mut self, field: &[u8]) -> Option<usize> {
        let allowed = usize::try_from(self.left).unwrap_or(usize::MAX).min(MAX_GZIP_FIELD);
        let window = &field[..field.len().min(allowed)];
        let end = window.iter().position(|&byte| byte == 0);
        self.left -= end.map_or(window.len(), |end| end + 1) as u64;
        if end.is_none() && window.len() < field.len().min(MAX_GZIP_FIELD) {
            self.exhausted = true;
        }
        end
    }
}

fn gzip(bytes: &[u8], probe: &mut Probe) -> Option<Candidate> {
    // Three magic bytes are too common to report alone: the reserved flag bits, the extra-flags and OS bytes and
    // the first deflate block header must also check out, or nothing is reported.
    if !bytes.starts_with(&[0x1f, 0x8b, 0x08]) {
        return None;
    }
    let flags = *bytes.get(3)?;
    if flags & 0xe0 != 0 || !matches!(bytes.get(8)?, 0 | 2 | 4) || !matches!(bytes.get(9)?, 0..=13 | 255) {
        return None;
    }
    let mut candidate = Candidate::new(Kind::Gzip);
    let mut at = 10;
    if flags & 0x04 != 0 {
        at += 2 + read_uint(bytes, at, 2, false)? as usize;
    }
    for (flag, what) in [(0x08, "original name"), (0x10, "comment")] {
        if flags & flag != 0 {
            let field = bytes.get(at..)?;
            let end = probe.nul(field)?;
            if flag == 0x08 {
                candidate.notes.push(format!("{what} {:?}", String::from_utf8_lossy(&field[..end])));
            }
            at += end + 1;
        }
    }
    if flags & 0x02 != 0 {
        at += 2;
    }
    let block = *bytes.get(at)?;
    match (block >> 1) & 3 {
        // A stored block's length is followed by its ones' complement.
        0 if read_uint(bytes, at + 1, 2, false)? != !read_uint(bytes, at + 3, 2, false)? & 0xffff => None,
        3 => None,
        _ => Some(candidate),
    }
}

/// Slicing-by-8 tables for the reflected CRC-32 (polynomial 0xedb88320): whole-image checksums (TRX, CramFS)
/// run over many megabytes.
const CRC_TABLES: [[u32; 256]; 8] = {
    let mut tables = [[0u32; 256]; 8];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
            bit += 1;
        }
        tables[0][index] = crc;
        index += 1;
    }
    let mut index = 0;
    while index < 256 {
        let mut slice = 1;
        while slice < 8 {
            let previous = tables[slice - 1][index];
            tables[slice][index] = (previous >> 8) ^ tables[0][(previous & 0xff) as usize];
            slice += 1;
        }
        index += 1;
    }
    tables
};

/// The CRC-32 register after `bytes`, from `state`, with no inversion before or after: the standard CRC-32 is
/// `!crc32_update(!0, bytes)`; UBI and TRX keep the register as is, and JFFS2 starts it at 0.
fn crc32_update(mut state: u32, bytes: &[u8]) -> u32 {
    let (chunks, remainder) = bytes.as_chunks::<8>();
    for chunk in chunks {
        let low = state ^ u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let t = &CRC_TABLES;
        state = t[7][(low & 0xff) as usize]
            ^ t[6][((low >> 8) & 0xff) as usize]
            ^ t[5][((low >> 16) & 0xff) as usize]
            ^ t[4][(low >> 24) as usize]
            ^ t[3][usize::from(chunk[4])]
            ^ t[2][usize::from(chunk[5])]
            ^ t[1][usize::from(chunk[6])]
            ^ t[0][usize::from(chunk[7])];
    }
    for &byte in remainder {
        state = CRC_TABLES[0][((state ^ u32::from(byte)) & 0xff) as usize] ^ (state >> 8);
    }
    state
}

fn crc32(bytes: &[u8]) -> u32 {
    !crc32_update(!0, bytes)
}

fn xz(bytes: &[u8]) -> Option<Candidate> {
    if !bytes.starts_with(b"\xfd7zXZ\0") {
        return None;
    }
    let (Some(flags), Some(stored)) = (bytes.get(6..8), read_uint(bytes, 8, 4, false)) else {
        return Some(Candidate::magic_only(Kind::Xz, "xz stream header is truncated"));
    };
    if flags[0] != 0 || flags[1] & 0xf0 != 0 || u64::from(crc32(flags)) != stored {
        return Some(Candidate::magic_only(Kind::Xz, "xz stream flags or their CRC32 do not check out"));
    }
    Some(Candidate::new(Kind::Xz))
}

fn zstd(bytes: &[u8]) -> Option<Candidate> {
    if !bytes.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return None;
    }
    let Some(&descriptor) = bytes.get(4) else {
        return Some(Candidate::magic_only(Kind::Zstd, "zstd frame header is truncated"));
    };
    if descriptor & 0x08 != 0 {
        return Some(Candidate::magic_only(Kind::Zstd, "zstd frame header's reserved bit is set"));
    }
    let single_segment = descriptor & 0x20 != 0;
    let at = 5 + usize::from(!single_segment) + [0, 1, 2, 4][usize::from(descriptor & 3)];
    let width = match descriptor >> 6 {
        0 => usize::from(single_segment),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let mut candidate = Candidate::new(Kind::Zstd);
    let size = if width == 0 { Some(0) } else { read_uint(bytes, at, width, false) };
    let (Some(size), Some(block)) = (size, read_uint(bytes, at + width, 3, false)) else {
        return Some(Candidate::magic_only(Kind::Zstd, "zstd frame header is truncated"));
    };
    // The first block header: its type must not be the reserved one, and no block exceeds 128 KiB.
    if (block >> 1) & 3 == 3 || block >> 3 > 128 << 10 {
        return Some(Candidate::magic_only(Kind::Zstd, "zstd first block header is invalid"));
    }
    if width > 0 {
        candidate.uncompressed_size = Some(if width == 2 { size + 256 } else { size });
    }
    Some(candidate)
}

fn lzma(bytes: &[u8]) -> Option<Candidate> {
    // LZMA-alone has no magic: only the common properties byte, a power-of-two dictionary between 64 KiB and
    // 1 GiB, a plausible size and the range coder's leading zero byte are checked.
    let dictionary = read_uint(bytes, 1, 4, false)?;
    let size = read_uint(bytes, 5, 8, false)?;
    if bytes[0] != 0x5d
        || !dictionary.is_power_of_two()
        || !(1 << 16..=1 << 30).contains(&dictionary)
        || (size != u64::MAX && size > 1 << 40)
        || *bytes.get(13)? != 0
    {
        return None;
    }
    let mut candidate = Candidate::magic_only(Kind::Lzma, "LZMA-alone has no magic; its header is only plausible");
    candidate.uncompressed_size = (size != u64::MAX).then_some(size);
    Some(candidate)
}

fn squashfs(bytes: &[u8]) -> Option<Candidate> {
    let big = match bytes.get(..4)? {
        b"hsqs" => false,
        b"sqsh" => true,
        _ => return None,
    };
    let read = |at: usize, width: usize| read_uint(bytes, at, width, big);
    let header = || Some([read(12, 4)?, read(20, 2)?, read(22, 2)?, read(28, 2)?, read(40, 8)?]);
    let Some([block_size, compression, block_log, major, used]) = header() else {
        return Some(Candidate::magic_only(Kind::Squashfs, "squashfs superblock is truncated"));
    };
    // Compression id 0 is no compressor: the kernel does not mount such an image, but backhand writes and reads it.
    if major != 4 || compression > 6 || !(12..=20).contains(&block_log) || block_size != 1 << block_log || used < 96 {
        // "hsqs" and "sqsh" occur in ordinary text; only a consistent superblock is worth reporting.
        return None;
    }
    // The tables follow the inode table in a fixed order and lie within bytes_used; absent ones are all ones. A
    // superblock forged to claim the rest of the file rarely gets these right.
    let tables = || Some([read(64, 8)?, read(72, 8)?, read(48, 8)?, read(56, 8)?, read(80, 8)?, read(88, 8)?]);
    let Some([inodes, directories, optional @ ..]) = tables() else {
        return Some(Candidate::magic_only(Kind::Squashfs, "squashfs superblock is truncated"));
    };
    let ids = optional[0];
    if inodes < 96
        || directories <= inodes
        || !(directories..used).contains(&ids)
        || optional[1..].iter().any(|&table| table != u64::MAX && !(directories..used).contains(&table))
    {
        return Some(Candidate::magic_only(Kind::Squashfs, "squashfs table offsets are inconsistent"));
    }
    let mut candidate = Candidate::new(Kind::Squashfs).endian(big);
    let compressor = ["no", "gzip", "lzma", "lzo", "xz", "lz4", "zstd"][compression as usize];
    candidate.notes.push(format!("{compressor} compression, {block_size}-byte blocks"));
    candidate.declared_size = Some(used);
    Some(candidate.extent(used, "squashfs superblock bytes_used"))
}

/// A cpio (newc) archive at its first header, and how many bytes from it the scan takes as the archive's own:
/// through its end when that is known, else through the last member header read whole.
fn cpio(bytes: &[u8]) -> Option<(Candidate, usize)> {
    if !(bytes.starts_with(b"070701") || bytes.starts_with(b"070702")) {
        return None;
    }
    let field = |at: usize, index: usize| -> Option<u64> {
        let text = bytes.get(at + 6 + index * 8..at + 14 + index * 8)?;
        if !text.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        u64::from_str_radix(std::str::from_utf8(text).ok()?, 16).ok()
    };
    let header = |at: usize| -> Option<(u64, &[u8])> {
        for index in 0..13 {
            field(at, index)?;
        }
        let name_size = field(at, 11)? as usize;
        let name = bytes.get(at + 110..at + 110 + name_size)?;
        Some((field(at, 6)?, name.strip_suffix(b"\0")?))
    };
    // Six ASCII digits alone are too common to report.
    header(0)?;
    let align = |at: usize| at.checked_add(3).map(|at| at & !3);
    // A member at `at`: its name, where its data starts and where the next member starts.
    let member = |at: usize| -> Option<(&[u8], usize, usize)> {
        let magic = bytes.get(at..at + 6)?;
        let (size, name) = header(at).filter(|_| magic == b"070701" || magic == b"070702")?;
        let data = align(at + 110 + name.len() + 1)?;
        Some((name, data, align(data.checked_add(usize::try_from(size).ok()?)?)?))
    };
    let mut candidate = Candidate::new(Kind::Cpio);
    // `covered` ends the last member header read whole: a declared member size is not trusted past it.
    let (mut at, mut covered, mut members) = (0usize, 6usize, 0u64);
    let walk = 'walk: {
        for _ in 0..MAX_TABLE_ENTRIES {
            let Some((name, data, next)) = member(at) else {
                break 'walk Walk::Stopped("a member header is missing or malformed");
            };
            covered = data.min(bytes.len());
            if name == b"TRAILER!!!" {
                candidate = candidate.extent(next as u64, "cpio member headers through TRAILER!!!");
                covered = next.min(bytes.len());
                break 'walk Walk::Ended;
            }
            members += 1;
            at = next;
        }
        Walk::Capped
    };
    match walk {
        Walk::Ended => {}
        Walk::Stopped(reason) => candidate.notes.push(format!("no extent: {reason}")),
        Walk::Capped => {
            // The trailer is the first member named TRAILER!!! after the cap, found by its name.
            let mut from = at.min(bytes.len());
            let trailer = loop {
                let Some(found) = bytes[from..].windows(11).position(|window| window == b"TRAILER!!!\0") else {
                    break None;
                };
                let name_at = from + found;
                if let Some((b"TRAILER!!!", _, next)) = name_at.checked_sub(110).and_then(member) {
                    break Some(next);
                }
                from = name_at + 1;
            };
            match trailer {
                Some(end) => {
                    candidate = candidate.extent(end as u64, "TRAILER!!! header found past the member walk's cap");
                    candidate.notes.push(format!("the member walk stopped at its cap ({MAX_TABLE_ENTRIES} members)"));
                    covered = end.min(bytes.len());
                }
                None => {
                    candidate.notes.push(format!(
                        "no extent: the member walk stopped at its cap ({MAX_TABLE_ENTRIES} members) and no \
                         TRAILER!!! header follows; cpio headers in the rest of the file are taken as its members"
                    ));
                    covered = bytes.len();
                }
            }
        }
    }
    candidate.notes.push(format!("{members} members walked"));
    Some((candidate, covered))
}

fn uimage(bytes: &[u8]) -> Option<Candidate> {
    if read_uint(bytes, 0, 4, true)? != 0x2705_1956 {
        return None;
    }
    let Some(header) = bytes.get(..64) else {
        return Some(Candidate::magic_only(Kind::UImage, "uImage header is truncated"));
    };
    let mut zeroed = [0u8; 64];
    zeroed.copy_from_slice(header);
    zeroed[4..8].fill(0);
    if u64::from(crc32(&zeroed)) != read_uint(header, 4, 4, true)? {
        return Some(Candidate::magic_only(Kind::UImage, "uImage header CRC32 does not match"));
    }
    let size = 64 + read_uint(header, 12, 4, true)?;
    let mut candidate = Candidate::new(Kind::UImage).endian(true);
    candidate.arch = Some(match header[29] {
        2 => Arch::Arm.to_string(),
        3 => Arch::X86.to_string(),
        5 => Arch::Mips.to_string(),
        6 => Arch::Mips64.to_string(),
        7 => Arch::PowerPc.to_string(),
        10 => Arch::Sparc.to_string(),
        11 => Arch::Sparc64.to_string(),
        12 => Arch::M68k.to_string(),
        22 => Arch::Aarch64.to_string(),
        24 => Arch::X86_64.to_string(),
        other => format!("uimage arch {other}"),
    });
    let name = &header[32..64];
    let name = &name[..name.iter().position(|&byte| byte == 0).unwrap_or(name.len())];
    candidate.notes.push(format!("image name {:?}, compression type {}", String::from_utf8_lossy(name), header[31]));
    candidate.declared_size = Some(size);
    Some(candidate.extent(size, "uImage header data size"))
}

fn android_boot(bytes: &[u8]) -> Option<Candidate> {
    if !bytes.starts_with(b"ANDROID!") {
        return None;
    }
    let read = |at: usize| read_uint(bytes, at, 4, false);
    let Some(version) = read(40) else {
        return Some(Candidate::magic_only(Kind::AndroidBoot, "Android boot image header is truncated"));
    };
    let parts = || -> Option<(u64, Vec<u64>)> {
        match version {
            0..=2 => {
                let mut parts = vec![read(8)?, read(16)?, read(24)?];
                if version >= 1 {
                    parts.push(read(1632)?);
                }
                if version == 2 {
                    parts.push(read(1648)?);
                }
                Some((read(36)?, parts))
            }
            3 => Some((4096, vec![read(8)?, read(12)?])),
            4 => Some((4096, vec![read(8)?, read(12)?, read(1580)?])),
            _ => None,
        }
    };
    let Some((page, parts)) = parts() else {
        return Some(Candidate::magic_only(Kind::AndroidBoot, "Android boot image header is truncated or unknown"));
    };
    if !page.is_power_of_two() || !(2048..=65536).contains(&page) {
        return Some(Candidate::magic_only(Kind::AndroidBoot, "Android boot image page size is implausible"));
    }
    let pages = parts.iter().map(|size| size.div_ceil(page)).sum::<u64>() + 1;
    let mut candidate = Candidate::new(Kind::AndroidBoot).endian(false);
    candidate.notes.push(format!("header version {version}, page size {page}"));
    candidate.declared_size = Some(pages * page);
    Some(candidate.extent(pages * page, "Android boot image header part sizes"))
}

/// Where an ext superblock starts, from the file system's start.
const EXT_SUPERBLOCK: usize = 0x400;
/// Where the ext superblock magic lies, from the file system's start.
const EXT_MAGIC_AT: usize = EXT_SUPERBLOCK + 56;
const EXT_MAGIC: [u8; 2] = [0x53, 0xef];
/// Where the ustar magic lies in a tar header.
const TAR_MAGIC_AT: usize = 257;
const TAR_MAGIC: &[u8; 5] = b"ustar";

/// An ext2/3/4 file system, found by the superblock magic at 0x438. The checks follow binwalk's ext signature (MIT):
/// the state and error-policy words beside the magic, creator OS, revision and block size; the group geometry must
/// also agree with the block and inode counts.
fn ext(bytes: &[u8]) -> Option<Candidate> {
    if bytes.get(EXT_MAGIC_AT..EXT_MAGIC_AT + 2)? != EXT_MAGIC {
        return None;
    }
    let read = |at: usize, width: usize| read_uint(bytes, EXT_SUPERBLOCK + at, width, false);
    let (state, errors) = (read(58, 2)?, read(60, 2)?);
    // Two magic bytes are too common to report alone: the words beside them must also check out.
    if state & !7 != 0 || !(1..=3).contains(&errors) {
        return None;
    }
    let fields = || {
        Some([
            read(0, 4)?,
            read(4, 4)?,
            read(12, 4)?,
            read(16, 4)?,
            read(20, 4)?,
            read(24, 4)?,
            read(32, 4)?,
            read(40, 4)?,
            read(72, 4)?,
            read(76, 4)?,
        ])
    };
    let Some(
        [
            inodes,
            blocks_lo,
            free_blocks,
            free_inodes,
            first_block,
            log_block,
            per_group,
            inodes_per_group,
            os,
            revision,
        ],
    ) = fields()
    else {
        return Some(Candidate::magic_only(Kind::Ext, "ext superblock is truncated"));
    };
    let inconsistent = || Some(Candidate::magic_only(Kind::Ext, "ext superblock fields are inconsistent"));
    // Block sizes run from 1 KiB to 64 KiB; only a 1 KiB-block file system starts its first group at block 1.
    if os > 4 || revision > 1 || log_block > 6 || first_block != u64::from(log_block == 0) {
        return inconsistent();
    }
    let block_size = 1024u64 << log_block;
    let features = if revision >= 1 { (read(92, 4), read(96, 4)) } else { (Some(0), Some(0)) };
    let (Some(compat), Some(incompat)) = features else {
        return Some(Candidate::magic_only(Kind::Ext, "ext superblock is truncated"));
    };
    // The 64bit feature keeps the block count's high word at 0x150.
    let blocks = match incompat & 0x80 {
        0 => blocks_lo,
        _ => blocks_lo | read(0x150, 4).unwrap_or(0) << 32,
    };
    if blocks <= first_block
        || per_group == 0
        || per_group > 8 * block_size
        || inodes_per_group == 0
        || free_blocks > blocks
        || free_inodes > inodes
    {
        return inconsistent();
    }
    // Every group has the same number of inodes.
    let groups = (blocks - first_block).div_ceil(per_group);
    if groups.checked_mul(inodes_per_group) != Some(inodes) {
        return inconsistent();
    }
    // extents, 64bit or flex_bg make it ext4; a journal without them, ext3.
    let version = if incompat & 0x2c0 != 0 {
        "ext4"
    } else if compat & 0x4 != 0 {
        "ext3"
    } else {
        "ext2"
    };
    let mut candidate = Candidate::new(Kind::Ext).endian(false);
    let mut note = format!("{version}, {block_size}-byte blocks, {blocks} blocks, {inodes} inodes");
    if let Some(name) = bytes.get(EXT_SUPERBLOCK + 120..EXT_SUPERBLOCK + 136) {
        let name = &name[..name.iter().position(|&byte| byte == 0).unwrap_or(name.len())];
        if !name.is_empty() {
            note.push_str(&format!(", volume name {:?}", String::from_utf8_lossy(name)));
        }
    }
    candidate.notes.push(note);
    let Some(size) = blocks.checked_mul(block_size) else {
        candidate.notes.push("no extent: the block count times the block size exceeds 2^64".to_owned());
        return Some(candidate);
    };
    candidate.declared_size = Some(size);
    Some(candidate.extent(size, "ext superblock block count and size"))
}

const SPARSE_RAW: u64 = 0xcac1;
const SPARSE_FILL: u64 = 0xcac2;
const SPARSE_DONT_CARE: u64 = 0xcac3;
const SPARSE_CRC32: u64 = 0xcac4;

/// An Android sparse image, its extent from walking its chunk headers. The header checks follow binwalk's
/// androidsparse signature (MIT).
fn android_sparse(bytes: &[u8], walk: &mut Probe) -> Option<Candidate> {
    if read_uint(bytes, 0, 4, false)? != 0xed26_ff3a {
        return None;
    }
    let read = |at: u64, width: usize| read_uint(bytes, usize::try_from(at).ok()?, width, false);
    let header =
        || Some([read(4, 2)?, read(6, 2)?, read(8, 2)?, read(10, 2)?, read(12, 4)?, read(16, 4)?, read(20, 4)?]);
    // The header ends with an image checksum at 24, not read but part of the 28-byte header.
    let header = || header().filter(|_| bytes.len() >= 28);
    let Some([major, minor, header_size, chunk_header_size, block_size, blocks, chunks]) = header() else {
        return Some(Candidate::magic_only(Kind::AndroidSparse, "Android sparse header is truncated"));
    };
    if major != 1
        || minor != 0
        || header_size < 28
        || chunk_header_size < 12
        || block_size == 0
        || !block_size.is_multiple_of(4)
        || block_size > 64 << 20
    {
        return Some(Candidate::magic_only(Kind::AndroidSparse, "Android sparse header fields are inconsistent"));
    }
    let mut candidate = Candidate::new(Kind::AndroidSparse).endian(false);
    candidate.uncompressed_size = Some(blocks * block_size);
    candidate.notes.push(format!("{chunks} chunks of {block_size}-byte blocks"));
    let (mut at, mut covered) = (header_size, 0u64);
    let stopped = 'walk: {
        for _ in 0..chunks {
            if !walk.charge(chunk_header_size) {
                break 'walk Some("the scan's header walk budget ran out");
            }
            let fields = (|| Some([read(at, 2)?, read(at + 2, 2)?, read(at + 4, 4)?, read(at + 8, 4)?]))();
            let Some([kind, reserved, chunk_blocks, total]) = fields else {
                break 'walk Some("a chunk header lies past the end of the file");
            };
            let expected = match kind {
                SPARSE_RAW => chunk_blocks * block_size,
                SPARSE_FILL | SPARSE_CRC32 => 4,
                SPARSE_DONT_CARE => 0,
                _ => break 'walk Some("a chunk header has an unknown type"),
            };
            if reserved != 0 || total.checked_sub(chunk_header_size) != Some(expected) {
                break 'walk Some("a chunk's size does not match its type");
            }
            if kind != SPARSE_CRC32 {
                covered += chunk_blocks;
            }
            at += total;
        }
        None
    };
    match stopped {
        Some(reason) => candidate.notes.push(format!("no extent: {reason}")),
        // A forged header must not claim the rest of the file: the chunks must cover what the header declares.
        None if chunks == 0 || covered != blocks => candidate
            .notes
            .push(format!("no extent: the {chunks} chunks cover {covered} blocks, the header declares {blocks}")),
        None => candidate = candidate.extent(at, "Android sparse header and chunk headers"),
    }
    Some(candidate)
}

/// The longest run of tar headers one walk reads.
const MAX_TAR_HEADERS: usize = 1 << 16;

/// A tar numeric field: octal digits between optional spaces and NULs, or GNU base-256 (high bit of the first byte
/// set).
fn tar_number(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return field.iter().enumerate().try_fold(0u64, |value, (index, &byte)| {
            value.checked_mul(256)?.checked_add(u64::from(if index == 0 { byte & 0x7f } else { byte }))
        });
    }
    let text = field.trim_ascii_start();
    let digits = &text[..text.iter().position(|&byte| byte == 0 || byte == b' ').unwrap_or(text.len())];
    if digits.is_empty() || !text[digits.len()..].iter().all(|&byte| byte == 0 || byte == b' ') {
        return None;
    }
    digits.iter().try_fold(0u64, |value, &digit| match digit {
        b'0'..=b'7' => value.checked_mul(8)?.checked_add(u64::from(digit - b'0')),
        _ => None,
    })
}

/// The data size the ustar header at `at` records, if its magic and checksum check out.
fn tar_header(bytes: &[u8], at: usize) -> Option<u64> {
    let header = bytes.get(at..at.checked_add(512)?)?;
    if &header[TAR_MAGIC_AT..TAR_MAGIC_AT + 5] != TAR_MAGIC {
        return None;
    }
    let sum: u64 = header
        .iter()
        .enumerate()
        .map(|(index, &byte)| if (148..156).contains(&index) { 32 } else { u64::from(byte) })
        .sum();
    if tar_number(&header[148..156])? != sum {
        return None;
    }
    tar_number(&header[124..136])
}

/// A tar archive at its first header, and how many bytes from it the scan takes as the archive's own: through its
/// end when that is known, else through the last header read whole. The checks follow binwalk's tarball signature
/// (MIT): the ustar magic and header checksum, entries walked by their recorded sizes.
fn tar(bytes: &[u8], walk: &mut Probe) -> Option<(Candidate, usize)> {
    // The first header's checksum is charged too: a file of repeated "ustar" costs no more than the budget.
    if bytes.get(TAR_MAGIC_AT..TAR_MAGIC_AT + 5)? != TAR_MAGIC || !walk.charge(512) {
        return None;
    }
    let first = tar_header(bytes, 0)?;
    let mut candidate = Candidate::new(Kind::Tar);
    let first_end = first.checked_next_multiple_of(512).and_then(|size| usize::try_from(size).ok());
    let (mut at, mut covered, mut members) = (first_end.map_or(usize::MAX, |data| data.saturating_add(512)), 512, 1u64);
    let stopped = 'walk: {
        if first_end.is_none() {
            break 'walk Some("a member's size is out of range".to_owned());
        }
        for _ in 1..MAX_TAR_HEADERS {
            let Some(block) = bytes.get(at..at.saturating_add(512)) else {
                break 'walk Some("the archive runs past the end of the file".to_owned());
            };
            // The archive ends with two zero blocks; some writers leave out the second.
            if block.iter().all(|&byte| byte == 0) {
                let next = bytes.get(at + 512..at + 1024);
                let end = at + if next.is_some_and(|next| next.iter().all(|&byte| byte == 0)) { 1024 } else { 512 };
                candidate = candidate.extent(end as u64, "tar headers through the end-of-archive blocks");
                covered = end;
                break 'walk None;
            }
            if !walk.charge(512) {
                break 'walk Some("the scan's header walk budget ran out".to_owned());
            }
            let Some(size) = tar_header(bytes, at) else {
                break 'walk Some(
                    "a block after the members is neither a tar header nor the end of the archive".to_owned(),
                );
            };
            members += 1;
            covered = at + 512;
            let Some(data) = size.checked_next_multiple_of(512).and_then(|size| usize::try_from(size).ok()) else {
                break 'walk Some("a member's size is out of range".to_owned());
            };
            at = covered.saturating_add(data);
        }
        Some(format!(
            "the header walk stopped at its cap ({MAX_TAR_HEADERS} headers); tar headers up to the last one read \
             are taken as its members"
        ))
    };
    if let Some(reason) = stopped {
        candidate.notes.push(format!("no extent: {reason}"));
    }
    candidate.notes.push(format!("{members} members walked"));
    Some((candidate, covered))
}

/// A bzip2 stream: the "BZh" magic and block size, then the first block's magic (the BCD digits of pi), as
/// binwalk's bzip2 signature has them (MIT), and the block's origin pointer within the block size. Nothing gives
/// an extent without decompressing.
fn bzip2(bytes: &[u8]) -> Option<Candidate> {
    if !bytes.starts_with(b"BZh") || !(b'1'..=b'9').contains(bytes.get(3)?) {
        return None;
    }
    if bytes.get(4..10)? != [0x31, 0x41, 0x59, 0x26, 0x53, 0x59] {
        return None;
    }
    let level = u64::from(bytes[3] - b'0');
    let Some(word) = read_uint(bytes, 14, 4, true) else {
        return Some(Candidate::magic_only(Kind::Bzip2, "bzip2 block header is truncated"));
    };
    // After the block CRC come one randomised bit and the 24-bit origin pointer.
    if (word >> 7) & 0xff_ffff >= level * 100_000 {
        return Some(Candidate::magic_only(Kind::Bzip2, "bzip2 block origin pointer exceeds the block size"));
    }
    let mut candidate = Candidate::new(Kind::Bzip2);
    candidate.notes.push(format!("{level}00k blocks"));
    Some(candidate)
}

/// The most partition names an OTA payload candidate lists.
const MAX_OTA_NAMES: usize = 16;

/// A protobuf field's value: a varint (fixed-width values read as 0), or length-delimited bytes.
enum Proto<'a> {
    Int(u64),
    Bytes(&'a [u8]),
}

/// The fields of the protobuf message `bytes`, as (field number, value); `None` for a malformed field, which
/// ends the iteration.
fn proto_fields(mut bytes: &[u8]) -> impl Iterator<Item = Option<(u64, Proto<'_>)>> {
    fn varint(bytes: &mut &[u8]) -> Option<u64> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let (&byte, rest) = bytes.split_first()?;
            *bytes = rest;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }
    let mut failed = false;
    std::iter::from_fn(move || {
        if bytes.is_empty() || failed {
            return None;
        }
        let field = (|| {
            let key = varint(&mut bytes)?;
            let value = match key & 7 {
                0 => Proto::Int(varint(&mut bytes)?),
                1 | 5 => {
                    bytes = bytes.get(if key & 7 == 1 { 8 } else { 4 }..)?;
                    Proto::Int(0)
                }
                2 => {
                    let len = usize::try_from(varint(&mut bytes)?).ok().filter(|len| *len <= bytes.len())?;
                    let (head, rest) = bytes.split_at(len);
                    bytes = rest;
                    Proto::Bytes(head)
                }
                _ => return None,
            };
            Some((key >> 3, value))
        })();
        failed = field.is_none();
        Some(field)
    })
}

/// Where an OTA install operation's data blob ends, relative to the payload's data: its fields 2 (data_offset) and
/// 3 (data_length).
fn ota_operation_end(operation: &[u8]) -> Option<u64> {
    let (mut offset, mut length) = (0u64, 0u64);
    for field in proto_fields(operation) {
        match field? {
            (2, Proto::Int(value)) => offset = value,
            (3, Proto::Int(value)) => length = value,
            _ => {}
        }
    }
    offset.checked_add(length)
}

/// An Android OTA payload (update_engine `payload.bin`), its extent from the manifest: the end of the furthest
/// operation's data blob or of the payload signature, after the header, manifest and metadata signature.
fn ota_payload(bytes: &[u8], walk: &mut Probe) -> Option<Candidate> {
    if !bytes.starts_with(b"CrAU") {
        return None;
    }
    let read = |at: usize, width: usize| read_uint(bytes, at, width, true);
    let (Some(version), Some(manifest_size)) = (read(4, 8), read(12, 8)) else {
        return Some(Candidate::magic_only(Kind::OtaPayload, "OTA payload header is truncated"));
    };
    let header_size: usize = match version {
        1 => 20,
        2 => 24,
        _ => return Some(Candidate::magic_only(Kind::OtaPayload, "OTA payload major version is neither 1 nor 2")),
    };
    let signature_size = if version == 2 { read(20, 4) } else { Some(0) };
    let Some(signature_size) = signature_size else {
        return Some(Candidate::magic_only(Kind::OtaPayload, "OTA payload header is truncated"));
    };
    let manifest =
        usize::try_from(manifest_size).ok().and_then(|size| bytes.get(header_size..header_size.checked_add(size)?));
    let Some(manifest) = manifest else {
        return Some(Candidate::magic_only(Kind::OtaPayload, "OTA payload manifest lies outside the file"));
    };
    let mut candidate = Candidate::new(Kind::OtaPayload).endian(true);
    if !walk.charge(manifest_size) {
        candidate.notes.push("no extent: the scan's header walk budget ran out".to_owned());
        return Some(candidate);
    }
    let malformed = || Some(Candidate::magic_only(Kind::OtaPayload, "OTA payload manifest is malformed"));
    let (mut block_size, mut signatures, mut blobs_end) = (4096, (None, None), 0u64);
    let (mut partitions, mut operations, mut names) = (0usize, 0usize, Vec::new());
    // Manifest fields: 1 and 2 operations (major version 1), 3 block_size, 4 signatures_offset, 5 signatures_size
    // and 13 partitions, whose field 1 is the name and 8 an operation.
    for field in proto_fields(manifest) {
        let Some(field) = field else { return malformed() };
        let operation = match field {
            (1 | 2, Proto::Bytes(operation)) => Some(operation),
            (3, Proto::Int(value)) => {
                block_size = value;
                None
            }
            (4, Proto::Int(value)) => {
                signatures.0 = Some(value);
                None
            }
            (5, Proto::Int(value)) => {
                signatures.1 = Some(value);
                None
            }
            (13, Proto::Bytes(partition)) => {
                partitions += 1;
                for field in proto_fields(partition) {
                    match field {
                        None => return malformed(),
                        Some((1, Proto::Bytes(name))) if names.len() < MAX_OTA_NAMES => {
                            names.push(String::from_utf8_lossy(name).into_owned());
                        }
                        Some((8, Proto::Bytes(operation))) => {
                            let Some(end) = ota_operation_end(operation) else { return malformed() };
                            operations += 1;
                            blobs_end = blobs_end.max(end);
                        }
                        _ => {}
                    }
                }
                None
            }
            _ => None,
        };
        if let Some(operation) = operation {
            let Some(end) = ota_operation_end(operation) else { return malformed() };
            operations += 1;
            blobs_end = blobs_end.max(end);
        }
    }
    if !(512..=1 << 20).contains(&block_size) || !block_size.is_power_of_two() {
        return Some(Candidate::magic_only(Kind::OtaPayload, "OTA payload block size is implausible"));
    }
    if let (Some(offset), Some(size)) = signatures {
        let Some(end) = offset.checked_add(size) else { return malformed() };
        blobs_end = blobs_end.max(end);
    }
    let mut note = format!("major version {version}, {block_size}-byte blocks, {partitions} partitions");
    if !names.is_empty() {
        note.push_str(&format!(" ({})", names.join(", ")));
    }
    candidate.notes.push(note);
    // A header forged to claim the rest of the file through its metadata signature size carries no operations.
    if operations == 0 || blobs_end == 0 {
        candidate.notes.push("no extent: the manifest records no operation data".to_owned());
        return Some(candidate);
    }
    let end = (header_size as u64)
        .checked_add(manifest_size)
        .and_then(|end| end.checked_add(signature_size))
        .and_then(|end| end.checked_add(blobs_end));
    let Some(end) = end else { return malformed() };
    Some(candidate.extent(end, "OTA payload header, manifest operations and payload signature"))
}

/// What running out of each walked or checksummed format's budget costs, in the order of the scan's budgets.
const WALKS: [&str; 11] = [
    "tar header walks ran out of their {budget}-byte budget at offset {offset}; tar archives from there on were not \
     reported",
    "Android sparse chunk walks ran out of their {budget}-byte budget at offset {offset}; sparse images from there on \
     have no extent",
    "OTA payload manifest reads ran out of their {budget}-byte budget at offset {offset}; payloads from there on have \
     no extent",
    "UBI erase block walks ran out of their {budget}-byte budget at offset {offset}; UBI images from there on have no \
     extent",
    "JFFS2 node walks ran out of their {budget}-byte budget at offset {offset}; JFFS2 images from there on have no \
     extent",
    "CramFS checksums ran out of their {budget}-byte budget at offset {offset}; CramFS images from there on are \
     magic_only",
    "TRX checksums ran out of their {budget}-byte budget at offset {offset}; TRX images from there on are magic_only",
    "UBIFS superblock checksums ran out of their {budget}-byte budget at offset {offset}; UBIFS superblocks from \
     there on are magic_only",
    "GPT checksums ran out of their {budget}-byte budget at offset {offset}; GPT disks from there on are reported as \
     their protective MBR",
    "UEFI firmware volume header checksums ran out of their {budget}-byte budget at offset {offset}; volumes from \
     there on are magic_only",
    "ESP image checksums ran out of their {budget}-byte budget at offset {offset}; ESP images from there on are \
     magic_only",
];

/// The string `bytes` holds up to its first NUL, for a note.
fn c_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(&bytes[..bytes.iter().position(|&byte| byte == 0).unwrap_or(bytes.len())]).into_owned()
}

/// UBI's CRC-32 (also TRX's): the register after the bytes, without the final inversion.
fn ubi_crc(bytes: &[u8]) -> u32 {
    crc32_update(!0, bytes)
}

const UBI_EC_MAGIC: &[u8; 4] = b"UBI#";
const UBI_VID_MAGIC: &[u8; 4] = b"UBI!";
const UBI_HEADER: usize = 64;
/// The erase block sizes looked for: powers of two in this range.
const MIN_UBI_PEB: usize = 1 << 10;
const MAX_UBI_PEB: usize = 16 << 20;
/// The longest run of erased blocks the walk crosses; an image ends at the last header before a longer one.
const MAX_UBI_ERASED_RUN: usize = 16 << 20;
/// How many erase counter headers after the first the erase block size is inferred from.
const UBI_SIZE_HEADERS: usize = 16;

fn gcd(mut a: usize, mut b: usize) -> usize {
    while b != 0 {
        (a, b) = (b, a % b);
    }
    a
}

/// The VID header offset, data offset and image sequence number of the UBI erase counter header at `at`, if its
/// padding and CRC check out (binwalk's ubi signature, MIT).
fn ubi_ec_header(bytes: &[u8], at: usize) -> Option<[u64; 3]> {
    let header = bytes.get(at..at.checked_add(UBI_HEADER)?)?;
    if &header[..4] != UBI_EC_MAGIC
        || header[4] != 1
        || header[5..8] != [0; 3]
        || header[28..60].iter().any(|&byte| byte != 0)
        || u64::from(ubi_crc(&header[..60])) != read_uint(header, 60, 4, true)?
    {
        return None;
    }
    let [vid, data, sequence] = [16, 20, 24].map(|at| read_uint(header, at, 4, true).unwrap_or(0));
    (vid >= UBI_HEADER as u64 && data >= vid + UBI_HEADER as u64 && data < MAX_UBI_PEB as u64)
        .then_some([vid, data, sequence])
}

/// Whether a UBI volume identifier header with a good CRC lies at `at`.
fn ubi_vid_header(bytes: &[u8], at: usize) -> bool {
    bytes.get(at..at.saturating_add(UBI_HEADER)).is_some_and(|header| {
        &header[..4] == UBI_VID_MAGIC
            && header[4] == 1
            && read_uint(header, 60, 4, true) == Some(u64::from(ubi_crc(&header[..60])))
    })
}

/// A UBI image at its first erase counter header, and how many bytes from it the scan takes as the image's own.
/// The erase block size is the first power of two past the data offset where the next erase counter header of the
/// same image lies; the extent ends after the last of the consecutive blocks with such a header (erased blocks
/// between them, all 0xff, are part of the image).
fn ubi(bytes: &[u8], walk: &mut Probe) -> Option<(Candidate, usize)> {
    if !bytes.starts_with(UBI_EC_MAGIC) || bytes.get(4) != Some(&1) {
        return None;
    }
    if bytes.len() < UBI_HEADER {
        return Some((Candidate::magic_only(Kind::Ubi, "UBI erase counter header is truncated"), 4));
    }
    let Some(first) = ubi_ec_header(bytes, 0) else {
        let reason = "UBI erase counter header padding or CRC does not check out";
        return Some((Candidate::magic_only(Kind::Ubi, reason), 4));
    };
    let [vid, data, sequence] = first;
    let mut candidate = Candidate::new(Kind::Ubi).endian(true);
    let budget = "no extent: the scan's header walk budget ran out";
    let same_image = |at: usize| ubi_ec_header(bytes, at) == Some(first);
    // An erased block is all 0xff, every byte of it: a block whose header alone is erased may hide anything.
    let erased = |at: usize, size: usize, walk: &mut Probe| {
        walk.charge(size as u64)
            && bytes.get(at..at.saturating_add(size)).is_some_and(|block| block.iter().all(|&byte| byte == 0xff))
    };
    // Erase blocks are a power of two past the data offset. The headers of the image's next few blocks, looked for
    // at every multiple of the smallest such size, all lie at multiples of the erase block size: it is the largest
    // power of two dividing their offsets, which an erased block between them does not change.
    let smallest = (data as usize + 1).next_power_of_two().max(MIN_UBI_PEB);
    let (mut common, mut headers, mut last, mut at) = (0usize, 0usize, 0usize, smallest);
    while at < bytes.len() && headers < UBI_SIZE_HEADERS && at - last <= MAX_UBI_ERASED_RUN {
        if !walk.charge(4) {
            candidate.notes.push(budget.to_owned());
            return Some((candidate, UBI_HEADER));
        }
        if bytes[at..].starts_with(UBI_EC_MAGIC) && same_image(at) {
            headers += 1;
            last = at;
            common = if common == 0 { at } else { gcd(common, at) };
        }
        at += smallest;
        if headers == 0 && at > MAX_UBI_PEB {
            break;
        }
    }
    let peb = 1usize << common.trailing_zeros().min(MAX_UBI_PEB.trailing_zeros());
    if common == 0 {
        candidate.notes.push(format!(
            "image sequence {sequence:#x}; no extent: no second erase counter header of the image lies within \
             {MAX_UBI_PEB:#x} bytes"
        ));
        return Some((candidate, UBI_HEADER));
    }
    let (mut blocks, mut mapped, mut at, mut erased_run) = (0usize, 0u64, 0usize, 0usize);
    let mut ran_out = false;
    while at < bytes.len() && erased_run <= MAX_UBI_ERASED_RUN {
        if !walk.charge(2 * UBI_HEADER as u64) {
            ran_out = true;
            break;
        }
        if same_image(at) {
            blocks = at / peb + 1;
            erased_run = 0;
            mapped += u64::from(ubi_vid_header(bytes, at + vid as usize));
        } else if erased(at, peb, walk) {
            erased_run += peb;
        } else {
            ran_out = walk.exhausted;
            break;
        }
        at = match at.checked_add(peb) {
            Some(next) => next,
            None => break,
        };
    }
    candidate.notes.push(format!(
        "{blocks} erase blocks of {peb:#x} bytes ({mapped} with a volume header), data at {data:#x} in each, image \
         sequence {sequence:#x}"
    ));
    if ran_out {
        candidate.notes.push(budget.to_owned());
        return Some((candidate, at.min(bytes.len())));
    }
    let end = blocks * peb;
    Some((candidate.extent(end as u64, "UBI erase counter headers of consecutive erase blocks"), end.min(bytes.len())))
}

const UBIFS_NODE_MAGIC: u64 = 0x0610_1831;
const UBIFS_SUPERBLOCK_NODE: u8 = 6;
const UBIFS_SUPERBLOCK_SIZE: usize = 4096;

/// A UBIFS file system at its superblock node: the common node header's CRC over the node, and the geometry (as
/// binwalk's ubifs signature, MIT). The extent is the LEB count times the LEB size, as stored by mkfs.ubifs; inside
/// a UBI image the LEBs lie in erase blocks instead.
fn ubifs(bytes: &[u8], sum: &mut Probe) -> Option<Candidate> {
    // Every UBIFS node carries the magic; only the superblock node starts a file system.
    if read_uint(bytes, 0, 4, false)? != UBIFS_NODE_MAGIC || *bytes.get(20)? != UBIFS_SUPERBLOCK_NODE {
        return None;
    }
    let Some(node) = bytes.get(..UBIFS_SUPERBLOCK_SIZE) else {
        return Some(Candidate::magic_only(Kind::Ubifs, "UBIFS superblock node is truncated"));
    };
    let read = |at: usize, width: usize| read_uint(node, at, width, false);
    if read(16, 4)? != UBIFS_SUPERBLOCK_SIZE as u64 || node[21] > 2 || node[22..26] != [0; 4] {
        return Some(Candidate::magic_only(Kind::Ubifs, "UBIFS superblock node header does not check out"));
    }
    if !sum.charge(UBIFS_SUPERBLOCK_SIZE as u64) {
        let reason = "its CRC was not checked: the scan's checksum budget ran out";
        return Some(Candidate::magic_only(Kind::Ubifs, reason));
    }
    if read(4, 4)? != u64::from(ubi_crc(&node[8..])) {
        return Some(Candidate::magic_only(Kind::Ubifs, "UBIFS superblock node header or CRC does not check out"));
    }
    let [min_io, leb_size, lebs, max_lebs, version] = [32, 36, 40, 44, 80].map(|at| read(at, 4).unwrap_or(0));
    if !min_io.is_power_of_two() || leb_size == 0 || !leb_size.is_multiple_of(min_io) || lebs == 0 || lebs > max_lebs {
        return Some(Candidate::magic_only(Kind::Ubifs, "UBIFS superblock geometry is inconsistent"));
    }
    let compressor = match read(84, 2)? {
        0 => "no".to_owned(),
        1 => "lzo".to_owned(),
        2 => "zlib".to_owned(),
        3 => "zstd".to_owned(),
        other => format!("unknown ({other})"),
    };
    let mut candidate = Candidate::new(Kind::Ubifs).endian(false);
    candidate.notes.push(format!(
        "format version {version}, {lebs} LEBs of {leb_size:#x} bytes, {compressor} compression by default"
    ));
    candidate.declared_size = Some(lebs * leb_size);
    Some(candidate.extent(lebs * leb_size, "UBIFS superblock LEB count and size"))
}

const JFFS2_MAGIC: u64 = 0x1985;
const JFFS2_NODE_HEADER: usize = 12;
/// The most padding between two JFFS2 nodes the walk crosses (binwalk's limit).
const MAX_JFFS2_GAP: usize = 64 << 10;
/// The largest JFFS2 node the walk accepts: an inode holds at most a page of data, and padding at most an erase
/// block.
const MAX_JFFS2_NODE: u64 = 1 << 20;
/// The fewest nodes, the first included, that make a JFFS2 image (binwalk asks for more than two).
const MIN_JFFS2_NODES: u64 = 3;

/// The size of the JFFS2 node whose header lies at `at`, if its magic, header CRC and size check out, and whether
/// the node's own CRC was checked too: a directory entry's or inode's must match, and its length must be its
/// header's plus its name or data. Other nodes (clean markers, padding) have only the header CRC, so a forged one
/// costs nothing; they are walked past but do not extend the image.
fn jffs2_node(bytes: &[u8], at: usize, big: bool) -> Option<(u64, bool)> {
    let header = bytes.get(at..at.checked_add(JFFS2_NODE_HEADER)?)?;
    let size = read_uint(header, 4, 4, big)?;
    if read_uint(header, 0, 2, big)? != JFFS2_MAGIC
        || read_uint(header, 8, 4, big)? != u64::from(crc32_update(0, &header[..8]))
        || !(JFFS2_NODE_HEADER as u64..=MAX_JFFS2_NODE).contains(&size)
    {
        return None;
    }
    // (fixed part, where the node CRC lies, what it covers, the name or data length)
    let (fixed, crc_at, covered, variable) = match read_uint(header, 2, 2, big)? {
        0xe001 => (40, 32, 32, read_uint(bytes, at + 28, 1, big)?),
        0xe002 => (68, 64, 60, read_uint(bytes, at + 48, 4, big)?),
        _ => return Some((size, false)),
    };
    let node = bytes.get(at..at.checked_add(fixed)?)?;
    (size == fixed as u64 + variable
        && read_uint(node, crc_at, 4, big)? == u64::from(crc32_update(0, &node[..covered])))
    .then_some((size, true))
}

/// A JFFS2 image at its first node (a directory entry, inode or clean marker, as binwalk's jffs2 signature has
/// it, MIT), and how many bytes from it the scan takes as the image's own: nodes are walked by their sizes, each
/// next one looked for at 4-byte boundaries across at most 64 KiB of padding. The extent ends with the last
/// directory entry or inode whose node CRC checks out.
fn jffs2(bytes: &[u8], walk: &mut Probe) -> Option<(Candidate, usize)> {
    let big = match bytes.get(..2)? {
        [0x19, 0x85] => true,
        [0x85, 0x19] => false,
        _ => return None,
    };
    if !matches!(read_uint(bytes, 2, 2, big)?, 0xe001 | 0xe002 | 0x2003) {
        return None;
    }
    if bytes.len() < JFFS2_NODE_HEADER {
        return Some((Candidate::magic_only(Kind::Jffs2, "JFFS2 node header is truncated"), 2));
    }
    // A node magic and type are four bytes: only a node whose CRCs check out is reported.
    let (first, checked) = jffs2_node(bytes, 0, big)?;
    let node_end = |at: usize, size: u64| at.checked_add(usize::try_from(size.next_multiple_of(4)).ok()?);
    let mut end = node_end(0, first)?;
    let mut checked_end = if checked { end } else { 0 };
    let (mut nodes, mut checked_nodes, mut ran_out) = (1u64, u64::from(checked), false);
    'walk: loop {
        let mut at = end;
        let limit = end.saturating_add(MAX_JFFS2_GAP);
        let (size, checked) = loop {
            if at > limit || at.saturating_add(JFFS2_NODE_HEADER) > bytes.len() {
                break 'walk;
            }
            if !walk.charge(4) {
                ran_out = true;
                break 'walk;
            }
            if let Some(node) = jffs2_node(bytes, at, big) {
                break node;
            }
            at += 4;
        };
        let Some(next) = node_end(at, size) else { break };
        nodes += 1;
        end = next;
        if checked {
            checked_nodes += 1;
            checked_end = end;
        }
    }
    let mut candidate = Candidate::new(Kind::Jffs2).endian(big);
    candidate.notes.push(format!("{nodes} nodes walked, {checked_nodes} of them directory entries or inodes"));
    if ran_out {
        candidate.notes.push("no extent: the scan's header walk budget ran out".to_owned());
        return Some((candidate, checked_end.max(2).min(bytes.len())));
    }
    if nodes < MIN_JFFS2_NODES || checked_nodes == 0 {
        let reason =
            format!("only {nodes} JFFS2 nodes, {checked_nodes} of them directory entries or inodes, follow here");
        return Some((Candidate::magic_only(Kind::Jffs2, reason), 2));
    }
    Some((candidate.extent(checked_end as u64, "JFFS2 directory entries and inodes"), checked_end.min(bytes.len())))
}

/// The flags a CramFS superblock may set (the kernel's CRAMFS_SUPPORTED_FLAGS).
const CRAMFS_FLAGS: u64 = 0xff | 0x100 | 0x200 | 0x400 | 0x800;
const CRAMFS_FSID_V2: u64 = 1;

/// A CramFS image, both byte orders, as binwalk's cramfs signature has it (MIT): the signature string, the size,
/// and the CRC over the whole image (charged to the scan's checksum budget); the root inode must be a directory.
fn cramfs(bytes: &[u8], sum: &mut Probe) -> Option<Candidate> {
    let big = match read_uint(bytes, 0, 4, false)? {
        0x28cd_3d45 => false,
        0x453d_cd28 => true,
        _ => return None,
    };
    if bytes.get(16..32)? != b"Compressed ROMFS" {
        return None;
    }
    let read = |at: usize, width: usize| read_uint(bytes, at, width, big);
    let fields =
        || Some([read(4, 4)?, read(8, 4)?, read(32, 4)?, read(36, 4)?, read(40, 4)?, read(44, 4)?, read(64, 2)?]);
    let Some([size, flags, crc, edition, blocks, files, root_mode]) = fields() else {
        return Some(Candidate::magic_only(Kind::Cramfs, "CramFS superblock is truncated"));
    };
    if flags & !CRAMFS_FLAGS != 0 || root_mode & 0xf000 != 0x4000 || size < 76 {
        return Some(Candidate::magic_only(Kind::Cramfs, "CramFS superblock fields are inconsistent"));
    }
    let mut candidate = Candidate::new(Kind::Cramfs).endian(big);
    candidate.declared_size = Some(size);
    if flags & CRAMFS_FSID_V2 == 0 {
        candidate
            .notes
            .push("no extent: a superblock without the version 2 identifier has no CRC to confirm its size".to_owned());
        return Some(candidate);
    }
    candidate.notes.push(format!("{files} files, {blocks} blocks, edition {edition}"));
    match usize::try_from(size).ok().and_then(|size| bytes.get(..size)) {
        None => candidate.notes.push("its CRC was not checked: the image runs past the end of the file".to_owned()),
        Some(_) if !sum.charge(size) => {
            let reason = "its CRC was not checked: the scan's checksum budget ran out";
            return Some(Candidate::magic_only(Kind::Cramfs, reason));
        }
        Some(image) => {
            let state = crc32_update(crc32_update(!0, &image[..32]), &[0; 4]);
            if u64::from(!crc32_update(state, &image[36..])) != crc {
                return Some(Candidate::magic_only(Kind::Cramfs, "CramFS image CRC does not match"));
            }
        }
    }
    Some(candidate.extent(size, "CramFS superblock size"))
}

/// A TRX firmware container (Broadcom), as binwalk's trx signature has it (MIT): version 1 or 2, partition offsets
/// in order within the length, and the CRC from the flags word to the end (charged to the scan's checksum budget).
fn trx(bytes: &[u8], sum: &mut Probe) -> Option<Candidate> {
    if !bytes.starts_with(b"HDR0") {
        return None;
    }
    let read = |at: usize| read_uint(bytes, at, 4, false);
    let fields = || Some([read(4)?, read(8)?, read(12)?, read(16)?, read(20)?, read(24)?]);
    let Some([length, crc, flags_version, first, second, third]) = fields() else {
        return Some(Candidate::magic_only(Kind::Trx, "TRX header is truncated"));
    };
    let version = flags_version >> 16;
    let header_size = match version {
        1 => 28,
        2 => 32,
        _ => return None,
    };
    let mut partitions = vec![first, second, third];
    if version == 2 {
        partitions.push(read(28).unwrap_or(0));
    }
    partitions.retain(|&offset| offset != 0);
    // "HDR0" is ASCII: only a header whose partitions lie in order within its length is reported.
    if length < header_size
        || partitions.first().is_none_or(|&offset| offset < header_size)
        || partitions.windows(2).any(|pair| pair[0] >= pair[1])
        || partitions.last().is_some_and(|&offset| offset > length)
    {
        return None;
    }
    let mut candidate = Candidate::new(Kind::Trx).endian(false);
    let offsets: Vec<String> = partitions.iter().map(|offset| format!("{offset:#x}")).collect();
    candidate.notes.push(format!("version {version}, partitions at {}", offsets.join(", ")));
    match usize::try_from(length).ok().and_then(|length| bytes.get(12..length)) {
        None => candidate.notes.push("its CRC was not checked: the image runs past the end of the file".to_owned()),
        Some(_) if !sum.charge(length) => {
            let reason = "its CRC was not checked: the scan's checksum budget ran out";
            return Some(Candidate::magic_only(Kind::Trx, reason));
        }
        Some(covered) if u64::from(ubi_crc(covered)) != crc => {
            return Some(Candidate::magic_only(Kind::Trx, "TRX CRC does not match"));
        }
        Some(_) => {}
    }
    candidate.declared_size = Some(length);
    Some(candidate.extent(length, "TRX header length"))
}

const FDT_BEGIN_NODE: u64 = 1;
const FDT_END: u64 = 9;

/// A flattened device tree (or U-Boot FIT image), as binwalk's dtb signature has it (MIT): version 17, last
/// compatible version 16, aligned blocks within totalsize; the structure block must also start with a node and end
/// with the end token.
fn dtb(bytes: &[u8]) -> Option<Candidate> {
    if read_uint(bytes, 0, 4, true)? != 0xd00d_feed {
        return None;
    }
    // The magic is also the byte-swapped constant x86 code compares with: a header that does not check out is not
    // reported at all.
    let read = |at: usize| read_uint(bytes, at, 4, true);
    let [total, structs, strings, reserved, version, compatible, cpu, strings_size, structs_size] =
        [read(4)?, read(8)?, read(12)?, read(16)?, read(20)?, read(24)?, read(28)?, read(32)?, read(36)?];
    if version != 17
        || compatible != 16
        || !structs.is_multiple_of(4)
        || !reserved.is_multiple_of(8)
        || [structs, strings, reserved].iter().any(|&offset| offset < 40)
        || structs_size < 8
        || structs + structs_size > total
        || strings + strings_size > total
    {
        return None;
    }
    let token = |at: u64| usize::try_from(at).ok().and_then(|at| read_uint(bytes, at, 4, true));
    let (Some(begin), Some(end)) = (token(structs), token(structs + structs_size - 4)) else {
        let reason = "device tree structure block lies past the end of the file";
        return Some(Candidate::magic_only(Kind::Dtb, reason));
    };
    if begin != FDT_BEGIN_NODE || end != FDT_END {
        return None;
    }
    let mut candidate = Candidate::new(Kind::Dtb).endian(true);
    candidate.notes.push(format!("version {version}, boot CPU {cpu}"));
    candidate.declared_size = Some(total);
    Some(candidate.extent(total, "device tree header totalsize"))
}

/// xxHash32 of `input` with seed 0, for the LZ4 frame descriptor checksum.
fn xxh32(input: &[u8]) -> u32 {
    const P1: u32 = 2_654_435_761;
    const P2: u32 = 2_246_822_519;
    const P3: u32 = 3_266_489_917;
    const P4: u32 = 668_265_263;
    const P5: u32 = 374_761_393;
    let word = |chunk: &[u8]| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    let round = |acc: u32, lane: u32| acc.wrapping_add(lane.wrapping_mul(P2)).rotate_left(13).wrapping_mul(P1);
    let mut rest = input;
    let mut hash = if input.len() >= 16 {
        let mut lanes = [P1.wrapping_add(P2), P2, 0, 0u32.wrapping_sub(P1)];
        while rest.len() >= 16 {
            for (index, lane) in lanes.iter_mut().enumerate() {
                *lane = round(*lane, word(&rest[index * 4..]));
            }
            rest = &rest[16..];
        }
        lanes[0]
            .rotate_left(1)
            .wrapping_add(lanes[1].rotate_left(7))
            .wrapping_add(lanes[2].rotate_left(12))
            .wrapping_add(lanes[3].rotate_left(18))
    } else {
        P5
    };
    hash = hash.wrapping_add(input.len() as u32);
    while rest.len() >= 4 {
        hash = hash.wrapping_add(word(rest).wrapping_mul(P3)).rotate_left(17).wrapping_mul(P4);
        rest = &rest[4..];
    }
    for &byte in rest {
        hash = hash.wrapping_add(u32::from(byte).wrapping_mul(P5)).rotate_left(11).wrapping_mul(P1);
    }
    hash ^= hash >> 15;
    hash = hash.wrapping_mul(P2);
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(P3);
    hash ^ (hash >> 16)
}

/// An LZ4 frame, as binwalk's lz4 signature has it (MIT): the frame descriptor's version and reserved bits and its
/// header checksum. Nothing gives an extent without walking the blocks.
fn lz4(bytes: &[u8]) -> Option<Candidate> {
    if !bytes.starts_with(&[0x04, 0x22, 0x4d, 0x18]) {
        return None;
    }
    let (Some(&flags), Some(&descriptor)) = (bytes.get(4), bytes.get(5)) else {
        return Some(Candidate::magic_only(Kind::Lz4, "LZ4 frame descriptor is truncated"));
    };
    // The magic is also a constant in programs that read LZ4: a descriptor whose version or reserved bits are wrong
    // is not reported at all.
    if flags >> 6 != 1 || flags & 0x02 != 0 || descriptor & 0x8f != 0 || (descriptor >> 4) < 4 {
        return None;
    }
    let content_size = flags & 0x08 != 0;
    let end = 6 + if content_size { 8 } else { 0 } + if flags & 0x01 != 0 { 4 } else { 0 };
    let Some(&checksum) = bytes.get(end) else {
        return Some(Candidate::magic_only(Kind::Lz4, "LZ4 frame descriptor is truncated"));
    };
    if checksum != (xxh32(&bytes[4..end]) >> 8) as u8 {
        return Some(Candidate::magic_only(Kind::Lz4, "LZ4 frame descriptor checksum does not match"));
    }
    let mut candidate = Candidate::new(Kind::Lz4).endian(false);
    candidate.notes.push(format!("{} KiB maximum block size", 64 << (2 * ((descriptor >> 4) - 4))));
    if content_size {
        candidate.uncompressed_size = read_uint(bytes, 6, 8, false);
    }
    Some(candidate)
}

const LZOP_MAGIC: [u8; 9] = [0x89, b'L', b'Z', b'O', 0, 0x0d, 0x0a, 0x1a, 0x0a];
/// The newest lzop format version (lzop 1.04), as binwalk has it.
const MAX_LZOP_VERSION: u64 = 0x1040;

fn adler32(bytes: &[u8]) -> u32 {
    let (mut low, mut high) = (1u32, 0u32);
    for chunk in bytes.chunks(5552) {
        for &byte in chunk {
            low += u32::from(byte);
            high += low;
        }
        low %= 65521;
        high %= 65521;
    }
    (high << 16) | low
}

/// An lzop file: the header fields binwalk's lzop signature checks (MIT) and the header checksum (Adler-32, or
/// CRC-32 when the header says so). Nothing gives an extent without walking the blocks.
fn lzop(bytes: &[u8]) -> Option<Candidate> {
    if !bytes.starts_with(&LZOP_MAGIC) {
        return None;
    }
    let read = |at: usize, width: usize| read_uint(bytes, at, width, true);
    let truncated = || Some(Candidate::magic_only(Kind::Lzop, "lzop header is truncated"));
    let Some([version, needed, method, flags]) = (|| Some([read(9, 2)?, read(13, 2)?, read(15, 1)?, read(17, 4)?]))()
    else {
        return truncated();
    };
    // Headers before version 0.94 lack the fields the checksum is read past.
    if !(0x0940..=MAX_LZOP_VERSION).contains(&version) || needed > version || !(1..=3).contains(&method) {
        return Some(Candidate::magic_only(Kind::Lzop, "lzop header version or method is unknown"));
    }
    let name_at = 21 + if flags & 0x800 != 0 { 4 } else { 0 } + 12;
    let Some(&name_len) = bytes.get(name_at) else { return truncated() };
    let checksum_at = name_at + 1 + usize::from(name_len);
    let Some(stored) = read(checksum_at, 4) else { return truncated() };
    let header = &bytes[9..checksum_at];
    let computed = if flags & 0x1000 != 0 { crc32(header) } else { adler32(header) };
    if u64::from(computed) != stored {
        return Some(Candidate::magic_only(Kind::Lzop, "lzop header checksum does not match"));
    }
    let mut candidate = Candidate::new(Kind::Lzop).endian(true);
    let name = &bytes[name_at + 1..checksum_at];
    let method = ["LZO1X-1", "LZO1X-1(15)", "LZO1X-999"][method as usize - 1];
    candidate.notes.push(if name.is_empty() {
        method.to_owned()
    } else {
        format!("{method}, original name {:?}", String::from_utf8_lossy(name))
    });
    Some(candidate)
}

const SECTOR: usize = 512;
/// Where a boot sector's signature lies.
const BOOT_SIGNATURE_AT: usize = 0x1fe;
const BOOT_SIGNATURE: [u8; 2] = [0x55, 0xaa];
const GPT_PROTECTIVE: u8 = 0xee;
/// The largest GPT partition entry array whose CRC is checked: the usual 128 entries of 128 bytes.
const MAX_GPT_ENTRIES_BYTES: u64 = 128 * 128;
/// The most partition names a GPT candidate lists.
const MAX_GPT_NAMES: usize = 16;

/// An MBR-partitioned disk, or a GPT disk behind its protective MBR, at a sector-aligned offset. The boot
/// signature alone is common, so every used partition entry must have a boot flag of 0 or 0x80, a type and a
/// non-empty range past the MBR, the entries must not overlap, and unused ones must be all zero (binwalk's mbr
/// signature, MIT, made stricter). The extent ends with the furthest partition.
fn disk(bytes: &[u8], sum: &mut Probe) -> Option<Candidate> {
    if bytes.get(BOOT_SIGNATURE_AT..BOOT_SIGNATURE_AT + 2)? != BOOT_SIGNATURE {
        return None;
    }
    let mut partitions = Vec::new();
    for entry in bytes[446..510].as_chunks::<16>().0 {
        if entry.iter().all(|&byte| byte == 0) {
            continue;
        }
        let (start, count) = (read_uint(entry, 8, 4, false)?, read_uint(entry, 12, 4, false)?);
        if !matches!(entry[0], 0 | 0x80) || entry[4] == 0 || start == 0 || count == 0 {
            return None;
        }
        partitions.push((entry[4], start, count));
    }
    partitions.sort_by_key(|&(_, start, _)| start);
    if partitions.is_empty() || partitions.windows(2).any(|pair| pair[0].1 + pair[0].2 > pair[1].1) {
        return None;
    }
    let protective = partitions.iter().any(|&(kind, ..)| kind == GPT_PROTECTIVE);
    if protective && let Some(candidate) = gpt(bytes, sum) {
        return Some(candidate);
    }
    let end = partitions.iter().map(|&(_, start, count)| (start + count) * SECTOR as u64).max().unwrap_or(0);
    let mut candidate = Candidate::new(Kind::Mbr).endian(false);
    let listed: Vec<String> = partitions
        .iter()
        .map(|&(kind, start, _)| format!("type {kind:#04x} at {:#x}", start * SECTOR as u64))
        .collect();
    candidate.notes.push(format!("{} partitions: {}", partitions.len(), listed.join(", ")));
    if protective {
        candidate.notes.push("a protective MBR, but the GPT header after it does not check out".to_owned());
    }
    Some(candidate.extent(end, "MBR partition table"))
}

/// The GPT disk whose protective MBR starts `bytes`, if the header at LBA 1 and its partition array check out
/// (binwalk's efigpt signature, MIT, with the header CRC too). The extent ends with the backup header's LBA or the
/// furthest partition.
fn gpt(bytes: &[u8], sum: &mut Probe) -> Option<Candidate> {
    let header = bytes.get(SECTOR..2 * SECTOR)?;
    if &header[..8] != b"EFI PART" {
        return None;
    }
    let read = |at: usize, width: usize| read_uint(header, at, width, false);
    let (revision, size, crc, reserved, current, backup) =
        (read(8, 4)?, read(12, 4)?, read(16, 4)?, read(20, 4)?, read(24, 8)?, read(32, 8)?);
    if revision != 0x0001_0000 || !(92..=SECTOR as u64).contains(&size) || reserved != 0 || current != 1 {
        return None;
    }
    // The header and partition array checksums are charged to the scan's checksum budget.
    if !sum.charge(size) {
        return None;
    }
    let mut zeroed = header[..size as usize].to_vec();
    zeroed[16..20].fill(0);
    if u64::from(crc32(&zeroed)) != crc {
        return None;
    }
    let (entries_lba, count, entry_size, entries_crc) = (read(72, 8)?, read(80, 4)?, read(84, 4)?, read(88, 4)?);
    if entry_size < 128 || !entry_size.is_multiple_of(8) {
        return None;
    }
    let array = count.checked_mul(entry_size).filter(|&len| len <= MAX_GPT_ENTRIES_BYTES)?;
    let at = usize::try_from(entries_lba.checked_mul(SECTOR as u64)?).ok()?;
    let entries = bytes.get(at..at.checked_add(array as usize)?)?;
    if !sum.charge(array) || u64::from(crc32(entries)) != entries_crc {
        return None;
    }
    let mut candidate = Candidate::new(Kind::Gpt).endian(false);
    let (mut used, mut names) = (0usize, Vec::new());
    let mut end = backup.saturating_add(1).saturating_mul(SECTOR as u64);
    for entry in entries.chunks_exact(entry_size as usize) {
        if entry[..16].iter().all(|&byte| byte == 0) {
            continue;
        }
        used += 1;
        let (first, last) = (read_uint(entry, 32, 8, false)?, read_uint(entry, 40, 8, false)?);
        end = end.max(last.saturating_add(1).saturating_mul(SECTOR as u64));
        if names.len() < MAX_GPT_NAMES {
            let units: Vec<u16> =
                entry[56..128].as_chunks::<2>().0.iter().map(|unit| u16::from_le_bytes([unit[0], unit[1]])).collect();
            let name = &units[..units.iter().position(|&unit| unit == 0).unwrap_or(units.len())];
            let name = if name.is_empty() { "(unnamed)".to_owned() } else { String::from_utf16_lossy(name) };
            names.push(format!("{name} at {:#x}", first.saturating_mul(SECTOR as u64)));
        }
    }
    candidate.notes.push(format!("{used} partitions: {}", names.join(", ")));
    Some(candidate.extent(end, "GPT backup header and partition entries"))
}

/// A FAT12, FAT16 or FAT32 file system at its boot sector: binwalk's fat signature (MIT), that is the jump, sector
/// size, cluster size, reserved sectors, FAT count and media byte, plus the boot signature, the "FAT" file system
/// type in the extended boot record and the layout fitting the sector count. The extent is the sector count. Also
/// where a FAT32 volume keeps its backup boot sector, from its start (0 for none).
fn fat_fs(bytes: &[u8]) -> Option<(Candidate, usize)> {
    if !matches!(bytes.first()?, 0xeb | 0xe9) || bytes.get(BOOT_SIGNATURE_AT..BOOT_SIGNATURE_AT + 2)? != BOOT_SIGNATURE
    {
        return None;
    }
    let read = |at: usize, width: usize| read_uint(bytes, at, width, false);
    let [sector, per_cluster, reserved, fats, roots, small_total, media, small_fat, total] =
        [(11, 2), (13, 1), (14, 2), (16, 1), (17, 2), (19, 2), (21, 1), (22, 2), (32, 4)]
            .map(|(at, width)| read(at, width).unwrap_or(0));
    if !matches!(sector, 512 | 1024 | 2048 | 4096)
        || !per_cluster.is_power_of_two()
        || reserved == 0
        || !matches!(fats, 1 | 2)
        || !(media == 0xf0 || media >= 0xf8)
    {
        return None;
    }
    let fat32 = small_fat == 0;
    let fat_size = if fat32 { read(36, 4)? } else { small_fat };
    let type_at = if fat32 { 0x52 } else { 0x36 };
    if bytes.get(type_at..type_at + 3)? != b"FAT" || (fat32 && (roots != 0 || small_total != 0)) {
        return None;
    }
    let total = if small_total != 0 { small_total } else { total };
    let metadata = reserved + fats * fat_size + (roots * 32).div_ceil(sector);
    if fat_size == 0 || metadata >= total {
        return None;
    }
    let clusters = (total - metadata) / per_cluster;
    let version = match (fat32, clusters) {
        (true, _) => "FAT32",
        (false, 0..4085) => "FAT12",
        _ => "FAT16",
    };
    let mut candidate = Candidate::new(Kind::Fat).endian(false);
    let mut note = format!("{version}, {sector}-byte sectors, {clusters} clusters");
    let label = c_string(&bytes[type_at - 11..type_at]);
    let label = label.trim_end();
    if !label.is_empty() && label != "NO NAME" {
        note.push_str(&format!(", volume label {label:?}"));
    }
    candidate.notes.push(note);
    candidate.declared_size = Some(total * sector);
    let backup = if fat32 { read(50, 2)?.saturating_mul(sector) } else { 0 };
    Some((candidate.extent(total * sector, "FAT boot sector sector count"), backup as usize))
}

/// Where a UEFI firmware volume's signature lies.
const FV_MAGIC_AT: usize = 0x28;
const FV_MAGIC: &[u8; 4] = b"_FVH";
/// The most block map entries read.
const MAX_FV_BLOCK_MAP: usize = 64;

/// A UEFI (PI) firmware volume, found by its signature at 0x28: binwalk's checks (MIT), that is the revision,
/// reserved byte and header length, plus the header's 16-bit checksum and the block map adding up to the volume
/// length.
fn uefi_volume(bytes: &[u8], sum: &mut Probe) -> Option<Candidate> {
    if bytes.get(FV_MAGIC_AT..FV_MAGIC_AT + 4)? != FV_MAGIC {
        return None;
    }
    let read = |at: usize, width: usize| read_uint(bytes, at, width, false);
    let (length, header_length, reserved, revision) = (read(0x20, 8)?, read(0x30, 2)?, read(0x36, 1)?, read(0x37, 1)?);
    // "_FVH" is also the constant code compares with: a header that does not check out is not reported at all.
    if !matches!(revision, 1 | 2)
        || reserved != 0
        || header_length < 0x48
        || header_length % 2 != 0
        || length <= header_length
    {
        return None;
    }
    let Some(header) = bytes.get(..header_length as usize) else {
        return Some(Candidate::magic_only(Kind::UefiVolume, "UEFI firmware volume header is truncated"));
    };
    // The block map: (block count, block length) pairs up to a zero pair, which must cover the volume.
    let mut covered = 0u64;
    let mut terminated = false;
    for entry in header[0x38..].as_chunks::<8>().0.iter().take(MAX_FV_BLOCK_MAP) {
        let (blocks, size) = (read_uint(entry, 0, 4, false)?, read_uint(entry, 4, 4, false)?);
        if blocks == 0 && size == 0 {
            terminated = true;
            break;
        }
        covered = covered.saturating_add(blocks * size);
    }
    if !terminated || covered != length {
        return None;
    }
    if !sum.charge(header_length) {
        let reason = "its header checksum was not checked: the scan's checksum budget ran out";
        return Some(Candidate::magic_only(Kind::UefiVolume, reason));
    }
    let sum = header
        .as_chunks::<2>()
        .0
        .iter()
        .fold(0u16, |sum, word| sum.wrapping_add(u16::from_le_bytes([word[0], word[1]])));
    if sum != 0 {
        return Some(Candidate::magic_only(Kind::UefiVolume, "UEFI firmware volume header checksum does not match"));
    }
    let mut candidate = Candidate::new(Kind::UefiVolume).endian(false);
    let file_system = match header[0x10..0x20] {
        [0x78, 0xe5, 0x8c, 0x8c, 0x3d, 0x8a, 0x1c, 0x4f, 0x99, 0x35, 0x89, 0x61, 0x85, 0xc3, 0x2d, 0xd3] => {
            "FFS version 2".to_owned()
        }
        [0x7a, 0xc0, 0x73, 0x54, 0xcb, 0x3d, 0xca, 0x4d, 0xbd, 0x6f, 0x1e, 0x96, 0x89, 0xe7, 0x34, 0x9a] => {
            "FFS version 3".to_owned()
        }
        _ => format!("file system {}", guid(&header[0x10..0x20])),
    };
    candidate.notes.push(format!("revision {revision}, {file_system}"));
    candidate.declared_size = Some(length);
    Some(candidate.extent(length, "UEFI firmware volume header length"))
}

/// A GUID in its registry form, from its mixed-endian bytes.
fn guid(bytes: &[u8]) -> String {
    let hex = |bytes: &[u8]| bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    format!(
        "{:08x}-{:04x}-{:04x}-{}-{}",
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_le_bytes([bytes[4], bytes[5]]),
        u16::from_le_bytes([bytes[6], bytes[7]]),
        hex(&bytes[8..10]),
        hex(&bytes[10..16])
    )
}

/// The capsule GUIDs binwalk's uefi signature knows (MIT), and the firmware management (FMP) capsule's.
const CAPSULE_GUIDS: [(&[u8; 16], &str); 4] = [
    (b"\xbd\x86\x66\x3b\x76\x0d\x30\x40\xb7\x0e\xb5\x51\x9e\x2f\xc5\xa0", "EFI capsule"),
    (b"\x8b\xa6\x3c\x4a\x23\x77\xfb\x48\x80\x3d\x57\x8c\xc1\xfe\xc4\x4d", "EFI2 capsule"),
    (b"\xb9\x82\x91\x53\xb5\xab\x91\x43\xb6\x9a\xe3\xa9\x43\xf7\x2f\xcc", "UEFI capsule"),
    (b"\xed\xd5\xcb\x6d\x2d\xe8\x44\x4c\xbd\xa1\x71\x94\x19\x9a\xd9\x2a", "firmware management capsule"),
];

/// A UEFI capsule: one of the capsule GUIDs, then a header size within the image size and only the defined flags
/// above the platform-specific low half.
fn uefi_capsule(bytes: &[u8]) -> Option<Candidate> {
    let &(_, what) = CAPSULE_GUIDS.iter().find(|(guid, _)| bytes.starts_with(&guid[..]))?;
    let read = |at: usize| read_uint(bytes, at, 4, false);
    let (Some(header_size), Some(flags), Some(size)) = (read(16), read(20), read(24)) else {
        return Some(Candidate::magic_only(Kind::UefiCapsule, "UEFI capsule header is truncated"));
    };
    if header_size < 28 || header_size >= size || flags & 0xfff8_0000 != 0 {
        return Some(Candidate::magic_only(Kind::UefiCapsule, "UEFI capsule header fields are inconsistent"));
    }
    let mut candidate = Candidate::new(Kind::UefiCapsule).endian(false);
    candidate.notes.push(format!("{what}, header size {header_size:#x}"));
    candidate.declared_size = Some(size);
    Some(candidate.extent(size, "UEFI capsule header image size"))
}

/// Partition tables start on a flash sector.
const ESP_PARTITION_TABLE_ALIGN: usize = 0x1000;

/// An ESP app or bootloader image whose segment headers fit, every segment loading into the chip's memory map (or
/// esptool's padding at address 0), with a matching checksum or appended SHA-256: a magic-only match otherwise.
fn esp_image(bytes: &[u8], offset: usize, sum: &mut Probe) -> Option<Candidate> {
    use crate::esp;
    if !esp::looks_like_app_image(bytes, 0) {
        return None;
    }
    // The checksum, then the SHA-256 only once the checksum matched, are charged to the scan's ESP budget.
    let image = match esp::parse_app_image_within(bytes, 0, &mut sum.left, true).ok()? {
        Some(image) => image,
        None => {
            sum.exhausted = true;
            return Some(Candidate::magic_only(
                Kind::EspImage,
                "its checksum was not checked: the scan's ESP checksum budget ran out",
            ));
        }
    };
    let mapped = image.segments.iter().all(|segment| segment.memory.is_some() || segment.load_address == 0);
    if !mapped || !image.chip.xtensa() {
        return None;
    }
    if !image.digests_valid() {
        return Some(Candidate::magic_only(Kind::EspImage, "ESP image checksum or SHA-256 does not match its bytes"));
    }
    let mut candidate = Candidate {
        arch: Some(Arch::Xtensa.to_string()),
        bits: Some(32),
        ..Candidate::new(Kind::EspImage).endian(false)
    }
    .extent(image.length, "ESP image segment headers, checksum and SHA-256");
    let what = match (&image.app_desc, &image.bootloader_desc) {
        (Some(desc), _) => format!(
            "{} application \"{}\" version {} (ESP-IDF {})",
            image.chip.label(),
            desc.project_name,
            desc.version,
            desc.idf_version
        ),
        (None, Some(desc)) => format!("{} bootloader (ESP-IDF {})", image.chip.label(), desc.idf_version),
        (None, None) if offset == 0x1000 => {
            format!("{} image at flash 0x1000, where the ROM loads the second-stage bootloader", image.chip.label())
        }
        (None, None) => format!("{} image", image.chip.label()),
    };
    candidate.notes.push(format!(
        "{what}; entry {:#x}, {} segments, {} ABI; checksum {}{}",
        image.entry,
        image.segments.len(),
        image.abi,
        if image.checksum.valid { "valid" } else { "mismatch" },
        match &image.sha256 {
            Some(sha) if sha.valid => ", SHA-256 valid",
            Some(_) => ", SHA-256 mismatch",
            None => "",
        }
    ));
    candidate
        .notes
        .push(format!("open it with \"raw\":{{\"profile\":\"xtensa\",\"format\":\"esp\",\"offset\":\"{offset:#x}\"}}"));
    Some(candidate)
}

/// An ESP-IDF partition table: its entries, validated by the MD5 entry when it has one, or else by every partition
/// lying on a 4 KiB boundary.
fn esp_partition_table(bytes: &[u8]) -> Option<Candidate> {
    let table = crate::esp::read_partition_table(bytes, 0)?;
    if table.md5.as_ref().is_some_and(|md5| !md5.valid) {
        return Some(Candidate::magic_only(Kind::EspPartitionTable, "partition table MD5 does not match"));
    }
    if !table.plausible() {
        return None;
    }
    let mut candidate =
        Candidate::new(Kind::EspPartitionTable).extent((table.partitions.len() as u64 + 1) * 32, "partition entries");
    let entries: Vec<String> = table
        .partitions
        .iter()
        .map(|partition| {
            format!(
                "{} {}/{} at {:#x}, {:#x} bytes",
                partition.label, partition.kind, partition.subtype, partition.offset, partition.size
            )
        })
        .collect();
    candidate.notes.push(format!(
        "{} partitions{}: {}",
        table.partitions.len(),
        if table.md5.is_some() { ", MD5 valid" } else { "" },
        entries.join("; ")
    ));
    Some(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_parser_magic_passes_the_prefilter() {
        let magics: [&[u8]; 14] = [
            UBI_EC_MAGIC,
            &LZOP_MAGIC,
            CAPSULE_GUIDS[0].0,
            CAPSULE_GUIDS[3].0,
            b"\x7fELF",
            b"MZ\x90\0",
            &0xfeed_facf_u32.to_le_bytes(),
            &0xcafe_babe_u32.to_be_bytes(),
            &0x2705_1956_u32.to_be_bytes(),
            &0xed26_ff3a_u32.to_le_bytes(),
            &(UBIFS_NODE_MAGIC as u32).to_le_bytes(),
            &0x28cd_3d45_u32.to_le_bytes(),
            &0x28cd_3d45_u32.to_be_bytes(),
            &0xd00d_feed_u32.to_be_bytes(),
        ];
        for magic in magics.iter().copied().chain(MAGICS) {
            assert!(starts_a_magic(magic[0], *magic.get(1).unwrap_or(&0)), "{magic:02x?}");
        }
        assert!(starts_a_magic(0xeb, 0x3c) && starts_a_magic(0xe9, 0x00));
        assert!(!starts_a_magic(0x55, 0xaa) && !starts_a_magic(b'U', b'X') && !starts_a_magic(0x04, 0x00));
    }

    /// Review: every 0xE9 header that passed was checksummed (and hashed) over the rest of the file with no
    /// budget. A header every 64 bytes, each claiming one segment to the end of the file, took 32 s on 16 MiB.
    #[test]
    fn crafted_esp_headers_stay_within_the_checksum_budget() {
        const SIZE: usize = 4 << 20;
        let mut data = vec![0u8; SIZE];
        for at in (0..SIZE - 64).step_by(64) {
            let length = (SIZE - at - 64) as u32;
            data[at..at + 8].copy_from_slice(&[0xe9, 1, 2, 0, 0x04, 0x00, 0x08, 0x40]);
            data[at + 8..at + 24].fill(0);
            data[at + 8 + 15] = 1; // a SHA-256 is appended
            data[at + 24..at + 28].copy_from_slice(&0x3ffb_0000u32.to_le_bytes());
            data[at + 28..at + 32].copy_from_slice(&length.to_le_bytes());
        }
        let limits = Limits { max_walk_bytes: 8 << 20, ..Limits::default() };
        let started = std::time::Instant::now();
        let carving = scan(&data, &limits);
        assert!(started.elapsed() < std::time::Duration::from_secs(10), "{:?}", started.elapsed());
        assert!(carving.limitations.iter().any(|limitation| limitation.starts_with("ESP image checksums ran out")));
        assert!(carving.candidates.iter().all(|candidate| candidate.confidence == Confidence::MagicOnly));
    }

    /// Review: `AA 50` at a 4 KiB boundary is not a partition table unless it checks out.
    #[test]
    fn stray_partition_magic_is_no_table() {
        let mut bytes = vec![0x5a; 0x1000];
        bytes[..2].copy_from_slice(&[0xaa, 0x50]);
        assert!(esp_partition_table(&bytes).is_none());
        assert!(crate::esp::flash_layout(&[&vec![0u8; 0x8000][..], &bytes].concat()).is_none());
    }

    #[test]
    fn esp_flash_dump_carves_bootloader_partition_table_and_app() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/xtensa/esp32-flash.bin");
        let carving = scan(&std::fs::read(path).unwrap(), &Limits::default());
        let found: Vec<(u64, Kind, Confidence)> = carving
            .candidates
            .iter()
            .map(|candidate| (candidate.offset, candidate.kind, candidate.confidence))
            .collect();
        assert_eq!(
            found,
            [
                (0x1000, Kind::EspImage, Confidence::Validated),
                (0x8000, Kind::EspPartitionTable, Confidence::Validated),
                (0x10000, Kind::EspImage, Confidence::Validated),
            ]
        );
        let app = &carving.candidates[2];
        let image_size =
            std::fs::metadata(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/xtensa/esp32-app.bin"));
        assert_eq!((app.arch.as_deref(), app.extent), (Some("xtensa"), Some(image_size.unwrap().len())));
        assert!(app.notes[0].starts_with("ESP32 application \"thermostat\" version 1.4.2"), "{:?}", app.notes);
        assert!(
            carving.candidates[1].notes[0].contains("factory app/factory at 0x10000"),
            "{:?}",
            carving.candidates[1]
        );
        // A flipped byte breaks the checksum and the digest: the image is then a magic-only match.
        let mut image =
            std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/xtensa/esp32-app.bin")).unwrap();
        image[0x40] ^= 1;
        let mut sum = Probe { left: MAX_WALK_BYTES, exhausted: false };
        assert_eq!(esp_image(&image, 0, &mut sum).unwrap().confidence, Confidence::MagicOnly);
        // The checksum matches but an appended SHA-256 does not: still not valid.
        let mut image =
            std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/xtensa/esp32-app.bin")).unwrap();
        let last = image.len() - 1;
        image[last] ^= 1;
        assert_eq!(esp_image(&image, 0, &mut sum).unwrap().confidence, Confidence::MagicOnly);
        let elf =
            std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/xtensa/esp32-app.elf")).unwrap();
        assert_eq!(executable(&elf).unwrap().arch.as_deref(), Some("xtensa"));
    }
}
