//! A first look at a binary: hashes, entropy, overlay, and hints of packing or weak hardening.

use md5::{Digest, Md5};
use rampage_loaders::{Binary, Details, Format, SectionKind};
use serde::Serialize;
use sha1::Sha1;
use sha2::Sha256;

/// Points in the entropy profile across the image.
const PROFILE_POINTS: usize = 64;
/// Entropy (bits per byte) above which code or data is likely compressed or encrypted.
const HIGH_ENTROPY: f64 = 7.2;

#[derive(Debug, Clone, Serialize)]
pub struct Triage {
    /// The image: the whole file, or one slice of a universal binary.
    pub image_size: u64,
    pub image_hashes: Hashes,
    /// The whole file's size and hashes, when the image is one slice of it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_hashes: Option<Hashes>,
    /// Shannon entropy of the image in bits per byte (0-8).
    pub entropy: f64,
    /// Entropy of consecutive equal slices of the image, for spotting packed or encrypted regions.
    pub entropy_profile: Vec<f64>,
    pub sections: Vec<SectionTriage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overlay: Option<OverlayTriage>,
    /// The PE import hash (pefile's algorithm), which groups samples built from the same import table.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub imphash: Option<String>,
    pub details: Details,
    /// Observations worth a closer look: packing, unusual layout, missing hardening.
    pub hints: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Hashes {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionTriage {
    pub name: String,
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub size: u64,
    /// Bytes present in the file (zero for uninitialized data).
    pub file_size: u64,
    pub kind: SectionKind,
    /// `rwx` permissions of the containing segment.
    pub perms: String,
    pub entropy: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct OverlayTriage {
    pub offset: u64,
    pub size: u64,
    pub entropy: f64,
}

/// Shannon entropy in bits per byte, rounded to two decimals.
pub fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &byte in bytes {
        counts[byte as usize] += 1;
    }
    let total = bytes.len() as f64;
    let bits: f64 = counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum();
    // max(0.0) turns a rounded -0.0 into 0.0.
    ((bits * 100.0).round() / 100.0).max(0.0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hashes(bytes: &[u8]) -> Hashes {
    let ((md5, sha1), sha256) = rayon::join(
        || rayon::join(|| hex(&Md5::digest(bytes)), || hex(&Sha1::digest(bytes))),
        || hex(&Sha256::digest(bytes)),
    );
    Hashes { md5, sha1, sha256 }
}

/// The PE import hash: MD5 of `library.function` pairs, lowercased, library extensions removed, ordinals as
/// `ord<n>`, joined with commas.
pub fn imphash(binary: &Binary) -> Option<String> {
    if binary.format != Format::Pe || binary.imports.is_empty() {
        return None;
    }
    let entries: Vec<String> = binary
        .imports
        .iter()
        .map(|import| {
            let library = import.library.as_deref().unwrap_or("").to_lowercase();
            let library = ["dll", "ocx", "sys"]
                .iter()
                .find_map(|extension| library.strip_suffix(&format!(".{extension}")))
                .unwrap_or(&library)
                .to_owned();
            let function = match import.name.strip_prefix('#') {
                Some(ordinal) => format!("ord{ordinal}"),
                None => import.name.to_lowercase(),
            };
            format!("{library}.{function}")
        })
        .collect();
    Some(hex(&Md5::digest(entries.join(",").as_bytes())))
}

/// Section names that well-known packers and protectors leave behind.
const PACKER_SECTIONS: [(&str, &str); 14] = [
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("UPX2", "UPX"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    (".petite", "Petite"),
    (".themida", "Themida"),
    (".winlice", "WinLicense"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".MPRESS1", "MPRESS"),
    (".MPRESS2", "MPRESS"),
    (".nsp0", "NsPack"),
    (".enigma1", "Enigma"),
];

pub fn triage(binary: &Binary) -> Triage {
    let image = binary.image_bytes();
    let file = binary.file_bytes();
    let sliced = image.len() != file.len();
    let ((image_hashes, file_hashes), (image_entropy, entropy_profile)) = rayon::join(
        || (hashes(image), sliced.then(|| hashes(file))),
        || {
            let chunk = image.len().div_ceil(PROFILE_POINTS).max(1);
            (entropy(image), image.chunks(chunk).map(entropy).collect())
        },
    );

    // Sections that are not mapped (ELF symbol and string tables) are metadata, not image content.
    let sections: Vec<SectionTriage> = binary
        .sections
        .iter()
        .filter(|section| binary.segment_containing(section.address).is_some())
        .map(|section| {
            let bytes = binary.read_to_segment_end(section.address).unwrap_or_default();
            let bytes = &bytes[..bytes.len().min(section.size as usize)];
            let perms = binary.segment_containing(section.address).map(|segment| segment.perms);
            let perms = perms.map_or_else(
                || "---".to_owned(),
                |perms| {
                    [(perms.read, 'r'), (perms.write, 'w'), (perms.execute, 'x')]
                        .iter()
                        .map(|&(set, letter)| if set { letter } else { '-' })
                        .collect()
                },
            );
            SectionTriage {
                name: section.name.clone(),
                address: section.address,
                size: section.size,
                file_size: bytes.len() as u64,
                kind: section.kind,
                perms,
                entropy: entropy(bytes),
            }
        })
        .collect();
    let overlay = binary.overlay.map(|overlay| OverlayTriage {
        offset: overlay.offset,
        size: overlay.size,
        entropy: entropy(&image[overlay.offset as usize..]),
    });

    let mut triage = Triage {
        image_size: image.len() as u64,
        image_hashes,
        file_size: sliced.then_some(file.len() as u64),
        file_hashes,
        entropy: image_entropy,
        entropy_profile,
        sections,
        overlay,
        imphash: imphash(binary),
        details: binary.details.clone(),
        hints: Vec::new(),
    };
    triage.hints = hints(binary, &triage);
    triage
}

fn hints(binary: &Binary, triage: &Triage) -> Vec<String> {
    let mut hints = Vec::new();
    for section in &triage.sections {
        let executable = section.perms.contains('x') || section.kind == SectionKind::Code;
        if executable && section.file_size >= 512 && section.entropy > HIGH_ENTROPY {
            hints.push(format!(
                "code section {} has entropy {:.2}: packed or encrypted code is likely",
                section.name, section.entropy
            ));
        }
        if section.perms == "rwx" {
            hints.push(format!("section {} is writable and executable", section.name));
        }
        if let Some((_, packer)) = PACKER_SECTIONS.iter().find(|(name, _)| *name == section.name) {
            hints.push(format!("section {} is typical of {packer}", section.name));
        }
    }
    if let Some(entry) = binary.entry
        && !binary.is_code(entry)
    {
        hints.push(format!("entry point {entry:#x} lies outside the code sections"));
    }
    if let Some(overlay) = &triage.overlay {
        hints.push(format!(
            "{} bytes of overlay data at file offset {:#x} (entropy {:.2})",
            overlay.size, overlay.offset, overlay.entropy
        ));
    }
    match &binary.details {
        Details::Pe(details) => {
            let has = |name| details.characteristics.contains(&name);
            if binary.imports.len() < 10 {
                hints.push(format!("only {} imports: packers resolve the rest at run time", binary.imports.len()));
            }
            if !has("aslr") {
                hints.push("no ASLR (DYNAMIC_BASE not set)".to_owned());
            }
            if !has("dep") {
                hints.push("no DEP (NX_COMPAT not set)".to_owned());
            }
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs());
            if u64::from(details.timestamp) > now {
                hints.push(format!(
                    "link timestamp {} lies in the future: a reproducible-build hash or a forged date",
                    details.timestamp_utc
                ));
            }
        }
        Details::Elf(details) => {
            if !details.nx && details.kind != "relocatable" {
                hints.push("executable stack (no PT_GNU_STACK, or it is executable)".to_owned());
            }
            if details.relro == "none" && details.kind != "relocatable" {
                hints.push("no RELRO".to_owned());
            }
            if details.stripped {
                hints.push("stripped: no symbol table".to_owned());
            }
        }
        Details::MachO(details) => {
            if details.flags.contains(&"allow_stack_execution") {
                hints.push("executable stack allowed (MH_ALLOW_STACK_EXECUTION)".to_owned());
            }
            if details.encrypted {
                hints.push("encrypted (LC_ENCRYPTION_INFO cryptid set): code is unreadable until decrypted".to_owned());
            }
            if !details.code_signature && details.file_type != "object" {
                hints.push("not code signed".to_owned());
            }
        }
        Details::None => {}
    }
    hints
}

#[cfg(test)]
mod tests {
    use super::entropy;

    #[test]
    fn entropy_spans_zero_to_eight_bits() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7; 100]), 0.0);
        assert_eq!(entropy(&[0, 1, 0, 1]), 1.0);
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(entropy(&all), 8.0);
    }
}
