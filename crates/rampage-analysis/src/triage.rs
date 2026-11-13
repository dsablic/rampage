//! A first look at a binary: hashes, entropy, overlay, and hints of packing or weak hardening.

use md5::{Digest, Md5};
use rampage_loaders::{Binary, Details, Embedded, Format, SectionKind};
use serde::Serialize;

use crate::code_integrity::{self, CodeRegion};
use sha1::Sha1;
use sha2::Sha256;

/// Points in the entropy profile across the image.
const PROFILE_POINTS: usize = 64;
/// Entropy (bits per byte) above which code or data is likely compressed or encrypted.
const HIGH_ENTROPY: f64 = 7.2;

#[derive(Debug, Clone, Serialize)]
pub struct Triage {
    /// The image: the whole file, one slice of a universal binary, or an image embedded in a larger file.
    pub image_size: u64,
    pub image_hashes: Hashes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_identity: Option<crate::capture_identity::CaptureIdentity>,
    /// Where the image lies in the outer file, when it was opened at an offset.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embedded: Option<Embedded>,
    /// The whole file's size and hashes, when the image is part of it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_hashes: Option<Hashes>,
    /// Shannon entropy of the image in bits per byte (0-8).
    pub entropy: f64,
    /// Entropy of consecutive equal slices of the image, for spotting packed or encrypted regions.
    pub entropy_profile: Vec<f64>,
    pub sections: Vec<SectionTriage>,
    /// Code regions judged encrypted or packed, with the entropy and decode evidence for each (see
    /// [`crate::code_integrity`]). Discovery does not explore them.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub encrypted_or_packed_code: Vec<CodeRegion>,
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
    /// Offset within the image (the slice, for a universal binary).
    pub offset: u64,
    /// Offset within the whole file.
    pub file_offset: u64,
    pub size: u64,
    pub entropy: f64,
}

/// Shannon entropy in bits per byte, rounded to two decimals.
pub fn entropy(bytes: &[u8]) -> f64 {
    // max(0.0) turns a rounded -0.0 into 0.0.
    ((rampage_loaders::shannon_entropy(bytes) * 100.0).round() / 100.0).max(0.0)
}

fn hashes(bytes: &[u8]) -> Hashes {
    let ((md5, sha1), sha256) = rayon::join(
        || {
            rayon::join(
                || rampage_arch::hex::bytes(&Md5::digest(bytes)),
                || rampage_arch::hex::bytes(&Sha1::digest(bytes)),
            )
        },
        || rampage_arch::hex::bytes(&Sha256::digest(bytes)),
    );
    Hashes { md5, sha1, sha256 }
}

/// Section names that well-known packers and protectors leave behind.
const PACKER_SECTIONS: [(&str, &str); 17] = [
    ("__povertext", "a PACE-style protection wrapper"),
    ("__poverdata", "a PACE-style protection wrapper"),
    ("__pbootstrap", "a PACE-style protection wrapper"),
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

/// [`triage_with_code`], judging code regions with the binary's own decoder.
pub fn triage(binary: &Binary) -> Triage {
    triage_with_code(binary, &code_integrity::assess(binary, || binary.decoder()))
}

/// The first look at `binary`, with `regions` from [`code_integrity::assess`] (measured with whichever decoder the
/// caller analyses with).
pub fn triage_with_code(binary: &Binary, regions: &[CodeRegion]) -> Triage {
    let image = binary.image_bytes();
    let file = binary.file_bytes();
    let sliced = image.len() != file.len();
    let ((image_hashes, file_hashes), (image_entropy, entropy_profile)) = rayon::join(
        || (hashes(image), sliced.then(|| hashes(file))),
        || {
            // Exactly PROFILE_POINTS slices (fewer only for images smaller than that), split as evenly as possible.
            let points = PROFILE_POINTS.min(image.len());
            let slice = |i: usize| &image[i * image.len() / points..(i + 1) * image.len() / points];
            (entropy(image), (0..points).map(|i| entropy(slice(i))).collect())
        },
    );

    let sections: Vec<SectionTriage> = binary
        .sections
        .iter()
        .map(|section| {
            // Measure what the file stores for the section: nothing for zero-fill sections.
            let bytes = binary.section_file_bytes(section).unwrap_or_default();
            // ELF sections that are not loaded (symbol and string tables) have address 0.
            let loaded = section.address != 0 || binary.format != Format::Elf;
            let perms = binary.segment_containing(section.address).filter(|_| loaded).map(|segment| segment.perms);
            let perms = perms.unwrap_or_default().to_string();
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
        file_offset: overlay.file_offset,
        size: overlay.size,
        entropy: entropy(&image[overlay.offset as usize..][..overlay.size as usize]),
    });

    let mut triage = Triage {
        image_size: image.len() as u64,
        image_hashes,
        capture_identity: crate::capture_identity::capture_identity(binary),
        embedded: binary.embedded,
        file_size: sliced.then_some(file.len() as u64),
        file_hashes,
        entropy: image_entropy,
        entropy_profile,
        sections,
        encrypted_or_packed_code: regions.iter().filter(|region| region.verdict.is_some()).cloned().collect(),
        overlay,
        imphash: match &binary.details {
            Details::Pe(pe) => pe.imphash.clone(),
            _ => None,
        },
        details: binary.details.clone(),
        hints: Vec::new(),
    };
    triage.hints = hints(binary, &triage);
    triage
}

fn hints(binary: &Binary, triage: &Triage) -> Vec<String> {
    let mut hints = Vec::new();
    if let Some(embedded) = binary.embedded {
        hints.push(format!(
            "embedded image at offset {:#x} of a {}-byte file: the image hashes cover only the image",
            embedded.offset, embedded.file_size
        ));
        if embedded.trailing > 0 {
            hints.push(format!(
                "{} bytes follow the image in the outer file and were not examined; an image length of {:#x} \
                 (--image-length, or image_length over MCP) takes them in as overlay",
                embedded.trailing,
                embedded.size + embedded.trailing
            ));
        }
    }
    for region in &triage.encrypted_or_packed_code {
        hints.push(format!(
            "code is likely encrypted or packed, so it was not explored for functions: {}",
            region.explain()
        ));
    }
    for section in &triage.sections {
        let executable = section.perms.contains('x') || section.kind == SectionKind::Code;
        let judged = triage.encrypted_or_packed_code.iter().any(|region| region.address == section.address);
        if executable && !judged && section.file_size >= 512 && section.entropy > HIGH_ENTROPY {
            hints.push(format!(
                "code section {} has entropy {:.2}: packed or encrypted code is likely",
                section.name, section.entropy
            ));
        }
        // Mach-O object files put every section in one rwx segment by convention.
        let object_file = matches!(&binary.details, Details::MachO(macho) if macho.file_type == "object");
        if section.perms == "rwx" && !object_file {
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
            overlay.size, overlay.file_offset, overlay.entropy
        ));
    }
    match &binary.details {
        Details::Pe(details) => {
            let has = |name| details.characteristics.contains(&name);
            // .NET assemblies import only mscoree, and EFI images import nothing by design.
            let firmware = details.subsystem.starts_with("efi");
            let unreadable = binary.warnings.iter().any(|warning| warning.contains("import table"));
            if binary.imports.len() < 10 && !details.dotnet && !firmware && !unreadable {
                hints.push(format!("only {} imports: packers resolve the rest at run time", binary.imports.len()));
            }
            if details.dotnet {
                hints.push(".NET assembly: the code is IL in the CLR metadata, not native instructions".to_owned());
            }
            if !has("aslr") && !firmware {
                hints.push("no ASLR (DYNAMIC_BASE not set)".to_owned());
            }
            if !has("dep") && !firmware {
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
