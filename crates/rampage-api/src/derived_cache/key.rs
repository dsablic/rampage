use std::io::{self, Write};
use std::ops::Range;

use rampage_arch::{Arch, Target};
use rampage_loaders::{Embedded, Export, Format, Import, ImportSlot, Section, Segment, Symbol};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{
    ApiError, FunctionInventoryCacheKey, Project, ProjectWorkspaceTaskControl, backing, borrow_held_annotations,
    invalid,
};

const INPUT_BYTES: usize = 256 * 1024 * 1024;
const ITEMS: usize = 65_536;
const NAME_BYTES: usize = 1024 * 1024;

#[derive(Serialize)]
struct Context<'a> {
    format: Format,
    architecture: Arch,
    entry: Option<u64>,
    embedded: Option<Embedded>,
    image: Range<usize>,
    segments: &'a [Segment],
    sections: &'a [Section],
    symbols: &'a [Symbol],
    imports: &'a [Import],
    import_slots: &'a [ImportSlot],
    exports: &'a [Export],
    function_starts: &'a [u64],
    slices: &'a [Arch],
    code_ranges: &'a [Range<u64>],
    rebases: &'a [(u64, u64)],
    code_big_endian: bool,
    data_big_endian: bool,
    thumb: &'a [Range<u64>],
    m_profile: bool,
    global_pointer: Option<u64>,
    got_address: Option<u64>,
    got_entries: &'a [u64],
    loader_names_sha256: String,
}

#[derive(Default)]
struct Budget {
    items: usize,
    bytes: usize,
}

impl Budget {
    fn items(&mut self, count: usize) -> Result<(), ApiError> {
        self.items = self.items.checked_add(count).ok_or_else(|| invalid("inventory key item budget exceeded"))?;
        if self.items > ITEMS {
            return Err(invalid("inventory key item budget exceeded"));
        }
        Ok(())
    }

    fn text(&mut self, text: &str) -> Result<(), ApiError> {
        self.items(1)?;
        self.bytes = self.bytes.checked_add(text.len()).ok_or_else(|| invalid("inventory key name budget exceeded"))?;
        if text.len() > 4096 || self.bytes > NAME_BYTES {
            return Err(invalid("inventory key name budget exceeded"));
        }
        Ok(())
    }
}

pub(super) fn dependency_key(
    project: &Project,
    control: &ProjectWorkspaceTaskControl<'_>,
) -> Result<FunctionInventoryCacheKey, ApiError> {
    control.check()?;
    backing(project)?;
    let binary = &project.binary;
    let mut budget = Budget::default();
    let (image, code_ranges, rebases) = binary.inventory_source_context();
    for count in [
        binary.segments.len(),
        binary.sections.len(),
        binary.symbols.len(),
        binary.imports.len(),
        binary.import_slots.len(),
        binary.exports.len(),
        binary.function_starts.len(),
        binary.slices.len(),
        binary.thumb.len(),
        code_ranges.len(),
        rebases.len(),
        project.inventory_loader_names().len(),
    ] {
        budget.items(count)?;
    }
    for segment in &binary.segments {
        budget.text(&segment.name)?;
    }
    for section in &binary.sections {
        budget.text(&section.name)?;
    }
    for symbol in &binary.symbols {
        budget.text(&symbol.name)?;
    }
    for import in &binary.imports {
        budget.text(&import.name)?;
        if let Some(library) = &import.library {
            budget.text(library)?;
        }
    }
    for slot in &binary.import_slots {
        budget.text(&slot.name)?;
        if let Some(library) = &slot.library {
            budget.text(library)?;
        }
    }
    for export in &binary.exports {
        budget.text(&export.name)?;
    }
    for (_, name) in project.inventory_loader_names() {
        budget.text(name)?;
    }
    let Target { arch: _, big_endian, data_big_endian, thumb, global_pointer, got, m_profile } = binary.target();
    let got_entries = got.as_ref().map_or(&[][..], |got| got.entries.as_ref());
    budget.items(got_entries.len())?;
    if binary.file_bytes().len() > INPUT_BYTES || binary.image_bytes().len() > INPUT_BYTES {
        return Err(invalid("inventory source byte budget exceeded"));
    }
    let annotation_names: Vec<_> = {
        let annotations = borrow_held_annotations(project, control)?;
        budget.items(annotations.names().len())?;
        for name in annotations.names().values() {
            budget.text(name)?;
        }
        annotations.names().iter().map(|(&address, name)| (address, name.clone())).collect()
    };
    let names_sha256 = digest_names(annotation_names.iter().map(|(address, name)| (*address, name.as_str())));
    control.check()?;
    backing(project)?;
    let embedded = binary
        .embedded
        .filter(|embedded| embedded.offset != 0 || embedded.trailing != 0 || embedded.size != embedded.file_size);
    let context = Context {
        format: binary.format,
        architecture: binary.arch,
        entry: binary.entry,
        embedded,
        image,
        segments: &binary.segments,
        sections: &binary.sections,
        symbols: &binary.symbols,
        imports: &binary.imports,
        import_slots: &binary.import_slots,
        exports: &binary.exports,
        function_starts: &binary.function_starts,
        slices: &binary.slices,
        code_ranges,
        rebases,
        code_big_endian: big_endian,
        data_big_endian,
        thumb: &thumb,
        m_profile,
        global_pointer,
        got_address: got.as_ref().map(|got| got.address),
        got_entries,
        loader_names_sha256: digest_names(project.inventory_loader_names()),
    };
    let mut writer = HashWriter { hash: Sha256::new(), remaining: 8 * NAME_BYTES };
    serde_json::to_writer(&mut writer, &context).map_err(|_| invalid("inventory context budget exceeded"))?;
    let context_sha256 = rampage_arch::hex::bytes(&writer.hash.finalize());
    backing(project)?;
    let hashes = (|| {
        let source = digest_bytes(binary.file_bytes(), control)?;
        backing(project)?;
        let image = digest_bytes(binary.image_bytes(), control)?;
        Ok::<_, ApiError>((source, image))
    })();
    let after_hashing = backing(project);
    control.check()?;
    let (source_sha256, image_sha256) = hashes?;
    after_hashing?;
    control.check()?;
    Ok(FunctionInventoryCacheKey {
        source_sha256,
        image_sha256,
        context_sha256,
        names_sha256,
        decoder: "rampage-decoder-target-v1".into(),
        discovery: "rampage-recursive-global-noreturn-v1".into(),
        naming: "rampage-default-namer-rendered-v1".into(),
    })
}

fn digest_names<'a>(names: impl Iterator<Item = (u64, &'a str)>) -> String {
    let mut hash = Sha256::new();
    hash.update(b"FunctionInventoryCacheV0.names\0");
    for (address, name) in names {
        hash.update(address.to_le_bytes());
        hash.update((name.len() as u64).to_le_bytes());
        hash.update(name.as_bytes());
    }
    rampage_arch::hex::bytes(&hash.finalize())
}

fn digest_bytes(bytes: &[u8], control: &ProjectWorkspaceTaskControl<'_>) -> Result<String, ApiError> {
    if bytes.len() > INPUT_BYTES {
        return Err(invalid("inventory source byte budget exceeded"));
    }
    let mut hash = Sha256::new();
    for chunk in bytes.chunks(1024 * 1024) {
        control.check()?;
        hash.update(chunk);
    }
    Ok(rampage_arch::hex::bytes(&hash.finalize()))
}

struct HashWriter {
    hash: Sha256,
    remaining: usize,
}

impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.remaining {
            return Err(io::Error::other("inventory context byte budget exceeded"));
        }
        self.remaining -= bytes.len();
        self.hash.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
