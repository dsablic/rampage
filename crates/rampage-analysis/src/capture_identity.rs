use rampage_loaders::{Binary, Format};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize)]
pub struct CaptureIdentity {
    pub schema: &'static str,
    pub sha256: String,
}

fn text(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value.as_bytes());
}

/// Content identity for validated capture mappings and analysis context, not an execution or authenticity proof.
pub fn capture_identity(binary: &Binary) -> Option<CaptureIdentity> {
    if binary.format != Format::Snapshot {
        return None;
    }
    let schema = "rampage-capture-identity-v1";
    let mut hash = Sha256::new();
    text(&mut hash, schema);
    text(&mut hash, &binary.arch.to_string());
    let target = binary.target();
    hash.update([u8::from(target.big_endian), u8::from(target.data_big_endian)]);
    hash.update([u8::from(binary.snapshot_target.is_some())]);
    if let Some(context) = &binary.snapshot_target {
        text(
            &mut hash,
            match context.platform {
                rampage_loaders::snapshot::SnapshotPlatform::Default => "default",
                rampage_loaders::snapshot::SnapshotPlatform::Darwin => "darwin",
                rampage_loaders::snapshot::SnapshotPlatform::Windows => "windows",
            },
        );
        hash.update([u8::from(context.compiler.is_some())]);
        if let Some(compiler) = &context.compiler {
            text(&mut hash, compiler);
        }
    }
    let mut regions: Vec<_> = binary.segments.iter().collect();
    regions.sort_by_key(|region| region.address);
    hash.update((regions.len() as u64).to_be_bytes());
    for region in regions {
        hash.update(region.address.to_be_bytes());
        hash.update(region.size.to_be_bytes());
        hash.update(region.file_size.to_be_bytes());
        hash.update([u8::from(region.perms.read), u8::from(region.perms.write), u8::from(region.perms.execute)]);
        let offset = usize::try_from(region.file_offset).ok()?;
        let size = usize::try_from(region.file_size).ok()?;
        hash.update(binary.image_bytes().get(offset..offset.checked_add(size)?)?);
    }
    let mut modes = binary.thumb.clone();
    modes.sort_by_key(|range| range.start);
    hash.update((modes.len() as u64).to_be_bytes());
    for range in modes {
        hash.update(range.start.to_be_bytes());
        hash.update(range.end.to_be_bytes());
    }
    let mut seeds = binary.function_starts.clone();
    seeds.sort_unstable();
    seeds.dedup();
    hash.update((seeds.len() as u64).to_be_bytes());
    for address in seeds {
        hash.update(address.to_be_bytes());
    }
    hash.update([u8::from(binary.entry.is_some())]);
    if let Some(entry) = binary.entry {
        hash.update(entry.to_be_bytes());
    }
    let mut modules: Vec<_> = binary
        .snapshot_modules
        .iter()
        .map(|module| {
            Some((
                rampage_loaders::snapshot::canonical_module_identity(&module.uuid),
                rampage_loaders::snapshot::address(&module.image_base).ok()?,
                rampage_loaders::snapshot::address(&module.runtime_base).ok()?,
            ))
        })
        .collect::<Option<Vec<_>>>()?;
    modules.sort();
    hash.update((modules.len() as u64).to_be_bytes());
    for (uuid, image, runtime) in modules {
        text(&mut hash, &uuid);
        hash.update(image.to_be_bytes());
        hash.update(runtime.to_be_bytes());
    }
    Some(CaptureIdentity { schema, sha256: rampage_arch::hex::bytes(&hash.finalize()) })
}
