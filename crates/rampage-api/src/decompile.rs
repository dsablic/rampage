//! C decompilation of a function, through the embedded Ghidra decompiler (`rampage-decompiler`). The decompiler
//! is built once per project over its executable segments and reused for every function.

use rampage_decompiler::{Decompiler, MemoryRegion};
use serde::Serialize;

use crate::{ApiError, Project};

#[derive(Debug, Serialize)]
pub struct Decompilation {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
    /// The decompiled function as C source.
    pub code: String,
}

impl Project {
    /// Decompiles the function containing `address` to C using bundled processor specifications.
    pub fn decompile(&self, address: u64) -> Result<Decompilation, ApiError> {
        let start = self.function_containing(address)?.unwrap_or(address);
        if self.binary.code_from(start).is_none() {
            return Err(ApiError::Invalid("decompilation requires a file-backed code address".to_owned()));
        }
        let name = self.function_name(start);

        let mut slot = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        if slot.is_none() {
            *slot = Some(self.build_decompiler()?);
        }
        let decompiler = slot.as_mut().expect("just built");
        let thumb = self.binary.arch == rampage_arch::Arch::Arm && self.binary.target().is_thumb(start);
        let code =
            decompiler.decompile(start, &name, thumb).map_err(|error| ApiError::Unavailable(error.to_string()))?;
        Ok(Decompilation { address: start, name, code })
    }

    /// Builds a decompiler over the program's loadable segments and registers the names rampage knows, so calls
    /// render by name. Read-only segments are mapped read-only so strings and constant pointers fold into output.
    fn build_decompiler(&self) -> Result<Decompiler, ApiError> {
        let binary = &self.binary;
        let mut regions = Vec::new();
        for segment in &binary.segments {
            if segment.size == 0 || !(segment.perms.read || segment.perms.execute) {
                continue;
            }
            let region = |base, bytes, size| MemoryRegion {
                base,
                bytes,
                size,
                readable: segment.perms.read,
                writable: segment.perms.write,
                executable: segment.perms.execute,
            };
            let bytes = if segment.file_size == 0 {
                &[][..]
            } else {
                binary.read_to_segment_end(segment.address).unwrap_or(&[])
            };
            let zero_fill = binary.format != rampage_loaders::Format::Snapshot;
            if bytes.len() as u64 == segment.file_size {
                let size = if zero_fill { segment.size } else { segment.file_size };
                if size != 0 {
                    regions.push(region(segment.address, bytes, size));
                }
                continue;
            }
            if !bytes.is_empty() {
                regions.push(region(segment.address, bytes, bytes.len() as u64));
            }
            if segment.file_size < segment.size && zero_fill {
                let base = segment
                    .address
                    .checked_add(segment.file_size)
                    .ok_or_else(|| ApiError::Invalid("zero-fill mapping overflows".to_owned()))?;
                regions.push(region(base, &[], segment.size - segment.file_size));
            }
        }
        // A segment can hold more than code (a Mach-O __TEXT starts with headers), so require an executable
        // segment rather than one that begins at code.
        if !binary.segments.iter().any(|segment| segment.perms.execute && segment.file_size > 0) {
            return Err(ApiError::Unavailable("no executable segments to decompile".to_owned()));
        }
        let mut decompiler = Decompiler::open_regions(binary.arch, binary.big_endian, &regions)
            .map_err(|error| ApiError::Unavailable(error.to_string()))?;

        // Known function names (analysis starts and named import stubs, with any user renames) so calls render
        // by name rather than by address.
        let mut names: Vec<String> = Vec::new();
        if let Ok(analysis) = self.analysis() {
            for function in &analysis.program.functions {
                let name = self.function_name(function.address);
                decompiler.add_symbol(function.address, &name);
                names.push(name);
            }
        }
        // Apply library prototypes to the symbols just registered, so their calls show typed, readable arguments.
        for name in names {
            if let Some(prototype) = rampage_decompiler::c_prototype(&name) {
                let _ = decompiler.parse_c(&prototype);
            }
        }
        Ok(decompiler)
    }
}
