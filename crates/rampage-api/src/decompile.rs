//! C decompilation of a function, through the embedded Ghidra decompiler (`rampage-decompiler`). The decompiler
//! is built once per project over its executable segments and reused for every function.

use rampage_decompiler::{Decompiler, Segment};
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
    /// Decompiles the function containing `address` to C. Requires a local Ghidra install for the processor
    /// specifications; see `rampage-decompiler`.
    pub fn decompile(&self, address: u64) -> Result<Decompilation, ApiError> {
        let start = self.function_containing(address)?.unwrap_or(address);
        let name = self.function_name(start);

        let mut slot = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        if slot.is_none() {
            *slot = Some(self.build_decompiler()?);
        }
        let decompiler = slot.as_mut().expect("just built");
        let code = decompiler.decompile(start, &name).map_err(|error| ApiError::Unavailable(error.to_string()))?;
        Ok(Decompilation { address: start, name, code })
    }

    /// Builds a decompiler over the program's loadable segments and registers the names rampage knows, so calls
    /// render by name. Read-only segments are mapped read-only so strings and constant pointers fold into output.
    fn build_decompiler(&self) -> Result<Decompiler, ApiError> {
        let binary = &self.binary;
        let owned: Vec<(u64, Vec<u8>, bool)> = binary
            .segments
            .iter()
            .filter(|segment| segment.file_size > 0)
            .filter_map(|segment| {
                let bytes = binary.read(segment.address, segment.file_size)?.to_vec();
                Some((segment.address, bytes, segment.perms.write))
            })
            .collect();
        if !owned.iter().any(|(address, _, _)| binary.is_code(*address)) {
            return Err(ApiError::Unavailable("no code segments to decompile".to_owned()));
        }
        let segments: Vec<Segment> =
            owned.iter().map(|(base, bytes, writable)| Segment { base: *base, bytes, writable: *writable }).collect();
        let mut decompiler = Decompiler::open(binary.arch, binary.big_endian, &segments)
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
