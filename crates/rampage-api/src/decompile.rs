//! C decompilation of a function, through the embedded Ghidra decompiler (`rampage-decompiler`). The decompiler
//! is built once per project over its executable segments and reused for every function.

mod context;
mod image;

use rampage_decompiler::{Decompiler, DecompilerOptions, Platform};
use serde::Serialize;

use crate::{ApiError, Project};

#[derive(Debug, Serialize)]
pub struct Decompilation {
    #[serde(serialize_with = "rampage_arch::hex::address")]
    pub address: u64,
    pub name: String,
    /// The decompiled function as C source.
    pub code: String,
    /// Exact processor/compiler specification used for this result.
    pub language_id: String,
}

#[derive(Default)]
pub(crate) struct DecompilerState {
    options: Option<DecompilerOptions>,
    engine: Option<Decompiler>,
}

fn default_options(binary: &rampage_loaders::Binary) -> DecompilerOptions {
    let platform = match binary.format {
        rampage_loaders::Format::Pe => Platform::Windows,
        rampage_loaders::Format::MachO => Platform::Darwin,
        rampage_loaders::Format::Elf | rampage_loaders::Format::Snapshot => Platform::Default,
    };
    DecompilerOptions { platform, compiler: None }
}

impl Project {
    /// Overrides automatic format-based compiler selection. `None` restores automatic selection.
    /// Invalid specifications return an error on the next decompilation, never fall back silently.
    pub fn set_decompiler_options(&self, options: Option<DecompilerOptions>) {
        let mut state = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        state.engine = None;
        state.options = options;
    }

    /// Decompiles the function containing `address` to C using bundled processor specifications.
    pub fn decompile(&self, address: u64) -> Result<Decompilation, ApiError> {
        let start = self.function_containing(address)?.unwrap_or(address);
        if self.binary.code_from(start).is_none() {
            return Err(ApiError::Invalid("decompilation requires a file-backed code address".to_owned()));
        }
        let name = self.function_name(start);

        let mut slot = self.decompiler.lock().unwrap_or_else(|poison| poison.into_inner());
        if slot.engine.is_none() {
            let options = slot.options.clone().unwrap_or_else(|| default_options(&self.binary));
            slot.engine = Some(self.build_decompiler(&options)?);
        }
        let decompiler = slot.engine.as_mut().expect("just built");
        let thumb = if self.binary.arch == rampage_arch::Arch::Arm {
            context::mode_at(&self.binary.target(), &self.analysis()?.program.code_modes, start)
        } else {
            false
        };
        let code =
            decompiler.decompile(start, &name, thumb).map_err(|error| ApiError::Unavailable(error.to_string()))?;
        Ok(Decompilation { address: start, name, code, language_id: decompiler.language_id().to_owned() })
    }

    /// Builds a decompiler over the program's loadable segments and registers the names rampage knows, so calls
    /// render by name. Read-only segments are mapped read-only so strings and constant pointers fold into output.
    fn build_decompiler(&self, options: &DecompilerOptions) -> Result<Decompiler, ApiError> {
        let binary = &self.binary;
        let regions = image::regions(binary)?;
        // A segment can hold more than code (a Mach-O __TEXT starts with headers), so require an executable
        // segment rather than one that begins at code.
        if !binary.segments.iter().any(|segment| segment.perms.execute && segment.file_size > 0) {
            return Err(ApiError::Unavailable("no executable segments to decompile".to_owned()));
        }
        let mut decompiler = Decompiler::open_with_options(binary.arch, binary.big_endian, &regions, options)
            .map_err(|error| ApiError::Unavailable(error.to_string()))?;
        if binary.arch == rampage_arch::Arch::Arm {
            let modes = context::arm_points(binary, &self.analysis()?.program.code_modes);
            decompiler.set_code_modes(&modes).map_err(|error| ApiError::Unavailable(error.to_string()))?;
        }

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
            if let Some(prototype) = decompiler.c_prototype(&name) {
                let _ = decompiler.parse_c(&prototype);
            }
        }
        Ok(decompiler)
    }
}
