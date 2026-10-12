//! Capability detection over a binary's imports and strings (see `rampage-capabilities`).

use rampage_capabilities::Capability;

use crate::Project;

impl Project {
    /// Likely behaviors of the binary, inferred from the names it imports and the strings it contains. This is
    /// triage evidence, not proof that the behavior executes.
    pub fn capabilities(&self) -> Vec<Capability> {
        let (imports, strings) = self.capability_inputs();
        rampage_capabilities::detect(&imports, &strings)
    }

    /// The imports and strings fed to capability detection. Imports and import slots name dynamically linked
    /// behavior; function symbols cover statically linked code (a static binary has `connect` as a symbol, not
    /// an import). The string scan is the cached default-length one, not a fresh rescan.
    pub(crate) fn capability_inputs(&self) -> (Vec<String>, Vec<String>) {
        let binary = &self.binary;
        let imports: Vec<String> = binary
            .imports
            .iter()
            .map(|import| import.name.clone())
            .chain(binary.import_slots.iter().map(|slot| slot.name.clone()))
            .chain(
                binary
                    .symbols
                    .iter()
                    .filter(|symbol| symbol.kind == rampage_loaders::SymbolKind::Function)
                    .map(|symbol| symbol.name.clone()),
            )
            .collect();
        let strings: Vec<String> = self.scanned_strings().iter().map(|string| string.text.clone()).collect();
        (imports, strings)
    }
}
