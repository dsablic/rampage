//! Mach-O load-command access shared by the loaders.

use object::Endianness;
use object::read::macho::{LoadCommandIterator, LoadCommandVariant};

pub(crate) fn load_commands<'data>(
    parsed: &object::File<'data>,
) -> Option<(LoadCommandIterator<'data, Endianness>, Endianness)> {
    match parsed {
        object::File::MachO32(file) => Some((file.macho_load_commands().ok()?, file.endian())),
        object::File::MachO64(file) => Some((file.macho_load_commands().ok()?, file.endian())),
        _ => None,
    }
}

/// The install names of the linked dylibs in load-command order, which is how bind ordinals (counted from 1)
/// refer to them. `None` marks a name that cannot be read, keeping later ordinals aligned.
pub(crate) fn dylibs(parsed: &object::File) -> Vec<Option<String>> {
    let mut dylibs = Vec::new();
    let Some((mut commands, endian)) = load_commands(parsed) else { return dylibs };
    while let Ok(Some(command)) = commands.next() {
        if let Ok(LoadCommandVariant::Dylib(dylib)) = command.variant() {
            let name = command.string(endian, dylib.dylib.name).ok();
            dylibs.push(name.map(|name| String::from_utf8_lossy(name).into_owned()));
        }
    }
    dylibs
}
