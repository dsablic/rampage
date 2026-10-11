# Embedded debug signature import

`rampage debug-types IMAGE` previews scalar/pointer function signatures from embedded ELF or Mach-O DWARF.
`--apply` persists accepted signatures without replacing existing analyst signatures. JSON output includes
accepted declarations, applied/preserved addresses and bounded diagnostics.

Supported signatures expand scalar typedefs by encoding/byte width, ordinary pointers, parameter names and
variadic markers. Native parser type names are sanitized. `const` erasure is reported; volatile/restrict
signatures are skipped because those qualifiers are not preserved by the native declaration parser.

Aggregate layouts, callbacks, recursive/nested pointer types, unsupported scalar encodings, compressed/split
DWARF and external PDB/dSYM files are not inferred. Unsupported types skip the complete dependent signature.
No signature is rebound from a debug entry to another containing function.

Preview is read-only. Application validates the merged snapshot under the shared annotation log lock; existing
signatures remain untouched. Multiple imported entries are recorded individually and can be undone separately.
An I/O failure during append can leave earlier validated entries applied; import is not a single atomic edit.

Limits include 64 MiB debug sections, 256 units, one million DIEs, bounded attributes/nesting, 1,024-byte
identifiers, 4,095-byte parser lines and 65,536-byte declarations. These limits do not guarantee semantic
equivalence or complete source recovery.

The `import_debug_signatures` API/MCP tool uses the same preview/apply behavior. A configured worker performs
native signature validation out of process.
