# Embedded debug signature import

`rampage type import-debug IMAGE` previews scalar/pointer function signatures from embedded ELF or Mach-O DWARF.
`--apply` persists accepted signatures without replacing existing analyst signatures. JSON output includes
preview declarations, applied/preserved addresses and bounded diagnostics. Preview does not run native declaration
validation; application validates the merged annotation snapshot before appending entries.

Supported signatures expand scalar typedefs by encoding/byte width, ordinary pointers, parameter names and
variadic markers. Native parser type names are sanitized. `const` erasure is reported; volatile/restrict
signatures are skipped because those qualifiers are not preserved by the native declaration parser.

Aggregate layouts, callbacks, recursive/nested pointer types, unsupported scalar encodings, compressed/split
DWARF and external PDB/dSYM files are not inferred. Relocatable-object DWARF addresses are not imported.
Unsupported types skip the complete dependent signature. Conflicting declarations at one address are skipped;
no signature is rebound from a debug entry to another containing function.

Preview is read-only. Application validates the merged snapshot under the shared annotation log lock; existing
signatures remain untouched. Multiple imported entries are recorded individually and can be undone separately.
The log's room for every signature is checked before the first append, so a size-limit refusal applies none. An
I/O failure during append can still leave earlier validated entries applied; import is not a single atomic edit.

Limits include 64 MiB total debug-section bytes, 256 units, one million DIEs, bounded attributes/nesting, 1,024-byte
identifiers, 4,095-byte parser lines and 65,536-byte declarations. These limits do not guarantee semantic
equivalence or complete source recovery.

The `import_debug_signatures` API/MCP tool uses the same preview/apply behavior. A configured worker performs
native signature validation out of process.
The legacy `debug-types` CLI spelling remains accepted.

[Checked flat-struct pointer import](debug-layout-import.md) is a separate library API with frozen consent,
persistent layout assertions and whole-batch type/signature application. It does not widen this importer.
