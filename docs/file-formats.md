# File formats

How rampage reads the build metadata, archives, modules and managed assemblies it reports on, and the bounds it
keeps. The [feature overview](features.md#file-formats) summarises these areas; the [MCP reference](mcp.md) and the
[CLI reference](cli-reference.md) list the tools and commands.

## Toolchain build info

`binary build-info` and the MCP tool `build_info` read the build metadata toolchains embed, which survives
stripping:

- Go build info (what `go version -m` prints) from `.go.buildinfo` (ELF), `__go_buildinfo` (Mach-O), or a
  16-byte aligned scan of the writable data sections (PE, or images without the section), as Go's
  `debug/buildinfo` does: a magic in read-only data is a constant, not a record, and a candidate that does not
  decode (its version must start with `go` or `devel`) does not hide a later one. Both the go1.18+ inline layout
  and the older pointer layout (resolved through file-backed segments) are read. Output: Go version, main package
  path, main module, dependency modules with `=>` replacements, build settings such as `-compiler`, `CGO_ENABLED`,
  `GOARCH`, `vcs.revision` and `vcs.time`, and whether the version agrees with the pclntab layout the loader found.
- Rust dependency lists that [cargo-auditable](https://github.com/rust-secure-code/cargo-auditable) embeds in a
  `.dep-v0` section (`__DATA,.dep-v0` on Mach-O): zlib-compressed JSON, decompressed under its documented 8 MiB
  cap. Output: root package(s) and every package's name, version, source, kind and dependency indices, and the
  zlib stream's length (`compressed_bytes`, without the section's padding).

Each record is absent, present, or found but unreadable (with a reason); malformed lines and dangling indices are kept
as warnings. Dependency modules and packages are paged, each page also fitted to the 60,000-byte result; build
settings and up to 16 roots are listed within byte shares, with their totals. The data is self-reported by the build
and is not verified against code; there is no vulnerability lookup.

## PyInstaller archives and WebAssembly modules

`binary pyinstaller-archive` and the `pyinstaller_archive` file tool find a PyInstaller CArchive by its cookie
(`MEI\x0c\x0b\x0a\x0b\x0e`), searching back through the file's last 8 MiB so a signature appended after the archive
is stepped over. Both the 24-byte pre-2.1 cookie and the 88-byte cookie with the Python library name are read. The
result has the cookie offset and layout, the package and TOC extents, the Python version (312 is 3.12) and library,
per-typecode counts and paged TOC entries: record and data file offsets, compressed and uncompressed sizes,
compression flag, typecode and its meaning (script, module, package, PYZ, zipfile, binary, data, runtime option,
dependency, nested package, splash, symlink) and name. An uncompressed PYZ entry's header gives the pyc magic and
its Python version; the PYZ TOC is not decompressed. Magic matches that do not validate (a bootloader holds the
magic as a constant) are skipped, and when none validates the result is `archive: null` with each rejected
candidate's reason rather than an error; the walk stops at a malformed TOC record with a warning. Nothing is extracted,
decompressed, decrypted or decompiled: hand the data offsets to `decode_file_range` or `carve`.

`binary wasm-module` and the `wasm_module` file tool summarise a core WebAssembly module with `wasmparser`: header
version and layer, up to 64 sections with offsets and sizes, index-space counts (types, imports, functions, tables,
memories, globals, tags, exports, data and element segments), the start function, custom-section names, the `name`
section's module name and the `producers` section. `list` pages imports (module, name, kind, type), exports (name,
kind, index) or functions (imports first, with type signature, body offset and size, and `name`-section name).
Project loading accepts native executables only and rejects `.wasm`, so these work on the raw file without a
Project. A component-model binary (layer 1) is reported as unsupported without reading its sections. Parsing is
bounded (1,048,576 decoded items, 65,536 retained per list, names cut at 256 bytes); malformed input returns what
parsed before the error with `complete` false and the error offset in `limitations`. Limitations list the first
of each kind (at most 32) and count repeats, and sections count against the decode budget, so a file of millions of
unknown sections stays cheap. Modules are not validated,
compiled, executed or disassembled.

## PE resources and load config

`binary pe-resources` and the `pe_resources` MCP tool list resource directory leaves: type (`RT_*` name, `#id` or
string name), name or id, language, data RVA, size, code page, offset in the image and whether the bytes are in the
file. The type/name/language walk stops at 3 levels, 4096 tables, 65,536 entries and 16,384 leaves, and a table
reached twice (a loop or alias) is skipped with a warning. A declared directory size that overruns its section's file
data (packers write these) is ignored, as Windows ignores it, and the tree is read from its RVA. Leaves are counted
per type, keeping numeric and string-named types apart, and filtered by `RT_*` name, bare name, `16` or `#16`; pages
hold whole rows within 60,000 JSON bytes and always decode their first payload. Version resources are decoded into
VS_FIXEDFILEINFO (file/product versions, flags, OS, file type), StringFileInfo key/value pairs per language and code
page, and VarFileInfo translations, within 64 KiB, 1024 nodes and 256 strings. Manifests return up to 16 KiB of UTF-8
text plus `requestedExecutionLevel` and `dependentAssembly` names from a bounded textual scan of the first 64 KiB; it
is not an XML parser. Icons, dialogs, string tables and other payloads are located but not interpreted or extracted.

`binary pe-load-config` and `pe_load_config` read IMAGE_LOAD_CONFIG_DIRECTORY (32- and 64-bit) up to the Size the
structure declares; fields past it are reported absent rather than read. They report the security cookie VA, SafeSEH
handler count and up to 256 handler RVAs (native x86 only: not ARM32 or IL-only .NET), CFG GuardFlags names,
check/dispatch pointers and function table placement, address-taken IAT, long-jump and EH continuation table counts,
and dynamic value relocation table presence. CET flags come from the IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS debug
entry. Findings note where the load config disagrees with the DllCharacteristics mitigations triage reports, such as
CFG instrumentation without `GUARD_CF` or an x86 image with neither SafeSEH nor `NO_SEH`. Table contents other than
SafeSEH handlers, CHPE, hot-patch, enclave and volatile metadata are not decoded.

## MSVC C++ metadata

In x86 and x64 PE images the loader reads the Microsoft C++ ABI's structural metadata once, at load, from
file-backed bytes: every followed address is checked against the image, address arithmetic is checked, every count
is capped, and one image shares one work budget and one retained-memory budget (about 64 MiB) across all of it, so
crafted tables that share a try map or handler array cannot multiply into unbounded work. Running out stops the
read with a warning in both tools. The tables name code that no call reaches, so they also seed function starts:
vftable slots (virtual methods and adjustor thunks), catch and cleanup funclets, x86 exception-handler thunks, and
the destructors and copy constructors of thrown types.

**Validation so far:** clang-cl and lld-link output using `__CxxFrameHandler3` only. MSVC `cl.exe` x64 builds
since Visual Studio 2019 16.3 default to `__CxxFrameHandler4` (`/d2FH4`), whose compressed tables are not decoded
and are counted in `undecoded_handlers`; `cl.exe` x86 places catch blocks inline in the parent function rather
than as separate funclets, which is untested.

- **Vftables** (`class_evidence` fields `vftables_total` and `vftables`, one page of 16 by default, paged with
  `vftable_offset`/`vftable_limit` and bounded to 24,000 JSON bytes): a table is found by the word before slot 0,
  which must point to an RTTI complete object locator whose signature, self reference (x64), type descriptor name
  and class hierarchy validate. Each table reports the demangled class, the locator, the subobject offset
  (non-zero for the tables of a second or virtual base) and up to 64 slot targets; slots run to the first non-code
  word. Classes built without RTTI (`/GR-`) have no locator and are not found.
- **RTTI classes** (`class_evidence` fields `rtti_classes_total` and `rtti_classes`, one page of 50 by default,
  paged with `rtti_class_offset`/`rtti_class_limit` and bounded to 16,000 JSON bytes): each class with a complete
  object locator (`source` `rtti_scan`), then each class that appears only as a base in those classes' hierarchies
  (`rtti_base`): an interface, an abstract class or any base whose vftable was never emitted. Each row lists the
  class's direct bases.
- **Virtual calls in decompilation**: a call through a vfptr, `(**(code **)(*this + 0x10))(this)`, whose object is
  known to point at some of these vftables gets a comment naming the slot and its possible targets
  (`Virtual call: vftable slot 2 (+0x10) -> geo::Rect::perimeter, geo::Circle::perimeter`), never the
  `_purecall` stub of an abstract table. The object is known when it is the `this` of a function in a table's slots
  (the vfptr it reads at any offset from `this` is then the matching table of the same complete class), or when it
  is a pointer typed with a class's name: the demangled name with every run of characters outside C identifiers
  made one `_` (`geo::Shape` is `geo_Shape`, `Box<int>` is `Box_int`), or its last component (`Shape`) when no other
  class shares it. Declare the type (`set_types`, any layout) and use it in a signature or a variable type; it
  matches a table whose vfptr sits at that class's offset 0 in its complete object, through non-virtual bases. When
  every target's own decompilation derives the same parameters, the call takes that prototype, so arguments are
  not dropped; `this` is always passed even to a target that ignores it. On x86, MSVC passes `this` in ECX
  (`__thiscall`), which Ghidra's default for an indirect call leaves out: every vfptr call in an image with
  vftables is given `__thiscall` unless ECX holds something other than the object (a COM `__stdcall` method takes
  `this` on the stack). Bases reached through a virtual base, and constructor-stored vftables in a caller, are not
  used.
- **Exception handling** (`exception_handlers`, formats group, **experimental**: its row shape may change): on x64, the unwind info of each `.pdata` entry
  names its language handler; entries whose handler is the `__CxxFrameHandler3` import (or an unnamed, statically
  linked handler whose data starts with a valid FuncInfo) are grouped by FuncInfo, and the entry that is not one of
  its own funclets is the function. On x86 there is no unwind directory: FuncInfo tables are found by their version
  stamp (`0x19930520`-`0x19930522`) and full validation, and tied to the function that stores the per-function
  handler thunk (`mov eax, FuncInfo; jmp __CxxFrameHandler3`) into its registration record, by `push imm32` (MSVC)
  or `mov [ebp+disp], imm32` (clang-cl). A FuncInfo yields the unwind map (each state's destructor funclet), the
  try blocks with their catch handlers (caught type from its RTTI type descriptor, by-reference and const
  adjectives, catch funclet) and, on x64, the code each try block covers from the IP-to-state map. x64
  `__C_specific_handler` scope tables give `__try` ranges with their filter or `__finally` funclets. `list=throws`
  pages `_ThrowInfo` records: each throw's catchable types, most derived first, with the thrown object's
  destructor and copy constructors. Each row caps its try blocks, catches, code ranges, cleanups and scopes, with
  exact `*_total` counts and `truncated`; type names are cut at 256 bytes. With `function` set, `detail_offset`
  pages that function's try blocks, cleanups and scopes.

Not decoded: `__CxxFrameHandler4` (see above), x86 SEH (`_except_handler3/4`) and ARM64 tables. Funclets become
their own functions, and the continuation addresses a catch funclet returns can appear as small functions inside
their parent, so try/catch structure is reported as evidence beside the decompiled parent rather than inside it.

Owned fixtures built with clang-cl and lld-link (`tests/fixtures/msvc-cpp`, rebuilt by its `build.sh`) pin this
against their PDBs: every PDB procedure and thunk is discovered, all 20 vftables per architecture are found with
every slot resolving to a PDB function, and the four functions with C++ exception state report their three try
blocks, seven catch handlers and seven cleanup funclets.

## Managed assemblies

ECMA-335 metadata includes assembly identity, references, entry point and one paged list:

- `types`: fields, method/property signatures, event types and metadata accessor tokens, plus IL body sizes.
- `pinvokes`: the DLL export bound by each P/Invoke method.
- `attributes`: targets and fixed/named primitive, string, type, single-dimensional array and verified
  local-enum arguments, including boxed values and supported vectors inside `object[]`. Unsupported values report
  errors. An attribute target can be filtered by parent token.
- `resources`: ManifestResource tokens/names/flags, raw offsets and metadata-only implementation links.

One method's CIL can be disassembled ILDasm-style with tokens resolved to names/signatures, `ldstr` literals,
branch/switch labels, locals and exception clauses. Paging counts instructions; an IL label selects the
instruction containing that offset. Metadata and body decoding are bounded against hostile inputs. CIL is
reported as managed code, never treated as native instructions. See
[managed CLI commands](cli-reference.md#managed-code) or MCP tools `dotnet_metadata` and `dotnet_il`.

Events retain tokens, names, flags, bounded type rendering and same-owner add/remove/fire/other method bindings.
EventPtr ordering is preserved; malformed types remain unreadable and invalid ownership is diagnosed. Accessor
bindings are metadata, not proof of accessor behavior. Events do not imply resource or general attribute decoding.

Verified local enum literals can carry optional `enum_constant` field metadata with an underlying integral type
and exact decimal `value` string, including 64-bit extrema. Different named fields may retain equal values as
aliases; duplicate Constant rows for one field invalidate that field's evidence. This requires a verified local
enum owner, matching value-type field signature, appropriate literal flags, and exact Constant type/width/padding.
It works without custom attributes and does not replace numeric attribute values with symbolic names or synthesize
`Flags` combinations.

Enum constants have separate bounds of 100,000 Constant rows, 100,000 owner/field work rows, 10,000 retained
constants and 4 MiB of work/text, with bounded diagnostics. Incomplete or over-limit Constant tables yield no
constant evidence because an unread suffix could contain duplicate parents. External assemblies are not loaded.

Boxed custom-attribute values retain serialized types in their rendered strings, such as `box(int32, 42)`
and `box(int32[], null)`; named arguments keep their declared `object`/`object[]` type. Boxed strings, types and
verified local enums share the depth/node/text/image-work budgets, including failed type/name lookups.
Direct jagged constructor types, unknown/external or assembly-qualified enum resolution, bare `0xFF` object tags
and repeated object tags are unsupported. A failure in named arguments retains only fully charged valid fixed values.

Serialized local enum names use exact canonical reflection spelling: literal `+`, comma, backslash, brackets,
`*` and `&` are escaped with backslashes, while structural nesting uses an unescaped `+`. For example,
`Demo.Mo\+de` names a literal `Mo+de`, not a nested type. Dots, slashes, whitespace, case and Unicode are preserved;
there is no case folding, Unicode normalization, alternate spelling or general type-expression parser.

Only unique local definitions with verified integral widths resolve. Assembly-qualified names remain unsupported,
even when the assembly name appears to match the local image. Invalid/conflicting nesting, cycles, unreadable names
or incomplete identity evidence disable the whole serialized-name index rather than proving partial uniqueness.
Direct numeric enum decoding and constant evidence remain independent when their own evidence and budgets suffice.
Initial nesting scans cap readable rows at 100,000 and reserve eight shared-work units per attempt before reads or
insertion; escape expansion and failed name lookup also consume the decoding budgets. Within these limits,
ordinary ILAsm nested-type display is unaffected.

Resource inventory distinguishes embedded-directory locations, external File/AssemblyRef links, unsupported
ExportedType links and malformed/dangling references. An embedded `readable_location` reports only a checked,
mapped location within a directory that fits one backed section span, not a validated length prefix or payload extent.
No payload, external resource, assembly or named file is opened or interpreted.

Resource inventory attempts at most 100,000 rows with a separate 4 MiB name-work budget; failed lookups and repeated
linked names consume that budget. Names have a 1,024-byte cap, UTF-8-safe truncation markers and explicit flags.
`resource_counts` separates declared/readable/retained/returned rows and reports inventory/name truncation independently
of filtering and pagination. `declared_known` distinguishes an observed zero from an unread declaration count;
`declared: 0` is only a placeholder when that flag is false. A recovered declaration can survive a later header
failure, but such a header still yields no decoded rows. `contains` matches resource or linked File/AssemblyRef names.
