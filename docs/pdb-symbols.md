# PDB function-name import reference

PDB import reads an explicitly supplied MSF 7 PDB and matches its GUID and age to the loaded PE image's unique
RSDS record. It imports names only, not types, signatures, calling conventions, object layouts or new function
starts. No sidecar is opened automatically, and a path recorded in CodeView metadata is not followed.

## API

`Project::import_pdb_names(path, apply)` returns an identity-checked preview, applied virtual addresses and
preserved addresses. `apply: false` writes no annotations. `apply: true` records eligible renames atomically as
one undoable annotation batch, preserving existing user, symbol, export and entry labels. Concurrent clients'
annotations are refreshed under the shared log lock before application.

Eligibility requires an already-discovered function entry and an unused name valid for the annotation identifier
contract. Ambiguous or invalid names reject the import rather than being sanitized into different names. Names
at undiscovered entries or already-named addresses are preserved; metadata does not invent discovery evidence.
The preview can include names not eligible for application. CLI/MCP/UI import exposure remains separate.

The standalone reader reports relative virtual addresses. Image-matched results and the project preview report
checked `ImageBase + RVA` virtual addresses, each in readable, executable, file-backed code.
Section-offset arithmetic is checked before RVA conversion. Matching GUID/age is linkage evidence,
not authentication of the PDB or proof that a name describes the code correctly.

## Limits and errors

- Explicit input: regular file, at most 64 MiB, with a complete MSF 7 page layout. Unix opens are nonblocking
  and refuse symlinks; the opened descriptor is validated before reading.
- MSF preflight: 64 MiB aggregate advertised stream bytes, 4 MiB directory, 32,768 streams, 262,144 page references
  and 4,000,000 structural-work units, checked before entering parser allocation paths.
- At most 10,000 modules, 1,000,000 symbol records and 100,000 distinct function RVAs.
  Raw record counting includes skipped alignment/skip records; at most 4,096 sections are admitted.
- Names: valid UTF-8, at most 4,096 bytes each and 16 MiB of retained name bytes.
- Shared preflight/source-read budget: 256 MiB; checked offsets and allocations stop range/size amplification.
- Missing or ambiguous RSDS identity, GUID/age mismatch, conflicting names, malformed required records,
  exhausted limits, address overflow and non-code/unbacked RVAs reject the whole report. No partial names apply.

Unsupported symbol kinds can be skipped; unused type/layout streams are not a general integrity audit. A report
with no names does not establish that the file contains no functions. The conventional sidecar-path helper only
suggests a filename; it neither opens the file nor establishes identity.
OMAP and original-section remapping are explicitly unsupported rather than passed through unchecked conversion.

## Acceptance scope

The controlled fixture is a freestanding Windows x64 PE/PDB pair compiled from owned Apache-2.0 C with LLVM/LLD
22.1.8. Repeated generation is byte-identical with that toolchain and normalizes debug build paths. Regressions
cover identity mismatch, malformed/truncated input, address validity, preservation, atomic application and undo.
This is not acceptance of all PDB producers, C++ naming forms, architectures or debug layouts.
