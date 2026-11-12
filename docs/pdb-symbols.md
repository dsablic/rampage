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
contract. Names are never sanitized into different names: the reader omits, with a counted warning, any function
whose name several functions share or that is not an identifier, when no decorated public name stands in.

A Microsoft C++ PDB names most functions twice: the procedure record (`S_GPROC32`/`S_LPROC32`) carries the
undecorated qualified name (`geo::Rect::area`, `Box<int>::get`) and the public record (`S_PUB32`) the decorated
linkage name, often with several decorated aliases at one address (scalar and vector deleting destructors). The
reader treats decorated (`?`-prefixed) publics, and x86 C publics that undecorate to the procedure name (`_name`,
`_name@8`, `@name@8`), as aliases rather than conflicts. Each function gets its procedure name when that is a plain
identifier (letters, digits and `_.$@?:`) used by no other function, and otherwise its smallest decorated alias:
templates and operators need characters outside identifiers, and overloads share one undecorated name. A name
that several functions share with no decorated alias to tell them apart names none of them, and a non-identifier
name without one (a local template or lambda) is left out too; the report counts both in warnings instead of
rejecting the PDB. Two different undecorated names at one address still reject it. Names
at undiscovered entries or already-named addresses are preserved; metadata does not invent discovery evidence.
The preview can include names not eligible for application. There is no dedicated UI import action.

The standalone reader reports relative virtual addresses. Image-matched results and the project preview report
checked `ImageBase + RVA` virtual addresses, each in readable, executable, file-backed code.
Section-offset arithmetic is checked before RVA conversion. Matching GUID/age is linkage evidence,
not authentication of the PDB or proof that a name describes the code correctly.

### Checked preview and consent

`Project::preview_pdb_names(path)` returns an opaque, immutable `PdbPreview<'_>` borrowing that exact project.
`Project::apply_pdb_names(&preview)` applies only cached, originally approved pairs that remain eligible.
The receipt cannot outlive its project or be deserialized into a different project. Read-only getters expose
`report`, `approved`, `preserved`, `image_sha256` and `pdb` provenance for inspection.

One capped owned input supplies both PDB parsing and SHA-256. Checked application revalidates the explicit PDB's
provenance/bytes and the original mapped image's backing identity and selected-image digest; it never adopts newly
parsed names as consent. Different/reloaded projects and observable source or PDB changes reject before import.
Concurrent labels and conflicts can shrink the approved set; clearing an originally preserved label/conflict cannot
enlarge it. Successful changes use the same atomic batch and same-process undo behavior.

Checked apply stages refreshed annotation state under the shared log lock. Validation failure leaves its cached
annotations, read cursor and undo/redo state unchanged while preserving external edits already committed to disk;
ordinary refresh can still observe those edits later. This is not rollback of durable or partially appended writes.

This checked API is the consent mechanism intended for a UI, which does not exist yet; the path-based API/CLI/MCP
imports keep their fresh-preview/recomputed-eligibility contract. Checked operation requires available original
backing identity, supported on macOS/Linux. Hashes and metadata checks do not authenticate a PDB, create an atomic filesystem
snapshot, eliminate races after validation, or make all existing mmap readers safe against concurrent truncation.

## Shared tool and MCP

`import_pdb_names` belongs to the `types` group. It requires the loaded PE's `path` and an explicit `pdb` path;
`arch` and embedded-image selectors use the normal binary-tool wrapper. Preview is the default. Only
`"apply": true` requests the whole atomic rename batch.

```json
{"path":"fixture.exe","pdb":"fixture.pdb","apply":false,"offset":0,"limit":100}
```

`offset` and `limit` page details only; they never select which names apply. The receipt retains identity,
`preview_total`, `applied_total`, `preserved_total`, `warnings_total`, `details_total` and
`whole_apply_succeeded`, even when the page is shortened or empty. `more` / `next_offset` continue details;
`byte_capped` identifies a page shortened to the output budget. Names and warnings can carry explicit text
truncation fields without losing whole-operation counts or status. Results remain valid JSON within 60,000 bytes.

Rejections retain a bounded JSON receipt with `ok: false`, failure status and `whole_apply_succeeded: false`.
Invalid arguments reject the import without edits. Non-string architecture selectors are rejected before
project loading; ordinary tool-argument validation can occur after the project is opened.
Malformed/identity-mismatched PDBs leave annotations unchanged. Undo reverts an applied import as one batch.
Paging a subsequent call recomputes eligibility; it is not a frozen receipt from the previous call.

## CLI

```sh
rampage type import-pdb-names fixture.exe --pdb fixture.pdb
rampage --json type import-pdb-names fixture.exe --pdb fixture.pdb --apply --limit 1
```

Preview is the default; `--apply` requests the same atomic whole-batch transaction as the API/MCP tool. Required PDB and
page arguments are validated before input loading. `--offset` and `--limit` select receipt details, never applied
names. Human output includes counts, identity, whole-apply status and explicit paging/truncation notes. JSON output
uses the same bounded receipt as the shared tool, including on load/import rejection, followed by a failing exit
status. Parser errors retain ordinary CLI argument-error behavior.
The shared JSON request requires a UTF-8 PDB path; an unrepresentable native path is rejected before project loading
with the same bounded failure receipt. This does not restrict the native PE operand's path encoding.

Global architecture and embedded-image selectors apply only to the PE operand. Existing annotation logs are
opened normally; this is distinct from automatic PDB discovery, which is disabled. Names persist in the
annotation log, but undo history is process-local: another API/MCP/UI instance cannot undo the exited CLI's import.
The CLI has no separate undo verb. Imports made through a persistent API/MCP project have one undo step in that
project's process; reopening the same annotation log restores values, not prior undo history.

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
