# Module references reference

**Module references…** displays bounded PE import/export declarations among the one to eight modules already
loaded in a [project workspace](project-workspaces.md). It does not discover or open dependencies, run native
analysis, initialize program analysis or invoke the decompiler SDK. There are no corresponding CLI or MCP tools.

## Declaration matching and coverage

The matching policy is `pe-whole-dll-ascii-case-only-exact-symbol-v1`:

- An import's whole raw DLL name matches the producer's `IMAGE_EXPORT_DIRECTORY.Name` using ASCII-only case
  equivalence. Both identities must be nonempty ASCII. No pathname, file basename, label, extension guess,
  Unicode normalization or namespace binding participates. Renaming a provider file does not change this identity.
- Named symbols match exact raw bytes, including case. Names expose `raw_hex` and an optional `display` only when
  the bytes are valid UTF-8. Display text is never a lossy comparison key.
- Regular and delay-import directory provenance remains distinct. Import lookup declarations, not bound IAT
  pointer values or delay stubs, supply names. Unsupported delay-table forms remain explicit coverage limitations.
- Ordinal imports are unsupported. An ordinal 7 and a literal named export `#7` are distinct, not interchangeable.
  Forwarded exports retain their raw declaration but are never followed.
- A direct export can be data. Its address and executable-backing flag do not establish a function entry,
  ownership, ABI, type, layout, call graph or runtime binding. `proven_runtime_flow` and `proven_layout` are false.

| Row status | Meaning |
| --- | --- |
| `declared_link` | One loaded PE producer and one matching direct named export, with complete required coverage |
| `ambiguous` | Multiple matching producer identities or named export declarations; no target is selected |
| `unresolved` | Complete loaded-PE metadata search found no matching direct export |
| `unsupported` | Ordinal, forwarder, unsupported identity, incomplete coverage or exhausted matching work |

A source-module or slot filter narrows displayed imports, not the producer uniqueness search. Every supplied PE
must have complete regular **and** delay-import coverage, including modules that export nothing. Unknown or
incomplete metadata in another supplied PE prevents a unique declaration claim. Positively absent export-directory
metadata with complete zero export coverage needs no producer identity; an unknown directory or a missing producer
name is not the same proof.

ELF, Mach-O, snapshots and owned bytes without original mapped-source proof receive explicit unsupported coverage,
not an empty resolved result or a claim of no exports. Unsupported non-PE modules do not participate as PE
producers. Coverage remains visible even when there are no rows, and the whole report need not be complete merely
because one PE row is a declared link.

## Explicit desktop controls

Right-click **rampage**, then choose **Module references…**. This opens the window only. Opening it, editing fields
or painting historical rows does not read source files. **Apply / Refresh** explicitly runs the query in the
background in the ordinary desktop app.

| Control | Behavior |
| --- | --- |
| **Source module** | All loaded modules or one stable module ID |
| **Source slot (optional 0x)** | Exact 64-bit hexadecimal import-slot address, with a `0x` prefix |
| **Exact UTF-8 substring filter** | Case-sensitive byte substring of the raw DLL or named import, at most 256 bytes |
| **Page size (1–256; default 64)** | Maximum rows requested per page |
| **Apply / Refresh** | Apply current fields at offset zero; no automatic query on edits |
| **Next page** | Explicitly rerun the retained applied query at its returned next offset |
| **Cancel query** | Invalidate pending authority; the execution lease remains held until execution returns |

Paging uses the applied query, not subsequent draft edits, and is not an atomic snapshot across pages. Editing
fields invalidates paging and navigation until another explicit Apply. The current bounded metadata API cannot
be interrupted mid-call: cancellation discards its late result rather than guaranteeing an immediate halt.
Closing the window also invalidates authority; it does not release an executing query's lease early.

Rows include unsuccessful declarations, candidate counts, identity-only candidates, reasons and truncation flags.
Coverage shows metadata origin, regular/delay/export status, producer identity, directory presence, parser work,
limits, omissions and warnings. Matching-work used/limit/exhaustion and lower-bound counts are displayed rather
than converting budget exhaustion into a fake unique match.

**Inspect source slot** navigates to raw memory in the qualified source module. **Inspect direct target** exists
only for a `declared_link` direct candidate. Neither action automatically decompiles, discovers functions or starts
global analysis. The address remains a memory-navigation candidate, even when it has executable backing.

## Retained sources and historical results

Supported metadata originates from the retained native mapped selected PE image (`native_mapped`), with original
file-descriptor and pathname metadata checks around collection. Keep mapped sources quiescent: these checks are
non-atomic with external writes and are not continuous freshness, authenticity or runtime-flow proof.

The process-local view retains stable module IDs and the exact `Arc<Project>` inputs. The desktop accepts a late
result or navigation only for that module set and those exact Projects. Membership changes or replacing a source
Project invalidate it. Merely selecting another module among the same retained set can preserve a valid observation.
Current annotation names, decompiler settings and active-module selection do not change declaration discovery.

Source checks run on explicit Apply/Refresh, page queries and navigation clicks, not on repaint. Each click
revalidates original sources before qualified navigation. A serialized report contains historical observations,
not reusable navigation authority or serialized consent.

## API queries and budgets

`module_references` returns a report; `prepare_module_reference_view` additionally retains process-local inputs
and query. `ModuleReferenceView::revalidate_sources` checks those retained sources. Inputs pair a unique printable
ASCII module ID of 1–64 bytes with the actual `Arc<Project>`, never a basename lookup.

`ModuleReferenceQuery` rejects unknown fields. Optional fields are `source_module_id`, exact `source_slot: u64`,
`filter`, zero-based `offset`, `limit` and `matching_work_limit`. The UI parses the slot as hexadecimal; report
addresses serialize as hexadecimal strings. The API page limit must be 1–256. Matching work defaults to
33,554,432 comparison units; a caller can lower it, including to zero, but cannot raise the cap.

| Budget | Limit |
| --- | --- |
| Supplied modules | 1–8 |
| Original source / selected image | 128 MiB each |
| Aggregate original sources | 256 MiB |
| Raw linkage record allowance | 65,536 across supplied modules, divided per module |
| Individual raw name / aggregate raw names | 4,096 bytes / 1 MiB |
| Aggregate parser lookup work | 1,000,000 units, including headers, scans and mapping lookups |
| Retained filtered import rows | 8,192 |
| Page rows | Default 64; 1–256 |
| Encoded response | 2 MiB for the whole structured JSON report, not just row text |
| Matching work | 33,554,432 comparison units, separate from parser work |
| Candidates displayed per row | At most 16; counts and truncation remain explicit |

Header/table record preflight and loader limits apply before unbounded table copying. Name comparisons charge
fallible merge sorting, whole-DLL comparisons, export lookup and duplicate scans to the separate matching counter.
Exhaustion leaves producer uniqueness unproven and reports `matching_work_exhausted`, `matching_work_used` and
`matching_work_limit`. Lower limits are useful for deterministic exhaustion checks, not evidence of no match.

`matched` counts observed filtered declarations. `matched_is_lower_bound` marks incomplete source-import coverage;
it is not an estimate of unreadable records. `rows_truncated` separately marks the retained-row cap. `returned`,
`more` and `next_offset` describe retained paging, while `byte_capped` describes the whole-JSON limit. No incomplete
search or truncated candidate set authorizes a declared link. Invalid queries, observable source changes and a
response unable to fit one bounded whole row return an API error rather than a misleading partial success.

## Validation boundary

Regression coverage includes regular/delay and bound-import provenance, raw names, ordinals, data exports,
forwarders, ambiguous and incomplete coverage, budget exhaustion, and original-source replacement. Desktop checks
exercise explicit querying and qualified source/target navigation, including stale original-source refusal.

The owned compiler-pair recipe uses clang and Rust's lld to build C into COFF objects, a provider DLL and a consumer
EXE, then renames the provider to `renamed-provider.bin`. The recipe accepts a check command through
`bash tools/ci/module-linkage-oracle.sh --check …`; generated binaries are never executed or committed. This checks
real PE declarations and basename independence, not ABI correctness or runtime binding. These focused checks do
not constitute full-workspace acceptance or a general performance claim.
