# Fuzzy library-function candidates

## Evidence and naming policy

Fuzzy matching is secondary to exact user, data-pack and bundled signatures. It compares production CFG
shape, scalar constants, known calls, sizes and flow distributions. Scores are similarities in `[0, 1]`, not
identity probabilities. Architecture, byte order and instruction mode must agree.

Every result is a proposal. Uncalibrated, below-threshold, insufficient-margin and conflicting-feature
results remain candidates. Even an eligible proposal is not automatically applied. Existing function and
analyst names are preserved; fuzzy queries do not write annotations or sidecars. `--apply` affects exact
matches only.

Call names used as features come from exact proposals, imports or analyst annotations, not held-out debug
names. Identical descriptors with conflicting reference names withhold eligibility. Margins compare
distinct names before candidate truncation.

## Source database requests

`build_signatures` accepts an optional `fuzzy_request` filename. The CLI exposes the same request with
`function build-signatures --fuzzy-request`. This produces a separate fuzzy JSON database, not native
exact-signature JSON.

A build request explicitly selects source names and provenance:

```json
{
  "provenance": {
    "library": "owned-checksums",
    "source": "reviewed source revision and compiler flags",
    "cohort": "reference-build"
  },
  "owned_names": ["checksum", "encode_runs"]
}
```

The API records the actual reference image hash and returns detailed descriptor rejections. MCP returns
the rejection count; successful CLI builds do not print partial rejection details. Rejected descriptors
are not replaced with weaker features. Source selection is limited to 4,096 bodies. Queries never use
target producer sizes or producer/debug labels to construct descriptors; known-call features can use
analyst annotations, imports and exact proposals.

## Queries

`identify_functions` accepts `fuzzy_database` and `fuzzy_request` filenames. The CLI uses `--fuzzy-db` and
`--fuzzy-request`. A query request selects independently discovered entries, not interior addresses:

```json
{
  "cohort": "investigation-build",
  "addresses": [4198400, 4198656],
  "candidates_per_function": 4
}
```

Requests contain 1–64 distinct numeric addresses and request 1–16 candidates per function. The query cohort
must differ from reference and calibration cohorts. Exact matches, existing names, feature rejections and
undiscovered entries are reported separately from candidate evidence. Fuzzy requests cannot be
combined with `no_bundled` / `--no-bundled`.

MCP paging includes exact matches, warnings and fuzzy suggestions while preserving whole-result totals.
Page selection never determines which exact names an apply considers. Invalid fuzzy inputs are rejected
before any exact-name writes.

## Calibration and limits

Calibration uses a separate labeled cohort and a profile-specific score threshold and distinct-name
margin. Held-out labels are opened only after predictions are frozen in the evaluation workflow. Cohort
identifiers alone do not establish independence; measured reports must disclose the actual executable-code
identity checks and remaining overlap.

Descriptors are limited to 4,096 instructions, 512 blocks, 128 constants and 64 known callees per function.
The discovered extent cannot exceed 1 MiB. At least 12 instructions, two blocks and discriminating
constant/known-call evidence are required. Delay-slot architectures and functions mixing effective
instruction modes are refused, even when otherwise valid. The database contains at most 100,000
references and its JSON input is capped at 64 MiB. Unsupported or inconsistent production evidence is
rejected; a rejected descriptor is not an exact-match failure or an excuse to infer a name.
