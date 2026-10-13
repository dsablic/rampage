# Decompiler corpus runner reference

`tools/decompiler_corpus.py` measures a JSON manifest of independent single-function
decompilations. It requires Python 3.10+ and only the standard library. It does not
require Ghidra headless, import Python packages from rampage, or build binaries.
The report is JSON, not a spreadsheet.

## Command

Successful output is distinct from recovery quality. Results with engine diagnostics report bad-data and
unimplemented flags, warning records and unresolved-flow counts; aggregation reports status counts over
successful outputs separately. Older outputs without these diagnostics are `unavailable`, not issue-free.
`no_reported_issues` is not a semantic-equivalence or correctness claim. Fixture assertions can intentionally
pass for a warning-bearing result; the assertion score does not override the reported recovery status.

| Recovery status | Meaning |
| --- | --- |
| `incomplete` | The engine reports bad data or unimplemented semantics. |
| `warnings` | No incomplete flag, but warnings, unresolved flow or partial jump tables are reported. |
| `no_reported_issues` | Diagnostics are present and none of those issues are reported; correctness is not proved. |
| `unavailable` | The result producer did not supply diagnostics. |

```sh
python3 tools/decompiler_corpus.py target/debug/rampage \
  --case tests/fixtures/bin/hello-x64-dyn.elf main \
  --case tests/fixtures/bin/hello-arm64.elf main

python3 tools/decompiler_corpus.py target/debug/rampage \
  --manifest corpus.json --baseline baseline.json --isolated \
  --timeout 30 --max-output-bytes 16777216 --output report.json
```

| Argument | Meaning |
| --- | --- |
| `RAMPAGE` | Executable path or executable name on `PATH`; resolved path and SHA-256 appear in the report. |
| `--case IMAGE FUNCTION` | Repeatable image/function pair; IDs are `cli-1`, `cli-2`, etc. |
| `--manifest FILE` | Versioned JSON corpus; manifest cases precede any `--case` entries. |
| `--baseline FILE` | Optional versioned JSON assertions scoped to image and function identity. |
| `--arch ARCH` | Default architecture slice selection; a manifest case can override it. |
| `--compiler ID` | Default Ghidra compiler ID; a manifest case can override it. |
| `--isolated` | Also pass `--isolated` to every CLI invocation; requires the sibling worker. |
| `--timeout SECONDS` | Positive finite wall-clock bound per CLI process and output drain; default 30. |
| `--max-output-bytes BYTES` | Positive retained-output limit **per stream**; default 16 MiB. |
| `--output FILE` | Write JSON here, replacing an existing report; otherwise emit it on stdout. |

Every case launches `RAMPAGE --json [--arch ARCH] decompile IMAGE --at FUNCTION`
with optional compiler and isolated flags. Cases run sequentially in fresh
processes, even without `--isolated`; no warm project/decompiler state is shared.
`--isolated` adds native worker isolation inside each CLI invocation.
The runner uses the accepted legacy `decompile` route; its canonical interactive
equivalent is `RAMPAGE --json [--arch ARCH] function decompile IMAGE --at FUNCTION`.

Exit status is `0` when every case completes successfully and all declared
assertions pass, `1` for case failures, assertion failures or reference identity
mismatches, and `2` for invalid input, an unavailable executable or report-write
errors. A failed case does not prevent subsequent cases from running.
An output path resolving to the executable, an image, the manifest or baseline is
rejected. Existing output files are also checked with filesystem identity
(`samefile`) to reject hard-link aliases, both before running cases and immediately
before writing the report. Inputs and output paths must not be replaced concurrently.

## Manifest schema

Image paths are relative to the manifest directory; absolute paths are accepted.
Functions are symbol names or CLI address selectors, such as `0x1001520`. IDs must
be unique, including IDs generated for `--case`. Metadata is preserved, not
interpreted as CLI flags. Unknown `expected_*` fields are rejected.

Numeric selectors (hexadecimal `0x...` or decimal) must equal the returned function
entry address numerically. Leading decimal zeroes and hex case/zero padding do not
change the address. An interior selector that the CLI normalizes to a containing
function fails with `address_mismatch`; this runner deliberately requires exact
entries for numeric benchmarks. Symbol selectors are not checked against the
display name, but the returned address is always validated and recorded.

```json
{
  "schema": "rampage-decompiler-corpus-v1",
  "metadata": {
    "dataset": "controlled greeting fixtures",
    "compiler": "clang (record the exact installed version)",
    "optimization": "-O2",
    "target": "x86_64-linux-gnu",
    "platform": "ELF / SysV",
    "settings": {
      "relocations": "CLI defaults",
      "annotations": "none",
      "processor_context": "CLI defaults"
    }
  },
  "cases": [
    {
      "id": "greeting-x64-main",
      "image": "tests/fixtures/bin/hello-x64-dyn.elf",
      "function": "main",
      "arch": "x86_64",
      "compiler": "gcc",
      "reference_source": "tests/fixtures/src/hello.c:main",
      "metadata": {
        "coverage": ["direct imported call", "string literal", "constant return"]
      },
      "expected_params": 0,
      "expected_calls": [{"name": "puts@plt", "indirect": false}],
      "expected_strings": ["\"rampage fixture greeting\""],
      "expected_contains": ["return 5;"],
      "expected_not_contains": ["WARNING:"]
    }
  ]
}
```

The example's compiler metadata is illustrative: replace it with actual fixture
build provenance. `compiler` in a case is the decompiler compiler specification,
not the version of the compiler that built the image. `reference_source` is an
opaque provenance label; the runner neither reads it nor hashes it.

### Assertions

| Field | Accepted value and check |
| --- | --- |
| `expected_contains` | List of literal substrings that must occur in rendered C. |
| `expected_not_contains` | List of literal substrings that must not occur in rendered C. |
| `expected_params` | Nonnegative count, or ordered list of objects with `name` and/or `type`. List length must match. |
| `expected_signature` | Nonempty object with return type, convention and/or variadic fields (below). |
| `expected_calls` | Object list: `name`, `target`, and/or `indirect`; each must match a recovered call. |
| `expected_strings` | Literal rendered substrings, including quotes/escapes for C literals. |
| `expected_switch_targets` | Unsigned addresses (integer or `0x...`); each must occur in a jump table. |
| `expected_switch_case_values` | Unsigned raw bit patterns; each must occur in recovered table labels. |

Parameter `type` is compared with the engine's `data_type.name`. Addresses are
compared numerically. Other comparisons are exact literal comparisons. Signature
fields use a type-name string for `return_type`, a string or null for
`calling_convention`, and a boolean for `variadic`. Call `indirect` is a boolean.
Parameter and signature expectations each constitute one assertion; other lists contribute
one assertion per element. An empty list declares no assertions, except
`expected_params: []`, which asserts that there are no parameters.

Call and switch lists are **membership checks**, not exhaustive inventories.
They do not penalize extra calls/targets, consume distinct matches, associate
case values with targets, or prove that a switch is complete. Switch case values
are not signed labels: interpreting signed values needs operand width and
signedness not present in this assertion schema.

## Baseline schema and identity scope

A baseline supplies assertions, not a text-equivalence score or a report from a
previous run. It requires a tool name, tool/version identifier, settings object
and a list of uniquely identified cases. A baseline may cover only part of the
corpus; extra baseline IDs not present in the corpus are rejected.

```json
{
  "schema": "rampage-decompiler-baseline-v1",
  "reference": {"tool": "fixture-source", "version": "source revision ID"},
  "settings": {
    "compiler": "exact compiler version and flags",
    "types": "source declarations",
    "analysis": "document mappings, relocation and processor-context policy"
  },
  "cases": [
    {
      "id": "greeting-x64-main",
      "image_sha256": "replace with the image's 64 lowercase SHA-256 hex digits",
      "function": "main",
      "address": "0x1001520",
      "arch": "x86_64",
      "compiler": "gcc",
      "language_id": "x86:LE:64:default:gcc",
      "reference_source": "source revision ID / hello.c:main",
      "expected_params": 0,
      "expected_strings": ["\"rampage fixture greeting\""]
    }
  ]
}
```

The placeholder hash must be replaced before this example is accepted. Hashes
cover the **entire image file**, not a function's bytes. `arch` and `compiler`
must be explicitly present, using null if no override was requested. Matching
requires the same case ID, hash, function selector, requested architecture,
requested compiler, actual `language_id` and actual function entry address.
Each baseline case must include `address`, as an unsigned integer or address
string; comparison with the returned address is numeric, including for symbol
selectors. A symbol and an address selecting the same function are not
interchangeable for baseline identity. Changing an
architecture alias or explicit compiler override also changes this scope.

Hashing occurs before the case is executed; corpus images and executables must
remain unchanged during the run. Reference source, referenced shared libraries,
worker binary, engine specifications and external configuration are not included
in the image hash. Record their provenance separately in metadata/settings.

Reference assertions with identity mismatches are marked unavailable, retained
in aggregate denominators and cause exit status 1. A CLI failure prevents
language matching and assertion evaluation. Settings are recorded but not
automatically reconciled with CLI defaults: identity matching does **not** mean
Ghidra mappings, types, symbols, processor context or analysis options matched.

## Report and measurements

Reports use schema `rampage-decompiler-corpus-report-v1`. Each case records image
hash, command, requested compiler/architecture, success/failure, exit code,
stderr, elapsed seconds, observed stdout/stderr bytes and child resources.
`actual_address` records the canonical hexadecimal returned entry address when
the result validates, even if a numeric selector mismatch makes the case fail;
it is null when no validated result is available. The returned `address` is
required, unsigned and parseable.
Successful JSON results additionally record:

- Actual language/compiler ID and the exported recovered signature/parameters;
  these are engine evidence, not proof that the original source signature was recovered.
- Recovered calls and their count; `typed_call_count: null` because the CLI's
  recovered calls do not export prototypes. A `type` token is not proof of a typed call.
- Token totals by kind, recovered block count, jump-table/target counts and table metadata.
- UTF-8 rendered C byte count and lines containing `WARNING:` in C and stderr separately.

Recovered blocks must have unique nonnegative integer indices, explicit `start`
and `end` (valid unsigned addresses or null), and a list of nonnegative integer
successor indices referencing recovered blocks. Indices need not be contiguous.
When both range endpoints are present, `end` must not precede `start`.
Jump tables require an explicit `switch_address` (valid address or null), boolean
`partial` and a list of valid unsigned target addresses. `case_values` may be
absent or empty when metadata is unavailable; otherwise its length must equal
the target list length and each element must be an unsigned integer or null.
Malformed structures fail the case rather than contribute recovery counts or
passing assertions. An unmatched expected label is unavailable if a nonempty
table lacks case-value metadata; unavailable assertions remain in denominators.

Warning counts are case-sensitive line counts, not counts of warning occurrences;
stderr is not parsed as a diagnostic protocol. The JSON stdout byte count includes
tokens and structure, and is not the same as rendered C bytes.

Elapsed time uses `time.perf_counter()` and includes process startup, image loading,
decompilation and pipe draining. It excludes runner image/executable hashing,
JSON parsing, assertion evaluation and report serialization. This is end-to-end
CLI time, not native decompiler time or a warm throughput benchmark.

On platforms with `resource`, CPU fields are differences in accumulated
`getrusage(RUSAGE_CHILDREN)` user/system time. Descendant accounting depends on
which children the CLI/worker reaps. `children_max_rss_bytes_high_water` is the
runner's cumulative child high-water value **after** that case, not a delta, not
per-case peak memory and not summed concurrent process RSS. macOS values are
bytes; Linux values are converted from KiB. Other platform conventions need
verification. Resource fields are null if the module is unavailable. Parent
memory is not measured.

Stdout and stderr are drained concurrently into capped byte buffers. Exceeding
either stream limit kills the process; reported bytes are bytes actually drained,
which can exceed the retained limit and omit bytes never read after termination.
Limits do not bound native child memory; backend output/token bounds are separate.
On POSIX, timeout/limit termination kills the fresh process group, including
workers and descendants retaining pipes. The executable is trusted: escaping the
process group is not sandboxed. On non-POSIX platforms only the direct process
is terminated, so descendants retaining pipes are outside the timeout guarantee.
If process-group termination is denied or the group disappears, cleanup falls
back to killing the direct child if it is still alive. `cleanup_errors` records
failed live-child termination and readers that remain active; these errors do
not escape reader threads. Reaping and draining after termination each have a
one-second cleanup allowance instead of waiting indefinitely. Permission-denied
cleanup cannot guarantee that descendants or an unkillable child have exited.

### Aggregate denominators

Success rate is successful cases / all requested cases. Assertion summaries
separately report total, evaluated, passed, failed and unavailable counts:

- `passed_over_total` keeps failures and identity mismatches in the denominator.
- `passed_over_evaluated` is conditional on available output and is not a corpus-wide score.
- Empty denominators produce null, never zero or a fabricated perfect score.
- Categories and sources (`fixture`, `baseline`) have separate counts. Asserting
  the same fact in both sources counts twice; it does not create independent evidence.
- `warning_lines_total` covers successful C outputs only; the associated case
  denominator is explicitly reported. Failed cases must not appear warning-free.

These are assertion coverage/pass measures, **not precision or recall**. Function
discovery precision/recall remain in `rampage function compare` and
`tools/benchmark.sh` workflow. A passing substring/signature/call/switch assertion
does not establish semantic equivalence, full decompiler accuracy or matched Ghidra parity.

## Dataset provenance and coverage fields

The supplied integration manifest contains selected controlled assertions, not a
frozen general-accuracy corpus or score. Each manifest should record
dataset source/revision/license, source language, compiler version, optimization
and linker flags, stripping/debug-info policy, target triple, ABI/platform,
architecture/endianness and actual analysis settings. Per-case metadata should
identify the intended coverage: integer/float/aggregate/variadic signatures,
direct/indirect/imported calls, literal/global strings, complete/partial switches,
relocations, processor context, unsupported targets or failure handling.

Optimization variants (`-O0`, `-O2`, `-Os`, LTO) and platform variants (ELF/SysV,
PE/Windows, Mach-O/macOS, ARM/Thumb, big-endian targets) are distinct datasets,
not interchangeable observations. Coverage is only that declared by supplied
fixtures/assertions; passing greeting fixtures says nothing about untested
targets, types, switch lowering or arbitrary programs.

The stdlib regression suite uses temporary fake executables and checks timeout,
crash/nonzero exits, malformed JSON, bounded concurrent output, identity scope,
exact numeric entries, hard-link output protection, block/table validation,
assertion mismatches and stable denominators:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest tools.test_decompiler_corpus -v
```
