# Exact-entry measurement reference

## Measurement status

The three-format inline-only run completed **18/18 attempts**, with no failures or unrun attempts, in 6.986 seconds
on Darwin 27.0.0 arm64 using Python 3.13.14 and debug-profile CLI binaries. Both modes passed their independent
source oracles. Results are local baselines, not a speedup or startup-stall fix.

A mixed-backend pilot failed: **6 inline ELF attempts passed, 1 isolated exact attempt failed with
`unsupported_separate_group_descendant`, and 29 attempts were not run**. Rust workers own a separate process group by
design, and the corpus guardian cannot supervise that ownership model. This is a measurement-supervision limitation,
not evidence of an exact-entry feature failure; the guardian's process-group authority and signalling policy are not
relaxed to work around it. The pilot's inline ELF wall medians were 0.2658 seconds exact and 0.2485 seconds legacy;
its first inline cold attempt took 1.838 seconds. These partial pilot observations establish no speedup and do not
substitute for three-format results. The inline-only run is a separate measurement with its own output file, not a
replacement or retry of the pilot's failed samples. Raw reports are not retained; only the sanitized observations
below are.

Isolated worker wall time and RSS are **UNAVAILABLE under this gate**. Rust worker parity acceptance is a separate
gate and does not supply missing performance measurements. A separate live SDK launch on the measurement host failed
with `Bad CPU type`; Rosetta was not installed and architecture checks were not weakened. Static Mach-O decompilation
does not establish live SDK execution acceptance.

A separate [owned exact-entry API pilot](worker-observations.md) records native/isolated full-image measurements
and actual worker lifecycle observations. It does not change this CLI guardian's inline-only policy.

## Workload and settings

The source-only runner compares exact-entry and legacy decompilation of the same complete owned fixture image.
It never executes the target fixtures and does not require Rosetta for the x86-64 Mach-O input.

| Fixture | Entry | Compiler override | Independent source oracle |
| --- | --- | --- | --- |
| hello-x64-dyn.elf | main | gcc | puts with the owned greeting literal; return 5 |
| hello-x64.exe | add | windows | Two parameters; return their sum |
| hello-x64.macho | _main | gcc | puts with the owned greeting literal; return 5 |
| hello-arm64.elf, optional | main | default | puts with the owned greeting literal; return 5 |

Both modes use the same explicit compiler override and otherwise default CLI native settings. Fresh copies of the
fixture files have no annotation sidecars. The report includes fixture, source, CLI, worker, runner and supervisor
SHA-256 digests, the compiler requested for each format, observed language IDs, and a canonical manifest fingerprint.
The observed language ID must equal the canonical architecture/compiler ID for the case. Before copying, preflight
checks full ELF64 headers and program/section-table bounds, full PE COFF/PE32+ headers and section-table bounds, or
full 64-bit Mach-O headers with a bounded command-size/count walk. ELF/PE file-backed extents must fit the file.
These are structural admission checks, not a replacement loader or proof of executable correctness. Extended ELF
numbering is unsupported. A Windows compiler setting alone does not admit PE.

Each fixture runs with the **inline backend only**: a physical CLI copy in a fresh directory without a sibling worker,
with `RAMPAGE_WORKER` removed. `--backend inline` is the default and only supported backend option; an isolated request
is rejected before scratch writes or child launches. The required worker executable is hashed for version provenance
only and is never launched. The manifest records this scope and null isolated wall/RSS metrics.

Exact responses must report `in_process_native`. Legacy JSON has no backend field;
its selection is controlled by the executable layout and environment, not independently attested by the response.
Exact responses must have root-level code and context, exact-entry scope, checked backing and
`full_image_mapping: true`.
Legacy responses must have root-level code and no context. Both modes independently pass the source oracles;
agreement between modes is not sufficient. Exact local context deliberately omits whole-program facts, so identical
decompiled text is not required. Legacy full-image behavior is a matched source setting, not a JSON attestation.

## Invocation and limits

Use Python 3.10 or newer. From the repository root, after building and inspecting the CLI and worker:

```sh
python3 tools/entry_measurements.py --cli /absolute/path/to/rampage \
  --worker /absolute/path/to/rampage-worker --backend inline \
  --output /caller/owned/scratch/entry-measurements-inline.json
```

The output parent must already exist outside the repository. The output file must not exist; it is opened exclusively.
Unknown arguments, missing inputs and invalid output destinations fail preflight before scratch files are created.
Temporary executable and fixture copies are removed after the run. The report contains no raw stdout, stderr, code,
omission text, command paths or PIDs. Response metadata is projected into a strict scalar schema: canonical lowercase
hexadecimal addresses within 64 bits, fixed case-specific language IDs, known unsigned count fields plus the boolean
budget flag, and bounded mapping/timing integers. Unknown or nested count values are rejected. Omission lists persist
only a count and SHA-256 digest of bounded canonical JSON; strings in that list are never copied into the report.
Byte counts, digests and allowlisted failure categories retain evidence without publishing arbitrary response text.

The default is three attempts per mode/fixture, inline only: 18 child launches. `--include-arm64` raises this to 24.
`--repeats` accepts 1, 2 or 3. Exact/legacy order alternates between repetitions.
There is no warmup, randomized scheduling, cache eviction or retry. Every launch has a maximum 30-second deadline;
the measurement lane has a shared 120-second execution budget. Remaining attempts become `not_run` when exhausted.
Bounded process cleanup and input copying add overhead; this is not a hard real-time whole-script deadline.
Stdout capture is capped at 1 MiB and stderr at 64 KiB per child, with cumulative limits rather than rolling tails.

The corpus guardian supervises pre-exec and execution, holds its directly owned process-group leader unreaped
through final group cleanup, and never signals PIDs inferred from process listings.
Separate-group descendants are unsupported, reported when observed and never signalled by guessed
ownership. The runner is single-threaded and POSIX-only. Cancellation unwinds supervision and temporary-file cleanup.

Exit code 0 means every planned attempt passed; 1 means at least one attempt failed or was not run; 2 means preflight or
report-generation failure. Interrupted execution returns 130 and does not promise a completed aggregate report.
Native nonzero exits, timeout and missing RSS observations are retained as failed attempts, not silently retried.
Missing or zero RSS produces `failed_missing_rss`, even when the sampler claims positive sample counts; successful
source-oracle evidence remains attached where available, but that attempt cannot pass the measurement gate.

## Metrics

| Field | Scope and limitations |
| --- | --- |
| wall_seconds | Supervised launch through cleanup; includes spawn, CLI loading/configuration and serialization |
| configuration_ms | Exact API configuration/source checks, excluding earlier CLI image opening and name resolution |
| metadata_ms | Exact local metadata preparation and entry evidence |
| replay_ms | Exact replay-plan construction, not native replay execution |
| mapping_ms | Exact full-image mapping preparation, not engine initialization |
| execution_ms | Engine initialization, native replay, decompilation and validation; see execution scope below |
| total_ms | Exact API total; integer milliseconds, not full CLI wall time |
| legacy phase timings | Unavailable (`null`); never inferred by subtracting exact phases |
| max_observed_summed_bytes | Largest sampled inline CLI RSS; guardian/sampler excluded |
| CLI/worker peak RSS | Unavailable (`null`); not inferred from the sampled group sum |
| Isolated wall time and RSS | Unavailable (`null`); worker process-group ownership unsupported by this gate |

Execution also includes result processing. This is not a pure native decompiler CPU timer.

RSS uses process snapshots at nominal 50 ms intervals, with additional sampling/scheduling jitter. It is
shared-inclusive,
not private memory, not a guaranteed peak and not a simultaneous per-process high-water sum. Short processes can escape
sampling. Missing or zero observations are unavailable, never a measured zero. Reports retain sampling/error counts.
Successful-attempt medians and minimum/maximum ranges exclude failures, whose counts and individual records remain
visible. With only three attempts and inline-only scope, results are descriptive local baselines, not statistical
speedup evidence, constant-time guarantees or evidence that intermittent native startup stalls are fixed.

## Observed inline results

Each row has three successful attempts and zero failed/unrun attempts. Parentheses contain minimum–maximum.
RSS is the sampled maximum described above, converted to MiB, not a per-process high-water measurement.

| Fixture | Mode | Wall seconds: median (range) | Sampled RSS MiB: median (range) |
| --- | --- | --- | --- |
| hello-x64-dyn.elf | exact | 0.2877 (0.2796–1.7387) | 49.47 (49.12–53.69) |
| hello-x64-dyn.elf | legacy | 0.2817 (0.2716–0.2895) | 49.34 (49.33–49.56) |
| hello-x64.exe | exact | 0.2609 (0.2600–0.2758) | 48.12 (47.72–48.27) |
| hello-x64.exe | legacy | 0.4029 (0.4019–0.4326) | 61.12 (60.00–61.45) |
| hello-x64.macho | exact | 0.2845 (0.2663–0.2885) | 49.44 (48.98–50.73) |
| hello-x64.macho | legacy | 0.2722 (0.2687–0.2902) | 49.28 (49.28–49.34) |

Exact API timings, milliseconds, median (minimum–maximum):

| Fixture | Metadata | Execution | Total |
| --- | --- | --- | --- |
| hello-x64-dyn.elf | 0 (0–0) | 170 (169–178) | 170 (169–179) |
| hello-x64.exe | 1 (1–1) | 168 (167–169) | 169 (168–170) |
| hello-x64.macho | 0 (0–0) | 168 (167–170) | 168 (167–170) |

Configuration, replay-plan and mapping timings were 0 (0–0) ms on every exact case. Integer zeros mean below
the timer's millisecond resolution, not an absence of preparation work. The first exact ELF wall observation
of 1.7387 seconds remains in the reported range; it is not hidden as a warmup or attributed to a proven cause.
These tiny fixtures do not demonstrate a general advantage over discovery-based decompilation.

### Reproduction identity

Canonical measurement manifest SHA-256:
`cd2c8c39db1625e22528c6211daf8c712dec1045300abafb2172f6ba727d7b8d`.

| Input | SHA-256 |
| --- | --- |
| CLI | ef75ef798e520dee03c30e9c8589f8cdf65392f90e4bf581c954150ee5295977 |
| Worker, provenance only | 4ca81e879df5e713be9d46a8a97b5f59fa79b435588e63034cfa8a2497993259 |
| hello-x64-dyn.elf | bb5d15a43a8e1ebb06eb7b1a3c649e6ff274f9d013b02a1c23d80df8f0d4cabb |
| hello-x64.exe | 3b6a01cc33e6b3c55702d69cf24c44f001dd09fe4ff7bdc7a0432de59d64c9c4 |
| hello-x64.macho | 0f45e6b07b65993e7afcea2e2c74d2aeb00dbe813ad2205d11590248798d6c40 |
| Owned source | 3f06109c966ca8c3d6cf5c87a031aab612be8f871f42c704f37a41b16ca1ecf7 |
| Measurement runner | 956189813134c31b6ce1bf321b48c4dbe0fef74f7f15ef7e62814d7a87c3e0f0 |
| Guardian supervisor | c6fdd7894a43370899fed758fd8ca7abcb26956e1f7206acc8368f7087810d06 |
