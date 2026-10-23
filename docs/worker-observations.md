# Owned worker observations

`run_supervised_measured` returns the ordinary result plus host-side observations even on failure.
`Project::decompile_entry_measured` delivers those observations before propagating a worker failure; inline
native calls produce no supervisor observation. Ordinary entry points leave optional collection disabled.
The worker JSON protocol remains version 4.

## Observation boundaries

Milestones share a host monotonic origin and overlap. They include serialization, spawn, pipe setup, actual
input delivery, first output, actual EOF, response decoding, cleanup and reaping. They do not identify native
initialization inside the child, and first output is not a native-initialization timer. A stopped reader does
not count as EOF. Partial request writes remain partial; missing observations are null rather than zero.

RSS is a sampled, shared-inclusive maximum for the directly owned root only, not guaranteed peak memory or
descendant-tree memory. Native-inline RSS is unavailable in the owned pilot. Observation overhead counts
toward the supervisor budget; synchronous spawn, OS queries, native FFI and reaping are not forcibly interruptible.

## Ownership and completion

The supervisor observes its direct child without reaping it before group cleanup. Lost wait ownership or
unsafe SIGCHLD disposition disables further numeric signals; sampled process IDs never grant signal authority.
Default SIGCHLD handling, exclusive ownership of the child's wait status and no concurrent disposition changes
are prerequisites. Descendants that leave the worker's process group remain outside the cleanup boundary.

The Rust worker uses a private inherited control socket to keep its root alive after flushing a response and
releasing its output pipes. The worker validates a fresh close-on-exec duplicate, never adopts the ambient
descriptor's ownership. Completion followed by control EOF/reset revokes intentional-stop authorization.
Successful controlled completion retains the actual SIGKILL root status in observations; it does not fabricate
a successful process exit. A valid response still requires successful cleanup and complete request delivery.
Legacy executables do not gain this completion authority. Primary operation failures retain their category;
measured secondary cleanup failures remain visible.

### Compatibility restrictions

The unchanged JSON schema does not imply unchanged supervisor compatibility. Use the matching shipped Rust
worker for the private completion lifecycle. A legacy/custom version-4 executable without that lifecycle can
fail a successful request if the supervisor cannot establish successful group cleanup, including Darwin's
permission-error path for an already-exited group leader. An otherwise valid JSON response does not waive cleanup.

Embedding processes must retain default SIGCHLD handling and exclusive wait ownership. Even a non-reaping custom
SIGCHLD handler is currently rejected; it is not classified as safe from its address or observed behavior.
Applications requiring custom handlers or independent child reapers are outside this supervisor's supported
embedding contract. Optional measurements do not relax these restrictions.

## Owned full-image experiment

### Journal-validated observations

The journal-validated pilot used complete committed owned x86-64 ELF, PE and Mach-O fixtures, matched explicit
compiler/platform settings, metadata-backed entries, tokens and structured results. Each attempt used a fresh
Project/native handle or a fresh Rust worker. No target fixture was executed. Three attempts per backend and
format all passed the independent greeting/return-five or two-argument-addition oracle. All six decompilation
outputs per format were identical, including tokens and structure. There was no retry or backend fallback.

| Image / entry | Native driver ms, three attempts | Isolated driver ms, three attempts |
| --- | --- | --- |
| ELF / `main` | 212.047, 187.357, 187.621 | 484.926, 209.570, 212.929 |
| PE / `add` | 190.337, 189.423, 185.882 | 294.377, 298.797, 291.010 |
| Mach-O / `_main` | 185.496, 185.684, 181.859 | 214.070, 219.854, 214.957 |

Driver time includes Project open/settings and exact-entry work, including durable in-API progress checkpoints,
but excludes admission checks and build time. Isolated supervisor-only totals were 455.085/179.536/181.130 ms
(ELF), 251.594/254.383/248.891 ms (PE), and 182.109/187.892/183.913 ms (Mach-O).
Sampled worker-root RSS ranged from 44,793,856 to 45,940,736 bytes. All nine isolated attempts recorded full
request delivery, real stdout/stderr EOF, successful cleanup and a reaped root intentionally stopped by SIGKILL.
OS/spec/process-global caches were uncontrolled; none of these is a cold-start claim. Native calls remained
cooperative; an outer finite test timeout bounded the pilot. No stall occurred, so no stall cause or fix is claimed.

The journal contained 215 records and 43,124 bytes, with all 18 attempts completed and none failed or unrun.
This validates normal completion and per-attempt admission, not an actual outer-timeout durability experiment.
Earlier buffered-writer runs also passed but are not timing comparisons: instrumentation and lifecycle changed.

Input SHA-256 identifiers:

- Owned C source: `3f06109c966ca8c3d6cf5c87a031aab612be8f871f42c704f37a41b16ca1ecf7`.
- ELF (4,064 bytes): `bb5d15a43a8e1ebb06eb7b1a3c649e6ff274f9d013b02a1c23d80df8f0d4cabb`.
- PE (220,160 bytes): `3b6a01cc33e6b3c55702d69cf24c44f001dd09fe4ff7bdc7a0432de59d64c9c4`.
- Mach-O (8,464 bytes): `0f45e6b07b65993e7afcea2e2c74d2aeb00dbe813ad2205d11590248798d6c40`.
- Measured worker: `e4db5c9bd631488b9390eae83faf0214d09887707515e5a7d7403e07e9e52880`.

### Additional startup probe

An additional startup-reproduction probe used the already-built pre-plugin harness in three fresh processes.
All 54 planned native/isolated attempts passed without retries; the largest driver times per process were
295.173, 293.604 and 294.340 ms. Each process completed in 4.70 seconds or less. OS/spec caches were uncontrolled,
and the harness was not rebuilt for this probe. Its SHA-256 was
`3a81641696acfba38c755f1448d708e06f1edd177b35bc5181fd5b0eb0f7ceae`.
No stall reproduced, so this probe supplies neither a cause nor an optimization claim.

### Incremental journal and input admission

The corrected opt-in test requires an explicit new output file in private external scratch and an available
`shasum` tool. It opens the output with private mode and `create_new` before input setup, hashing or native work.
The format is **JSON Lines**, schema `rampage-owned-entry-journal-v2`, not the earlier aggregate JSON object.
Every complete line is independently parseable. Each checkpoint flushes and calls `sync_data`; native work is
not started before its attempt-start checkpoint succeeds. Output is capped at 1 MiB total and 16 KiB per encoded
record plus its newline. A journal I/O/limit failure stops the experiment rather than silently buffering onward.
Each record has `journal_elapsed_us`, a monotonic run-relative offset when that record is prepared, not the time
its sync finishes. API phase and supervisor offsets retain their distinct origins.

The first `header` contains the complete ordered 18-attempt plan, IDs, limits and timing policy. Subsequent events:

| Event | Meaning |
| --- | --- |
| `setup_started` | The named fixed input is about to be captured; hashing/setup may still block or fail |
| `inputs_frozen` | Source/worker hashes and all fixture full/selected-image hashes and lengths are captured |
| `setup_failed` | A sanitized setup category; normal control flow marks all planned attempts not run |
| `attempt_started` | The planned attempt is starting, before opening/configuring its Project |
| `attempt_admitted` | The fresh Project passed full/selected-image and original-backing checks |
| `host_phase` | Durable API phase progress, at most 32 checkpoints per attempt; never child-internal timing |
| `operation_returned` | API return, segmented durations and optional supervisor observations, before final checks |
| `attempt_completed` | An observed final pass/failure category, after source-oracle/parity/identity checks |
| `attempt_not_run` | An observed setup, run-budget, supervision or prerequisite refusal prevented this attempt |
| `summary` | Normal-end accounting: planned, completed, passed, failed, not run and all-passed |

An outer kill may leave no summary or a partial final line. Read only the complete newline-terminated prefix.
A start without completion means **interrupted/unknown**, not an inferred timeout or failure. If an operation
returned but final validation did not finish, retain that distinction. Plan entries without starts remain
planned-without-start evidence; do not fabricate `attempt_not_run` reasons or a completed summary after a kill.
Missing/uncreatable output cannot contain a journal; its test failure is a constant category without a path.
After output creation, recoverable input/open/hash/setup errors are journaled with constant categories.

Before any attempt, all fixtures are frozen through retained original mapped Binaries, bounded owned copies
of complete file and selected-image bytes, the selected image range, hashes and original-backing guards. The
owned C source and worker retain descriptors and device/inode/length/mtime/ctime identities. Every admitted
fresh Project must match both frozen byte sequences and selected range, with original-backing checks before
and after comparisons. Source/worker descriptor and path identities are checked before and after each operation;
the admitted Project and frozen original are also revalidated afterward. Inputs must remain quiescent: these
checks do not make concurrent external modification atomic or authenticate worker authorship.

`driver_elapsed_us` sums two measured segments: Project open/construction/settings/entry resolution, and the
exact-entry API call. Per-attempt byte/identity verification and out-of-band journal/result-hash/oracle work are
outside those segments. `open_settings_us` and `operation_us` retain the separate durations. Durable `host_phase`
callbacks execute inside the API call and count toward its budget; supervisor offsets remain supervisor-relative.
This instrumentation changes measurement overhead, so the earlier table is not a baseline for journal costs.

Only allowlisted categories such as `api_unavailable`, `fixture_backing_changed` and `digest_spawn` are persisted
for errors. API unavailable errors are deliberately coarse: the harness does not parse message text to infer a
worker timeout or crash. No raw error messages, stderr, private paths, code, omission strings or arbitrary
context strings are written. Supervisor fields are the typed numeric/enum observations, not diagnostic text.
Matching settings, independent source oracles and complete output/token/structure parity checks are unchanged.
There is no retry, fallback, production profiler or automatic attach.

### Invocation

After final worker review closes, create a private external directory and select a **new** `.jsonl` filename.
From the repository root, with the native toolchain, `shasum` and `timeout` available:

```sh
CARGO_BUILD_JOBS=2 \
RAMPAGE_ENTRY_MEASUREMENTS=/caller/owned/private/entry-journal.jsonl \
  timeout 210 cargo test --locked -p rampage-worker --test integration -- \
  entry_measurements::owned_full_images_three_repetitions_native_and_isolated_exact_entry \
  --ignored --exact --nocapture --test-threads=1
```

The command selects the planned 18 attempts once. The worker deadline is 15 seconds per isolated attempt and
the cooperative run budget is 150 seconds; native initialization/calls remain noninterruptible in process.
The caller owns the finite outer timeout and must inspect the retained journal even if it kills the test.
Pure privacy/progress/size-limit regressions run by default without launching workers or hash tools:

```sh
cargo test --locked -p rampage-worker --test integration -- entry_measurements:: --test-threads=1
```

The existing CLI measurement guardian remains inline-only; this API pilot does not weaken its process-group policy.
