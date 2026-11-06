# Analyze several slices and functions in one report

Use `binary analyze` to combine workflows and explicitly selected function decompilations without an external
orchestration script. It reads the input; suggested next-step tool calls and annotation edits are not executed.

```sh
rampage binary analyze module.dylib --all-architectures --workflow triage-report \
  --workflow find-crypto --function exported_entry --json
```

The flat `analyze` spelling remains accepted for compatibility. The primary CLI help lists noun groups.

If only one slice is needed, use the global `--arch` selector instead of `--all-architectures`. The latter
enumerates supported declared architectures, including a slice whose contents fail to load; healthy selected
slices are analyzed independently. Duplicate architecture declarations are ambiguous and require an explicit
thin-image offset. Unsupported CPU families are not inferred. Embedded images use the `--image-offset`
and optional `--image-length` flags; a selected universal slice must still have valid bounds, alignment and
Mach-O headers. Other slice bodies are not considered validated by selecting one.

Repeat `--workflow` or `--function`. The default workflow is `triage-report`; at most 16 function selectors and
64 total architecture/task combinations are accepted. A `diff-builds` workflow requires `--other`; use
`--other-image-offset` and `--other-image-length` for an embedded comparison image. `--limit` caps findings per
workflow section. `--no-decompile` skips workflow previews, not explicit function selections.

## Interpret results

JSON uses `rampage-analysis-batch-v1`. Each target retains image/source SHA-256 and optional capture identity;
each task retains its selector, architecture, elapsed time, result or error. An unreadable slice does not hide
healthy-slice outcomes. Input files must remain quiescent: this is not an atomic multi-slice snapshot.
Non-UTF-8 file names have a lossy report label with `file_display_lossy: true`; loading uses the original path.

`completed` means a query returned, not that its decompilation is correct. Decompilation results retain
`recovery_status`, code and diagnostics; workflow findings and limitations remain visible in text output too.
`failed`, `output_limit` and `not_run` outcomes are explicit. Any such task makes the command exit nonzero after
emitting the report; never treat the exit code alone as a recovery-quality score.

Explicit decompilations and workflow previews require a supervised sibling `rampage-worker` or the explicit
`RAMPAGE_WORKER` executable. Worker failures do not fall back in process. `--decompile-timeout-ms` sets each
supervised request's deadline (default 30,000, range 1–600,000 ms). Workflows have their own work/output
budgets, not a hard wall-clock deadline.

Serialized task envelopes are capped at four MiB and the complete compact JSON report, including its final
newline, at sixteen MiB. Oversized results are omitted whole and their task outcomes retained; JSON is not
truncated mid-object. Reduce task selection or workflow limits when an output budget is reached.
