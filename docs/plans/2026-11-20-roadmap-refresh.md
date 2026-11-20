# Roadmap refresh (2026-11-20)

Status: the rules were agreed on 2026-11-20 and apply from now. The queue was agreed the same day with two amendments: MIPS16e is inserted after the acceptance pass (most OpenWrt programs are MIPS16), and the suite v4 Sonnet headline and the second-model run wait for the acceptance fixes. The agreed queue is in `todo.md`. The cleanup at
the end was applied the same day, except where noted.

## Goal, as restated

Match or improve on IDA Pro in everything except the interactive UI, for an agent working through MCP. The
desktop UI is a way for a person to inspect and assess a binary
([plan](2026-11-20-ui-inspection.md)), not a second analyst workbench.

## What is wrong with the planning today

- **Three sources of priority disagree.** The [parity roadmap](2026-10-16-ida-ghidra-parity-roadmap.md) orders
  work by phase, `todo.md` "Next up" by an agreed queue, and the last two weeks ran mostly outside both
  (firmware, Android, device privacy, `evaluate_function`, `check_claim`). The roadmap's status is dated
  2026-11-13 and still says there is no DEX support and that Phase 8 is a UI with a struct editor.
- **The queue runs out.** Incremental analysis is the last item in "Next up". Nothing is agreed after it.
- **`todo.md` no longer shows what is open.** It has 128 open boxes in about 1,290 lines. Four sections that
  other plans superseded hold 52 of them in about 500 lines, and several boxes are open for work that shipped.
- **Acceptance gates stay open.** About sixteen items say "run on a real sample" or "live acceptance pending".
  The roadmap's own rule (re-run one real investigation at the end of each phase) has not been applied to the
  tracks since 1.0.
- **Measurement has stopped steering.** Both servers are near the ceiling on self-authored suites, suite v4 has no
  Sonnet run, a second model has never been run, and nothing compares rampage with IDA.

## The queue after incremental analysis

One track at a time, each reviewed before merge, each closed by its acceptance run.

| # | Track | Why here |
| --- | --- | --- |
| 1 | **Acceptance pass on real samples** (local, never committed or named): a router userland, an ESP-IDF application, a real update pair through `diff_firmware`, a real APK, agent claims through `check_claim` | A week of features has only seen fixtures built for it. This turns sixteen vague open items into specific bugs or closes them. |
| 2 | **Flywheel steps 1–3** ([plan](2026-11-20-flywheel-next.md)): close row proposals, measure headroom, the unattended code loop | The main bet, parked since 2026-11-09. |
| 3 | **Signature recall on firmware** (flywheel step 5, first slice) | Library identification is a measured gap against FLIRT, and the arms already exist. |
| 4 | **Object files and static archives** (roadmap 4.3): ELF `.o`, COFF `.obj`, `.a`/`.lib` with relocations applied | Open since October and basic in IDA. It also lets signatures be built straight from a vendor's static library, which feeds track 3. |
| 5 | **Analysis depth, by measured headroom:** interprocedural signatures and parameter types (0.65 precision and recall today), then C++ class layout, `__CxxFrameHandler4`, Swift metadata | The largest remaining gaps inside a decompiled function. Skip whichever family the flywheel's code loop takes. |
| 6 | **Windows:** the flywheel's Windows corpus, then a Windows host build | MSVC runtimes are where FLIRT is strongest. The corpus needs the maintainer to accept Microsoft's licence through `xwin`. |

Small slices that fit between tracks: the UI assessment tab, `mine-transcripts`, the tool-surface work below.

Not queued, and why: more processors and container formats (add one when a real sample needs it), debugger launch
or attach (deliberately out of scope), the malware-analysis workflow (needs a real packed fixture and its own
design).

## Rules (agreed 2026-11-20)

1. **A track is done when it has run on something it was not built from.** Fixtures prove the code; one real or
   independently built input proves the feature. Until then it stays experimental and its line in `todo.md` names
   the input still needed.
2. **Follow-ups default to "when a sample needs it".** Each track leaves five to ten. Unless one blocks a queued
   track or an acceptance run, it is recorded once and not scheduled.
3. **One measurement per release, one headline per feature set.** A Haiku pass of the current suite with each
   release (about $1). The Sonnet headline of suite v4 once incremental analysis lands (about $13, the cap agreed
   earlier), and one run with a second model or client. Add tasks the project did not write, such as public
   challenge binaries with known answers, so the suite stops measuring its own authors.
4. **Compare with IDA where the licence allows.** Static results only (function starts, cross-references, library
   names) on the owned corpus, with IDA as a reference and not as truth, as Ghidra is used today. Check IDA Free's
   licence terms before running anything.
5. **Retire a gate or run it.** The live Phase 1 reconstruction was measured with a harness since removed: run it
   once through the current runner or retire it. The Phase 3.3 live gate is answered by the head-to-head medians
   (2 calls against 6): retire it. The Phase 2 recall target becomes the flywheel data loop's metric. The Windows
   debugger's live run stays open until a Windows host exists.
6. **The core tool list is full: demote before adding.** The default listing is 25 bytes under its budget. Use
   the transcripts to find core tools agents rarely call, move them to groups, and keep the budget where it is.
   Raising it charges every session for tools most never use.
7. **Release when a track and its acceptance are done,** not per day of work.

## Cleanup (applied 2026-11-20)

`todo.md`: the release line of the status header, the direction, the proposed queue and the rules were added;
boxes were ticked for work that had shipped (UBI and UBIFS readers, `carve` tagging, fixtures without local paths,
seven of the eight suite v3 items, the `evaluate_function` follow-ups); and three superseded sections moved to
[todo-archive.md](todo-archive.md#superseded-sections-archived-2026-11-20) with their 36 open boxes.

Parity roadmap: a 2026-11-20 update (direction, what shipped, gate decisions), the 4.4 status, and Phase 8
rewritten to point at the UI plan.

Left for later:

- The rest of the status header in `todo.md` and "Next up" were not rewritten, because the incremental-analysis
  session will update both when it lands. Replace "Next up" with the queue once the queue is agreed.
- The audio-plugin investigation batches in `todo.md` (16 open boxes, not touched since October) were left in
  place: whether that investigation is still wanted is the maintainer's call.
- Done in the 1.9.0 documentation pass: `docs/comparison.md` and `docs/features.md` now describe the UI as an
  inspection viewer that is not a type, struct or patch editor, as the UI plan says, instead of as lacking a type
  and struct editor.
