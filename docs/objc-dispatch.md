# Objective-C message sends

On Apple binaries most calls go through `objc_msgSend`, so a plain call graph ends there. rampage resolves each send
site in arm64 and x86-64 Mach-O images to the selector it sends and, where the receiver's class is statically
evident, to the method implementations it reaches. `objc_sends` (MCP, `core` group) and `rampage language objc-sends`
(CLI) list them; the same resolutions appear as call edges in `xrefs`, `function_summary` callees, comments in
`function_graph`/`function_summary` listings, and comments in decompiled C.

## What counts as a send

- calls and tail jumps to `objc_msgSend` (`_fpret`, `_fp2ret`), `objc_msgSend_stret`, `objc_msgSendSuper2`
  (and `objc_msgSendSuper`, `_stret` variants): through a stub, an import slot (`call [rip+slot]`) or a register
  loaded from one (`mov r14, [slot]; call r14`);
- arm64 selector stubs (`objc_msgSend$selector` in `__objc_stubs`), whose selector is read from the stub's own code.
  Stripped images name these stubs `_objc_msgSend$<selector>`, as the linker's symbols do;
- the allocation fast paths `objc_alloc` (`+alloc`), `objc_alloc_init` (`-init` on a new instance) and
  `objc_opt_new` (`+new`).

`objc_opt_class`, `objc_opt_self` and the ARC retain/claim/autorelease entry points are followed as passing their
argument through (or its class), not reported as sends.

## Selector and receiver

The selector is the `__objc_selrefs` entry loaded into the selector register (x1, rsi; rdx for `_stret`), or the
stub's. The receiver register (x0, rdi; rsi for `_stret`) has a known class when it holds:

| `source` | Value | Exact class? |
| --- | --- | --- |
| `class_ref` | a class reference (`__objc_classrefs`, `__objc_superrefs`, a GOT entry or `_OBJC_CLASS_$_` import, or the class's address formed directly) | yes: the class object itself |
| `self` | `self` on entry to a method of a known class (the class object in a class method) | no: it may be a subclass |
| `super` | the method's class's superclass, for `objc_msgSendSuper2` | yes: super sends are static |
| `alloc` | the result of `+alloc`, `+new`, `objc_alloc(_init)`, `objc_opt_new` on a known class, or of `-init…` on such an instance | as the class was |
| `class_of` | `-class` / `objc_opt_class` of a known instance | as the instance was |

Registers are followed by a forward dataflow over each function's blocks: moves between registers, loads of the
reference slots, and calls (which keep callee-saved registers). Values stored to memory, kept in ivars or returned by
other methods are not followed.

## Resolution

The receiver's class is looked up as the runtime does: instance or class methods (by receiver kind), categories
before the class's own methods, then up the superclass chain within the binary. `confidence` says what came of it:

| `confidence` | Meaning | Targets |
| --- | --- | --- |
| `resolved` | known class, exactly one implementation reachable | that implementation |
| `ambiguous` | known class, but a local subclass overrides the selector (receiver not exact) or several categories define it | the looked-up one first, then the overrides |
| `framework` | known class, no implementation in the binary: inherited from a class outside it | none |
| `candidates` | unknown class: every implementation of the selector in the binary, when there are at most 8 (`candidates` counts them all) | the implementations |
| `unknown_receiver` | unknown class, no implementation of the selector in the binary | none |
| `unknown_selector` | the selector register's value is not evident | none |

Nothing is guessed: a send of unknown receiver never gets a single target, and `resolved` requires both a known
class and a unique implementation.

## Where it shows

- `objc_sends {path, at?, selector?, offset?, limit?}`: a summary (counts by confidence, with selector, with
  receiver class, selector stubs) over the selected sends, and a page of sends with targets named.
- `xrefs`: each target of a `resolved`, `ambiguous` or `candidates` send is a `call` row from the send site with an
  `objc` object (`selector`, `receiver` — `+Class` for a class object —, `confidence`, `alternatives`). Other rows
  are unchanged. `function_summary` references and callees include them.
- Listings (`function_graph`, `function_summary`): the send's line comment gains
  `objc: [(Shape *) area] -> -[Shape area] | -[Circle area] (ambiguous)`.
- `decompile`: the C line holding the send ends with `/* objc: … */` (a `comment` token with the send's address).
- Method implementations are named `-[Class selector]` / `+[Class selector]` from the runtime metadata even when
  stripped (see `language_metadata`).

Images that are not Mach-O, or carry no selector references, skip all of this; their output is unchanged.

## Measurements

Owned fixtures (`tests/fixtures/objc-dispatch/dispatch.m`, built by `build.sh` for arm64 and x86-64, stripped and
unstripped): classes, a subclass calling `super`, class methods, `alloc`/`init` and `new`, a category on a local
superclass, a protocol method implemented by unrelated classes and overrides that make `self` sends ambiguous. Each
of the 32 sends is checked against the implementations it reaches at run time (from the source) in
`crates/rampage-analysis/tests/objc_dispatch.rs`:

| Fixture | Sends | Selector | Truth in binary | Resolved exactly | Truth among targets | False resolutions |
| --- | --- | --- | --- | --- | --- | --- |
| arm64, stripped and unstripped | 32 | 32 (100%) | 24 | 18 (75%) | 24 (100%) | 0 |
| x86-64, stripped and unstripped | 32 | 32 (100%) | 24 | 18 (75%) | 24 (100%) | 0 |

The six not resolved exactly are three `self` sends a subclass overrides (`ambiguous`, truth included) and three
sends to receivers returned by other methods or passed as parameters (`candidates`, truth included).

Installed applications (measured locally, not committed; sampled `resolved` sends checked by hand against the
disassembly, none wrong):

| Binary | Sends | Selector | Receiver class | Resolved | Ambiguous | Framework | Candidates |
| --- | --- | --- | --- | --- | --- | --- | --- |
| TextEdit (macOS 27, arm64e) | 2551 | 99.9% | 41.0% | 360 | 0 | 686 | 234 |
| Stickies (macOS 27, arm64e) | 2082 | 100.0% | 45.3% | 454 | 0 | 489 | 293 |
| Chess (macOS 27, arm64e) | 4328 | 100.0% | 37.4% | 671 | 7 | 942 | 1177 |
| Bluetooth MIDI Connect (arm64) | 221 | 100.0% | 39.4% | 30 | 0 | 57 | 17 |
| Bluetooth MIDI Connect (x86-64) | 216 | 94.9% | 39.8% | 28 | 0 | 56 | 14 |
| iTerm2 3.6 (x86-64, 114k functions) | 218295 | 94.6% | 38.0% | 36674 | 342 | 43458 | 97234 |

x86-64 code keeps selectors in stack slots more often than arm64 (`mov rsi, [rbp-0x30]` before the call), which is
where its unknown selectors come from. Resolution takes a fraction of discovery's time (5 s against 49 s for
iTerm2 in a debug build).

## Limits

- arm64 (including arm64e) and x86-64 only; 32-bit and legacy-runtime (`objc_msgSend` with fragile ivars) images
  are not resolved.
- No memory tracking: `-O0` code that spills `self` to the stack, ivar-held objects, block captures and method
  results other than the allocation/initialiser family leave the receiver unknown.
- Swift classes' Objective-C methods are found only when they are in the Objective-C class list; dynamically added
  methods, `forwardingTargetForSelector:` and method swizzling are not seen.
