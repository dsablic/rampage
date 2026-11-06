# Processor identity and decoder migration

**Date:** 2026-10-19. **Status:** historical; implemented with Phase 4.1's Raw Projects (see
[Sleigh decoding](../sleigh-decoding.md)); the Phase 4.2 work it names remains open.

This development plan governs ordinary-project integration of the MSP430, AVR8 and 6502 pilots. The
explicit-window workflow is not a substitute for that integration, and pilot success does not admit the
remaining processor roster.

## Identity and width contracts

Add real processor identities; never label their bytes as an existing architecture. Legacy architecture
pointer defaults become optional: existing fourteen values remain unchanged, while the pilots return
unknown. Code-space byte bounds, word units and encoded indirect-address widths are independent facts.
An absent C-pointer default must not become zero, eight, a sentinel, an unchecked unwrap or a host guess.

Classify each pointer-width consumer before changing it:

- Code addressing uses checked code-space facts.
- C layouts use reviewed exact language/compiler organization, checked against native results.
- Encoded indirect addresses use decoder/address-space evidence.
- Unsupported pointer-dependent operations return a checked capability error or `None` according to their
  existing contract; they do not report a complete empty analysis as if evidence had been examined.

Only `TI_MSP430:LE:16:default` + `default` and `avr8:LE:16:default` + `gcc` may acquire the reviewed 2/2/4
pointer/int/long model, checked against native results. Unknown pairs cannot inherit it through architecture,
compiler spelling, `has_c_runtime` or platform defaults. Propagation fingerprints and imported prototypes
use the same checked facts rather than synthesizing `int: 4`.
Keep native admission separate from reviewed automatic C-model availability. Existing-architecture Go
and explicitly configured external compiler routes retain their native-open and explicit-typing contracts.
Unknown C-model availability can disable automatic propagation with a clear limitation, but cannot itself
block ordinary explicit typing. An explicit propagation request may refuse without writes. Source/backing/
specification failures remain fatal; model unavailability is not permission to catch or mask those failures.
Existing external IDs must still load and validate natively, and nonexistent IDs must still fail loading;
none acquires an unrestricted reviewed-C fallback.
For new pilots, exact-pair ABI admission remains fail-closed. 6502 remains C-ABI-unknown: direct/worker C
decompilation and C-layout/type queries refuse. Existing
specification, named-type, debug-layout and source-proof gates remain intact; no global relaxation.

## Decoder and flow contracts

The API composes native decoders with the verified Sleigh backend. Arch/loaders do not depend upward on
the decompiler crate. Existing fourteen architectures retain their native route; only the three matching
explicit profiles use Sleigh. Resource/proof/context failures never trigger another backend as fallback.
Fallible creation propagates through joined-switch probing and every discovery round/worker, including
the Project cached-error contract: no `expect`, dummy decoder, skipped region or successful partial Program.
An initial successful open does not prove subsequent opens cannot fail. Classify standalone `.ok()` and
empty-result fallbacks too; they cannot hide initialization failures of a supported backend.

Valid unknown flow retains instruction length/text and a bounded backend gate, stops successor discovery,
and does not count as invalid opcode, return, fall-through or proof of noreturn. A valid unknown at a seed
remains a valid discovered instruction/function with an unresolved exit. Capture its gate before another
decode or format call overwrites state; other terminating paths do not make that exit noreturn.
Listing/search cannot imply fall-through or complete evidence beyond it. Initialization failure is an error,
not an unknown-flow gate. Discovery, listing and
code search must agree on the selected decoder and capability. Missing typed operands cause explicit
unsupported/incomplete evidence, not a complete zero-hit immediate search.

## Explicit image admission

A minimal single-code image uses an honest Raw format, exact owned bytes, explicit profile, internal-byte
base and caller-supplied seeds. Require bounded nonempty bytes, checked arithmetic, profile alignment,
backed seeds/entry and last-byte bounds from profile code-space highest, including AVR byte extent. Native
translator facts must agree with admitted bounds. No ELF/Snapshot parser alias or inferred entry point.
Native decompilation memory reads must also enforce address-space identity. The existing numeric-offset
`MemImage` lookup must not serve AVR data/register/other spaces from the single code mapping. Check that
boundary before permitting any pilot C engine, preserving existing unified-space processor behavior.
Interpretation identity uses an explicit Raw domain/schema and includes bytes, profile, mapping, entry and
seeds. Different interpretations must not share cached proofs. Capture identities stay unchanged and remain
unavailable for Raw. Owned-source support needs an explicit identity contract, not a source-proof waiver.

Ordinary header-driven open never falls back implicitly to Raw. Initial pilot annotations are memory-only.
Patch V1 remains ELF-only. Multi-region maps, MMIO, HEX/SREC and vector seeding remain separate Phase 4.2 work.

## Pilot, review and stopping conditions

Stage the width API without making the pilot depend on an unrestricted bulk fix. While the enum still has
only the existing fourteen identities, introduce an optional `default_pointer_size()` accessor alongside
the unchanged legacy total method. Pilot the classified consumer mappings using that accessor and explicit
unknown-width helper tests, preserving existing-image behavior. Do not add or expose the three new enum
identities until all production consumers have migrated and passed their classified checks.
Then change the legacy `pointer_size()` signature to optional, add the pilot identities with `None`, and
exercise the real unknown-width Project paths. No temporary fabricated width or panicking pilot arm is
permitted. Both stages require their own compiler/search stopping checks; this staging does not replace
ordinary-project integration tests.

The five pilot units are:

1. Architecture width: fourteen defaults become unchanged `Some(value)`; pilots become `None`.
2. Data inspection: default word width/pointer interpretation becomes checked facts or explicit refusal;
   caller-supplied scalar word widths are not automatically C pointers.
3. ABI/propagation: synthesized models become shared exact-profile facts with fail-closed unknowns.
4. Analysis/Project cache: infallible construction becomes propagated fallible creation at every worker,
   round and joined-switch probe.
5. API consumers: explicit Raw admission/identity plus one factory for listing and both search constructions,
   with preserved unknown gates and typed-capability refusals.

Pilot gates apply per transformation. Units 1–3 are the representative full-loop pilots for classified
width/model consumer migration. Once all three pass implementation, independent review, correction and
verification without outstanding mapping changes, only the classified width-consumer migration may proceed.
An unmapped case stops pending a guide update and representative re-pilot.

Units 4–5 remain separately reviewed and verified integration gates. Static Raw-draft review is not an
executed pilot. Their dependencies do not block already-validated width mappings, and width-pilot success
does not authorize factory/Raw implementation or establish ordinary-backend completion.

Freeze the enumerated production caller inventory before width bulk. Every code-address, C-layout,
encoded-address and scalar-inspection use requires a classified mapping. Before changing the legacy
signature or exposing new identities, all production consumers must migrate and pass their checks; search
must find no remaining production dependency on the total-width API, apart from its retained definition.
Relevant compilation/tests must preserve existing fourteen defaults and Go/external explicit-typing behavior.
Use compiler errors and this inventory as the queue, not a global textual replacement.

Completion requires no unclassified pointer/decoder consumers, no new compiler warnings/errors, preserved
existing-processor behavior, and owned ordinary-project discovery/listing/search agreement. Unknown gates,
typed-evidence refusals, distinct Raw interpretation identities and Raw patch refusal must be tested.
Real unknown-flow cases include Hexagon's helper-required gate at an entry and SuperH's aggregated
delay-slot flow within a body. The three-pilot window experiment probes CPSE/DES separately; it does not
establish retention of unknown seed instructions in ordinary Project discovery.
Passing standalone decode tests or shipping resource files alone does not satisfy those conditions.

## Status (2026-10-21)

Complete for Phase 4.1. `pointer_size()` returns `Option<u8>`; sixteen Raw identities exist with `None` widths and
no native decoders, admitted per profile against the verified translator (including byte order and Hexagon's
declared helper). Raw admission, the v2 interpretation identity and cache binding are in place. One project
decoder factory serves discovery, listing and code search with serialized unknown gates and typed
immediate-search refusal. The real unknown-flow cases required above are covered in ordinary Projects
(`crates/rampage-api/tests/raw_roster.rs`): Hexagon's helper-gated entry and SuperH's delay-slot gate inside a
body. MSP430 and AVR8 decompile through one code-space-isolated region; other profiles refuse C. Raw Projects are
exposed through MCP and CLI. Raw patch, capture, persistent-annotation and missing-C-model refusals are tested.
