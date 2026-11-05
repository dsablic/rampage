# Effective annotation read migration

**Date:** 2026-10-19. **Status:** historical; implemented with Phase 3.2's checked patches (see [patching](../patching.md)).

This development reference governs the Phase 3.2 immutable-patch-view integration. It does not authorize
changes to production source-validation, type/layout proofs, annotation history or debugger/capture writes.

## Read mapping

Presentation, analysis and decompilation reads associated with one held `Project` use that project's frozen
annotation view:

```rust,ignore
self.annotations.try_read()
```

becomes:

```rust,ignore
self.read_annotations_lock().try_read()
```

The same mapping applies to `.read()`. Preserve lock error/poison handling, bounded snapshots, replay checks,
lock lifetimes and cancellation behavior. Do not turn a nonblocking read into a blocking one.

## Authoritative operations

Annotation writes, refresh, transaction validation, commit preconditions and checks intentionally observing
concurrent authoritative revisions keep the authoritative lock. A read immediately preceding a write is
not automatically a frozen-view read. Classify each site by its data/control purpose, not by text matching.

`patch_bytes` and `revert_patch` return an effective project. Use that returned project for subsequent reads.
After any annotation mutation (including ordinary rename/comment/type edits), undo/redo or authoritative
refresh, reacquire `effective_snapshot()`; never attach a newer annotation map to an older patched binary.
Effective projects with an installed frozen map retain it. An unpatched original project can still read the
authoritative map when no frozen view has been installed; do not assume every `Project` is frozen.

## Hard cases

Flag mixed read/write, cross-context propagation, derived-cache nonce/contention and image-sealed proof
sites for manual review before changing them. A source/identity check failure is not permission to disable
the check, reinterpret owned bytes as the original mapping, or fall back to unpatched output.

Inventory shared helpers and revision accessors too. Frozen `names_revision()` / `annotation_revision()`
describe the held view, not authoritative writer freshness. A helper used by both row projection and
publication/freshness checks must be classified per purpose; do not freeze publication nonce/contention
checks or let presentation accidentally use newer authority. Preserve cancellation and source checks.

Proof decisions must inspect the same held annotation snapshot used for replay/presentation. Preserve
conditional gates such as `has_checked_layouts()`: do not require original-mapping proof universally for
owned effective bytes, and do not bypass a required proof merely because bytes are patched. Patch admission
must continue refusing incompatible image-sealed layouts and operand metadata.

## Pilot and stopping conditions

Pilot exact-entry read snapshots plus representative type/operand presentation reads first. Review the diff
independently and exercise old/new held snapshots before applying the same classification elsewhere.
Maintain an explicit inventory of direct/indirect reads and tokens, identifying each authoritative use.
Completion requires no unclassified reads/tokens, no new compiler errors and passing focused lifecycle and
read-only tests. Global cross-platform/CI acceptance remains separate; CI dispatch is not authorized.
