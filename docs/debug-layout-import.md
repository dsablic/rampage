# Checked embedded-DWARF layout import

The library API previews and imports producer-described flat structs used through pointers. It compares those
facts with the native decompiler's measured layout before applying dependent prototypes. This is separate from
the scalar-only `import_debug_signatures` API and existing `type import-debug` CLI/MCP behavior; there is no new
automatic CLI, MCP or UI import action.

## Supported evidence

The initial consumer is x86-64 little-endian ELF64 with bundled `x86:LE:64:default:gcc` specifications. Supported
compilation-unit languages are C89, C, C99, C11 and C17. Complete fixed prototypes require at least one flat-struct
pointer parameter. Results are void or supported scalar/scalar-pointer types, not struct-pointer results. Members
are supported exact-width scalars or ordinary scalar/void pointers.

Struct size, member offsets and member sizes must be exact constant metadata. Explicit supported producer struct
alignment is required for admission. Unknown member, scalar and pointer alignments remain `None` in the producer
report; they are never filled from native assumptions. The API separately measures and checks the consumer
counterpart, including every known producer constraint and the complete native layout.

The loader report distinguishes `strictly_applicable` producer evidence from `eligible_for_native_verification`
candidates. A candidate is not proof of native agreement. Missing struct alignment is preview-only. CU/DIE offsets
identify types; display names alone do not establish identity. Emitted names are identity-qualified, and ambiguous
names, sanitized collisions and incomplete concrete address indexes are refused.

Unions, bitfields, nested/recursive aggregates, arrays, flexible arrays, inheritance, callbacks, references, pointer
chains and aggregate-by-value arguments/results are unsupported. Unsupported qualifiers, calling conventions,
address classes, range-based entries, expression-valued layout attributes and inherited prototypes are refused.
External, compressed, split and type-unit DWARF are not loaded. Normal body-local and inlined-call metadata does
not become caller parameters. Present function extents must fit one backed code range; absent extents establish
an entry point only.

## API and consent

- `rampage_loaders::debug::layout_signatures(&binary)` returns bounded producer facts without Ghidra validation.
- `Project::preview_debug_layouts()` returns an opaque `DebugLayoutPreview<'_>` borrowing that exact project.
- `Project::apply_debug_layouts(&preview)` applies the cached approved functions and necessary type closure that
  remain eligible under the shared annotation lock.
- Receipt getters expose `report`, `producer_report`, `approved`, `preserved`, `image_sha256` and
  `compiler_spec_sha256`.
- `Project::try_set_decompiler_options(options)` validates remaining annotations before publishing the selection.
  A refusal preserves the old options/cache. The legacy void setter retains deferred validation.

Preview changes no annotations or undo history. A client calls apply only after reviewing the report and obtaining
approval. The receipt is immutable, process-local, non-deserializable and cannot be rebound to a reloaded project.
Image bytes, the original mapped descriptor, selected options and compiler context are revalidated before commit.
Concurrent analyst edits can shrink approval; clearing an originally preserved signature cannot enlarge it.
Existing analyst declarations and signatures are not overwritten, and preserved functions leave no orphan types.

```rust
use rampage_api::{ApiError, DebugLayoutImport, DebugLayoutReport, Project};

fn import_after_review(
    project: &Project,
    approve: impl FnOnce(&DebugLayoutReport) -> bool,
) -> Result<Option<DebugLayoutImport>, ApiError> {
    let preview = project.preview_debug_layouts()?;
    if !approve(preview.report()) {
        return Ok(None);
    }
    project.apply_debug_layouts(&preview).map(Some)
}
```

Accepted type bundles and dependent signatures are one atomic annotation batch and one same-process undo step.
Undo/redo validates remaining dependencies. Undo history is not recovered after the writer exits; persistent reopen
replays the accepted annotations and assertions, not the old process's undo stack.

## Persistent replay and compiler context

Existing `Types` values carry `!rampage-plain-layout-v1` bundles with selected-image, language and manifest identities.
Dependent `Signature` values carry `!rampage-layout-signature-v1` seals naming exact layout digests. Declarations are
regenerated from bounded descriptors. Every engine rebuild installs types, checks assertions, then applies dependent
globals/prototypes. Older clients encounter non-C values and refuse parsing rather than silently dropping proof.

Checked import requires an exact verified embedded specification manifest over the whole specification home.
Initial trusted-cache materialization can repair changed regular manifest files before verification. Checked live
verification then refuses mismatching bytes, overrides, extra discovery entries, symlinks and special files without
deleting unknown entries. Supported Rust native-open attempts are tracked before C entry, including failed attempts; an
unverified or incompatible context cannot be upgraded merely by restoring the environment. Ordinary lookup errors
under an unchanged verified bundle do not invalidate that source identity. A mismatched process must be restarted.
Independent unsafe native initialization outside the Rust wrappers is outside this proof boundary.

Checked worker assertions include `expected_context`. The child validates its own manifest and native context
before initialization, rather than trusting the parent's requested home. Older strict protocol-4 workers reject
checked requests containing the new field. Ordinary manual assertions omit it and retain external-spec support.
This does not authenticate an arbitrary replacement worker executable.

## Bounded logs and resources

Use `Annotations::open_checked(path)` or `open_for_image_checked(path, image)` when reopening untrusted checked
logs. Legacy openers remain compatible but are not retroactively allocation-safe. Checked staging preflights
existing cache/history before cloning and ingests bounded raw lines before Serde. Validation failure discards staged
cache/history/cursor changes while retaining external edits already committed to disk.

Checked writers bound encoded lines and whole batches before append, including escaping expansion and pending
unread batch bytes. They refuse unfinished tails rather than extending them into malformed lines. This is not
rollback of partial writes or an fsync-backed crash-durability guarantee.

| Boundary | Limit |
| --- | --- |
| Layout read work | 262,144 reserved bytes; `.debug_info` at most 128 KiB, potentially less |
| Layout parsing/resolution work | Separate cumulative 262,144-operation budgets |
| Loader graph | 128 layouts, 128 fields/struct, 4,096 types, 8,192 edges, 16,384 nodes |
| Loader output | 256 signatures, 256 KiB declarations, 32 KiB retained names/leaf text |
| Checked import | 16 layouts, 512 total fields, 128 functions, 32 parameters/function |
| Native layout | One MiB struct, alignment at most 8, 128-byte identifiers |
| Input/native copy | 128 MiB selected image and 128 MiB aggregate backed mapping bytes |
| Encoded persistence | 384 KiB type bundle; 8 KiB sealed signature |
| Checked log read | 16 MiB unread bytes, 2 MiB/line, 8,192 lines, depth 8 |
| Checked cache/history | 8 MiB text, one MiB/value, 8,192 counted entries, 1,024 steps |

Bounds can refuse otherwise valid large metadata or histories; they are not completeness claims. Metadata and
hashes establish observable association and agreement, not producer authentication or semantic correctness of
arbitrary debug information. Backing checks do not create an atomic filesystem snapshot or eliminate races with
concurrent writes/truncation. No target execution, attachment, resume, expressions, binary writes or provider
submission occurs.
