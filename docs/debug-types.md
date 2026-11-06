# Checked debug-type import reference

Types-group `import_debug_types` previews named project-library declarations and scalar/pointer function
signatures from embedded DWARF or an explicitly selected PDB. Producer facts and native target measurements
remain separate; successful parsing alone is not layout proof.

| Input | Meaning |
| --- | --- |
| `pdb` | Explicit PDB path; omit for embedded DWARF. No recorded debug path or sidecar is opened automatically. |
| `apply` | Defaults to false. True applies the complete reviewed batch, not a page. |
| `review_sha256` | Fresh whole-plan review hash required for apply. |
| `offset`, `limit` | Evidence paging only; never a subset of writes. |

```json
{
  "path": "target/phase1-6/debug-types.exe",
  "pdb": "target/phase1-6/debug-types.pdb",
  "apply": false,
  "limit": 16
}
```

The review binds source content, selected image, native target/specifications, retained producer evidence and
prospective edits. Changed inputs or eligibility require another review. PDB GUID/age matching establishes
linkage, not authentication. Library definitions, proof metadata and dependent signatures commit as one
checked annotation batch; invalid dependencies or oversized receipts do not produce partial edits.

## Layout evidence

Complete nested aggregates, arrays, enums and pointers are checked against the selected native target. Member
offsets, sizes and type references come from the producer; native measurements verify their consumer counterpart.
Missing producer alignment stays unknown even when native alignment can be measured.

Unsupported bitfields retain their source bit-size/offset evidence and reason. They are not erased to turn a
partial record into an apparently complete import. Unsupported calling conventions, aggregate argument ABI,
inheritance and ambiguous identities remain explicit rather than being guessed.

Existing analyst definitions and signatures are preserved. Reopening and native/worker replay check imported
library/proof consistency and image/target identity before dependent interpretations. Undo/redo operates on the
complete batch; unrelated proof groups are not silently cascaded away.

`import_pdb_names` imports names only. `import_debug_layouts` keeps its narrower checked flat/projection
workflow; it is not relaxed because the project-library importer supports more shapes.

Limits: bounded static producer records and native counterpart checks, not source authentication, full SDK or
arbitrary C++ class recovery, runtime object proof, symbol-server access, or executable-byte changes.
