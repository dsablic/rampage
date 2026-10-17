# Function-frame inspection

Types-group `function_frame` returns a paged, read-only inventory for one function. It combines native
parameters/locals with available static stack-access and register-preservation evidence.

Inputs: `at`, optional `offset`/`limit`, and `include_tracker` (default true). Native rows retain current user
names/types, complete raw storage mappings and editable selectors when supported. Joins, dynamic mappings
and unavailable metadata remain visible rather than becoming invented stack slots.

## Coordinates and evidence

Native stack-space widths and configured bases come from the selected decompiler. A signed native offset is
shown only when its address-space width is known; it is not automatically an offset from function-entry SP.

Tracker slots are separately identified as entry-SP-relative observations. Entry-register stores and matching
reloads are static candidates; unsupported instructions, calls, slot reuse and ambiguous joins can weaken them.
Register spill observations do not by themselves prove an ABI callee-save rule or an original source variable.

Diagnostics, availability and omissions accompany the rows. Paging does not establish a complete frame or a
frame-size bound. `edit_variable` remains the storage-keyed name/type edit surface; the frame query changes
neither annotations nor executable bytes.

Limits: native decompiler recovery plus available AArch64 SSA tracking, not runtime capture, an inferred full
ABI frame, or automatic coordinate equivalence.
