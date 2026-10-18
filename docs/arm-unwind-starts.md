# ARM ELF unwind discovery candidates

ARM ELF32 executable/shared images can supply discovery candidates through typed `SHT_ARM_EXIDX` sections.
The loader checks link-order flags, linked executable-section backing, ordered PREL31 addresses and ELF data
byte order. BE8 instruction byte order does not change unwind metadata byte order.

Supported descriptors are inline compact personality 0 and complete extab compact personalities 0/1. Existing
function discovery and `entry_diagnostics` expose admitted candidates through ordinary format-start metadata;
they are not renamed automatically and do not change ARM32 exact-entry decompilation support.

Limits: no unwinding, boundary proof or interior-range expansion. `CantUnwind`, end sentinels, unsupported
personalities and invalid backing do not supply starts. Fragment/range metadata cannot certify complete source
functions; malformed prefixes and unsupported forms retain warnings rather than promising full coverage.

The owned fixture build script produces distinct-record and coalesced controls under the linker's default
merging policy. Tests use the retained metadata—not copied symbol addresses—to seed the stripped positive;
the coalesced negative confirms that an interior address does not acquire a manufactured metadata origin.
