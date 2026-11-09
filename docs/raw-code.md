# Explicit raw-code windows

MCP `inspect_raw_code` inspects a bounded original-file range without an executable header. Supply `path`,
`offset`, `length`, `arch`, `mode`, `code_byte_order`, `data_byte_order` and `base_address`; `instruction_limit`
defaults to 64. Architecture/mode/order/base are analyst assertions, not detection or validated load mappings.

The result binds the selected bytes to a range hash, preserves original-file offsets separately from asserted
VAs, and returns linear decoder observations with a stop reason, consumed/remaining counts and continuation
parameters. It does not follow targets or create functions, annotations, sidecars or extracted files.

CLI uses the same request fields, excluding the positional path:

```sh
request='{"offset":0,"length":4,"arch":"arm","mode":"thumb",
"code_byte_order":"little","data_byte_order":"little","base_address":"0x1000"}'
rampage --json binary inspect-raw input.bin --request "$request"
```

Limits: 4096 input bytes, 256 instructions, x86/x64/ARM/AArch64 and little-endian code/data only; ARM requires
`arm` or `thumb`, other architectures `native`. `thumb` is A-profile Thumb: M-profile system-register moves (`msr
basepri, r0`) are invalid here. Open Cortex-M code as the `ARM:LE:32:Cortex` Raw profile instead ([Cortex-M
profile](sleigh-decoding.md#cortex-m-profile)), which decodes them. Invalid/incomplete instructions remain
unconsumed. ARM literal reads use complete words in the supplied suffix; backward literals and prior IT context
outside the window remain unknown. JSON is bounded and complete or refused. File access uses the Unix regular-file
checks; reads are non-atomic. Decoded bytes can use the internal borrowed-buffer API, but this MCP operation does
not implicitly decode input or turn decoded offsets into source-file offsets.

Owned acceptance assembles `tests/fixtures/src/raw-window.s` for Thumb, extracts its `.text` centrally, and
runs `compiler_owned_thumb_window` with `RAMPAGE_RAW_FIXTURE` set to those bytes. No target execution is needed.
