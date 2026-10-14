# Capability indicators

`rampage binary capabilities image.exe --json` and the `capabilities` agent/MCP tool report static metadata matches.
Each result includes an ID, name, category and matched import/string evidence. Indicators describe
available building blocks, not execution, call ordering, argument values or malicious intent. Legitimate software
can implement every behavior listed here.

## Corroborated rules

The following rules require a match in **every** independent indicator group. Alternative API spellings and
duplicate inputs cannot replace a missing group. Evidence retains original spelling and removes exact duplicates.
Legacy rules instead retain their canonical term evidence, such as `import:ptrace` and `string:https://`.
Import matching normalizes thunk prefixes, leading underscores, `@` decorations and ASCII case. Charset-neutral
terms accept one trailing A/W suffix; explicitly named variants remain distinct. Normalization affects matching,
not corroborated evidence: `__imp__CreateFileW@28` remains `import:__imp__CreateFileW@28` in a corroborated hit,
while a legacy filesystem hit reports `import:createfile`. Legacy thresholds count distinct matched rule terms,
not duplicate inputs. Name terms also match function symbols, which name statically linked code; a term or input
matched only by a symbol reports `symbol:` evidence instead of `import:` (`symbol:puts` in a static musl binary).
String matching is rule-specific: literal case-sensitive substrings, ASCII-insensitive
substrings or bounded registry paths. None of these rules establishes an API's argument values or data flow.

| Rule ID | Required groups |
| --- | --- |
| `persistence-registry-run` | Open/create registry key; set value; bounded Run/RunOnce key path |
| `persistence-scheduled-task` | COM instance creation; scheduler identity string; task-registration string |
| `persistence-service-install` | Service-manager open; service creation |
| `process-enumeration` | Process snapshot; first-process walk; next-process walk |
| `remote-process-injection` | Remote-process access; remote allocation/write or mapping; execution-start API |
| `vm-sandbox-detection` | Firmware-table or adapter read; hypervisor artifact string |
| `token-privilege` | Token open; privilege lookup; privilege adjustment |
| `debug-privilege` | Token/lookup/adjustment groups; `SeDebugPrivilege` string |
| `screen-capture` | Display DC; compatible DC; bitmap; blit; bitmap extraction |
| `clipboard-read` | Clipboard open; data read; close |
| `raw-input-capture` | Raw-input registration; raw-input data retrieval |
| `service-control` | Service-manager open; service open; service control/configuration operation |
| `named-pipe-server` | Named-pipe creation; connection |
| `named-pipe-client` | Named-pipe wait; file open; read/write; named-pipe path string |
| `dns-network` | DNS/name resolution; network communication |
| `system-info` | System information; host name; environment access |
| `system-shutdown` | Shutdown/reboot API; shutdown-privilege string or privilege-adjustment API |
| `lsa-private-data` | LSA policy open; private-data retrieval; specific credential-secret marker |
| `credential-registry-read` | Registry open; query value; bounded protected credential key path |
| `ransomware-indicators` | Encryption; enumeration start; enumeration walk; file write; two ransom-note string groups |

These are intentionally narrow metadata rules. DNS plus networking does not attribute command-and-control;
encryption plus file access alone does not imply ransomware. Registry paths use case-insensitive, key-bounded
matching. Existing broader rules retain their IDs and thresholds, so their presence should not be confused with
the stronger corroboration required by this table.
Run/RunOnce corroboration requires the exact key after an optional recognized user/machine hive prefix; it does
not accept a subkey or a `Runtime` prefix collision. Credential paths allow descendants of their protected keys
after an optional recognized machine-hive prefix. VM/sandbox detection here is import/string-based, not CPUID
instruction analysis. Shutdown matches do not prove a shutdown privilege was enabled or a reboot occurred.
The legacy `capabilities` CLI spelling remains accepted.
