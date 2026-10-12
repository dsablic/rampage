# Capability indicators

`rampage capabilities image.exe --json` and the `capabilities` agent/MCP tool report static metadata matches.
Each result includes an ID, name, category and matched import/string evidence. Indicators describe
available building blocks, not execution, call ordering, argument values or malicious intent. Legitimate software
can implement every behavior listed here.

## Corroborated rules

The following rules require a match in **every** independent indicator group. Alternative API spellings and
duplicate inputs cannot replace a missing group. Evidence retains original spelling and removes exact duplicates.
Legacy rules instead retain their canonical term evidence, such as `import:ptrace` and `string:https://`.

| Rule ID | Required groups |
| --- | --- |
| `persistence-registry-run` | Open/create registry key; set value; bounded Run/RunOnce key path |
| `persistence-scheduled-task` | COM instance creation; scheduler identity string; task-registration string |
| `persistence-service-install` | Service-manager open; service creation |
| `process-enumeration` | Process snapshot; first-process walk; next-process walk |
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
| `lsa-private-data` | LSA policy open; private-data retrieval; specific credential-secret marker |
| `credential-registry-read` | Registry open; query value; bounded protected credential key path |
| `ransomware-indicators` | Encryption; enumeration start; enumeration walk; file write; two ransom-note string groups |

These are intentionally narrow metadata rules. DNS plus networking does not attribute command-and-control;
encryption plus file access alone does not imply ransomware. Registry paths use case-insensitive, key-bounded
matching. Existing broader rules retain their IDs and thresholds, so their presence should not be confused with
the stronger corroboration required by this table.
