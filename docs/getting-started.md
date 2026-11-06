# Getting started

This tutorial takes you from a fresh checkout to a finished first investigation through MCP. You will build
rampage, connect it to an MCP client, and find out how a small stripped program derives its encryption key.

Every result shown here is real output from rampage on the fixture used, shortened where marked with `…`.

## What you need

- macOS on Apple silicon or Linux x64 (see [supported hosts](../README.md#supported-hosts)).
- A Rust toolchain with edition 2024. The repository's `rust-toolchain.toml` selects stable through rustup.
- A C/C++ compiler and zlib development files, for the embedded decompiler.
- An MCP client. This tutorial uses [Claude Code](https://docs.claude.com/en/docs/claude-code/overview); any client
  that runs stdio MCP servers works.

## 1. Build and install

```sh
git clone https://github.com/dsablic/rampage.git
cd rampage
tools/install.sh
```

`tools/install.sh` builds release binaries and installs `rampage` and `rampage-worker` into `~/.local/bin` (pass a
directory to install somewhere else). The two must stay side by side: decompilation runs in the supervised
worker. Make sure the directory is on your `PATH`, then check:

```sh
rampage --version
```

## 2. Get the fixture

The fixture is `vault-arm64.macho`, a stripped arm64 macOS program built from
[`tests/fixtures/bench-v2/src/vault.c`](../tests/fixtures/bench-v2/src/vault.c). It encrypts a message with a
stream cipher whose key comes from one of two look-alike derivation routines. Don't read the source yet.

rampage saves names, comments and findings in a log beside the binary, so work on a copy:

```sh
mkdir -p ~/rampage-tour
cp tests/fixtures/bench-v2/bin/vault-arm64.macho ~/rampage-tour/
cd ~/rampage-tour
```

rampage only reads the file. It never runs the program, so this works on Linux as well as macOS.

## 3. Connect Claude Code

From `~/rampage-tour`:

```sh
claude mcp add rampage -- rampage server serve
```

For another client, add this to its MCP configuration:

```json
{
  "mcpServers": {
    "rampage": {
      "command": "rampage",
      "args": ["server", "serve"]
    }
  }
}
```

Start the client and check that the `rampage` server is connected (`/mcp` in Claude Code).

## 4. Ask the question

Give the agent the question, the way you would give it to a colleague:

> Using rampage, analyse vault-arm64.macho. It encrypts a message with a stream cipher. Which function derives the
> key passed to the cipher's key-setup routine, and what 32-bit constant does it XOR into each key word? Name the
> functions you identify, and record your conclusion as a finding.

The agent picks its own tool calls. The rest of this tutorial walks through one path to the answer, call by call,
so you can see what the tools return. You can reproduce each step by asking the agent for that call.

## 5. Find the program's logic

`find_main` locates where the program's own code starts and summarises what it calls and references:

```json
{"path": "vault-arm64.macho"}
```

```text
summary:
  Most likely entry logic: `entry` at 0x100000460 (medium confidence, from binary_info).
  The candidate makes 7 distinct calls and references 5 strings.
Candidate calls:     sub_10000054c, sub_1000005cc, sub_10000064c, sub_1000006a0, sub_100000700,
                     import _printf, import ___stack_chk_fail
Candidate strings:   "correct horse", "vault", "attack at dawn", "%08x"
next_steps:          decompile {"at": "0x100000460"}, xrefs {"from": "0x100000460"}
```

(Condensed from the JSON report, which also carries the evidence, confidence and limitations of each finding.)

On a Mach-O with `LC_MAIN`, the entry point is `main` itself. The binary is stripped, so the five local functions
have only `sub_<address>` names.

## 6. Read main

`decompile` at `entry`, with `view: "code"` to get the C and the variable list without the full recovery
evidence:

```json
{"path": "vault-arm64.macho", "at": "entry", "view": "code"}
```

```c
  …
  sub_10000054c(axStack_48,xVar2);
  sub_1000005cc(axStack_58,xVar3);
  Stack_68 = Ram000000010000077c;
  …
  sub_10000064c(axStack_16a,axStack_58);
  sub_1000006a0(axStack_16a,&Stack_68);
  sub_100000700(axStack_48,&Stack_68);
  iVar1 = _printf("%08x\n");
  …
```

`sub_10000054c` and `sub_1000005cc` each fill a 16-byte stack buffer. Only the buffer from `sub_1000005cc`
(`axStack_58`) is passed to `sub_10000064c`, whose result then drives `sub_1000006a0` over the message bytes
copied from "attack at dawn". The other buffer goes to `sub_100000700` alone.

## 7. Compare the candidates

Decompile `sub_10000064c`:

```c
void sub_10000064c(int8 param_1,int8 param_2)
{
  …
  do {
    *(char *)(param_1 + iVar2) = (char)iVar2;
    iVar2 = iVar2 + 1;
  } while (iVar2 != 0x100);
  …
    uVar4 = uVar4 + cVar1 + *(char *)(param_2 + (uVar3 & 0xf));
    *(xunknown1 *)(param_1 + uVar3) = *(xunknown1 *)(param_1 + (uint8)uVar4);
    *(char *)(param_1 + (uint8)uVar4) = cVar1;
  …
```

A 256-entry permutation initialised to the identity and then swapped under a 16-byte key: an RC4-style key setup.
So its second argument is the key, and `sub_1000005cc` produced it.

Now the two look-alikes. `sub_1000005cc`:

```c
uint8 sub_1000005cc(int8 param_1,char *param_2)
{
  …
  uVar3 = _strlen(param_2);
  …
      uVar6 = (uint4)(uint1)param_2[uVar8 - uVar2 * uVar1] | uVar6 << 8;
  …
    *(uint4 *)(param_1 + iVar5 * 4) = uVar6 ^ 0x5ec12e7a;
  …
```

`sub_10000054c` is the same code with `uVar6 ^ 0x36363636`. It is the decoy: its output only feeds
`sub_100000700`. To confirm that `sub_1000005cc` has a single caller, `xrefs` to it:

```json
{"path": "vault-arm64.macho", "to": "0x1000005cc"}
```

```json
{"total":1,"offset":0,"items":[{"from":"0x1000004c8","to":"0x1000005cc","kind":"call","from_function":"entry","to_name":null}]}
```

The answer: the key is derived by the function at **0x1000005cc**, which XORs **0x5EC12E7A** into each key word.

## 8. Name what you found

`annotate_batch` applies several names and comments as one undo step, and checks every entry before applying
any:

```json
{
  "path": "vault-arm64.macho",
  "entries": [
    {"at": "entry", "name": "main"},
    {"at": "0x10000054c", "name": "derive_tag"},
    {"at": "0x1000005cc", "name": "derive_key", "comment": "Builds the stream cipher key; XORs 0x5EC12E7A into each word"},
    {"at": "0x10000064c", "name": "stream_init"},
    {"at": "0x1000006a0", "name": "stream_apply"},
    {"at": "0x100000700", "name": "checksum"}
  ]
}
```

```json
{"changed":6,"entries":[{"address":"0x100000460","name":"main","changed":true}, …]}
```

Decompile `main` again, and the names are there:

```c
  derive_tag(axStack_48,xVar2);
  derive_key(axStack_58,xVar3);
  …
  stream_init(axStack_16a,axStack_58);
  stream_apply(axStack_16a,&Stack_68);
  checksum(axStack_48,&Stack_68);
```

Local variables are in the `types` group, which a session does not list at first. Calling a tool from a group that
is not enabled runs nothing and says what to do:

```text
tool `edit_variable` is in the `types` group, which is not enabled; nothing was run. Call enable_tools with
{"groups": ["types"]} first, or start the server with --all-tools or RAMPAGE_MCP_TOOLS=types.
```

After `enable_tools` with `{"groups": ["types"]}`, `edit_variable` renames the buffer and returns the refreshed C
in the same call:

```json
{"path": "vault-arm64.macho", "at": "main", "variable": "axStack_58", "name": "key"}
```

```c
  derive_key(key,xVar3);
  …
  stream_init(axStack_16a,key);
```

`undo` reverts the last step if you change your mind.

## 9. Record the finding

The findings ledger keeps conclusions, open questions and unknowns with their evidence, so a later session (or
another agent) starts from them:

```json
{
  "path": "vault-arm64.macho",
  "kind": "finding",
  "text": "derive_key builds the stream cipher's key: main passes its output to stream_init, and it XORs 0x5EC12E7A into each 32-bit key word. derive_tag has the same shape with 0x36363636 and only feeds the checksum.",
  "function": "derive_key",
  "confidence": "high",
  "evidence": [
    {"tool": "decompile", "detail": "main passes derive_key's buffer to stream_init"},
    {"tool": "decompile", "detail": "derive_key: word ^ 0x5ec12e7a"}
  ]
}
```

```json
{"finding":{"id":1,"kind":"finding","status":"open", … ,"function":"0x1000005cc","function_name":"derive_key", … ,"confidence":"high", … ,"image_changed":false},"created":true,"changed":true}
```

`list_findings` pages the ledger with counts per kind and status.

## 10. Pick it up from the CLI

Everything was saved in `vault-arm64.macho.rampage` beside the binary. The CLI, the desktop UI and later MCP
sessions all read the same log:

```sh
rampage function list vault-arm64.macho
```

```text
address                size blocks  insns  name
0x0000000100000460      236      9     59  main
0x000000010000054c      128      5     32  derive_tag
0x00000001000005cc      128      5     32  derive_key
0x000000010000064c       84      5     21  stream_init
0x00000001000006a0       96      3     24  stream_apply
0x0000000100000700       68      5     17  checksum
…
```

```sh
rampage annotation list-findings vault-arm64.macho
```

```text
finding  1 open, 0 resolved, 0 rejected
unknown  0 open, 0 resolved, 0 rejected
question 0 open, 0 resolved, 0 rejected
#1 finding [open, high confidence] in derive_key (0x1000005cc): derive_key builds the stream cipher's key: …
    evidence decompile: main passes derive_key's buffer to stream_init
    evidence decompile: derive_key: word ^ 0x5ec12e7a
```

Now read [`vault.c`](../tests/fixtures/bench-v2/src/vault.c) and check the answer.

## Where next

- The [MCP reference](mcp.md) lists every tool group and how paging, edits and limits work.
- The [feature overview](features.md) describes each capability area and its limits.
- [Search](search.md), [patching](patching.md) and [types](type-library.md) are the next tools most
  investigations need.
- This fixture is one of the [suite v2 benchmark](benchmarks/agent-h2h-v2-2026-11-05.md) tasks; the others in
  [`tests/fixtures/bench-v2`](../tests/fixtures/bench-v2/) make good practice.
