# How to check what a device records and where it sends it

This guide is for owners of a smart device (a TV, a camera, a speaker, a hub) who have its firmware update file and
want to know which servers the device talks to, block the ones they do not want at their router, and find the
programs that can capture sound, video, the screen or input. It strings together four tools; each has its own
reference page for the details:

1. unpack the update ([firmware filesystem images](firmware-images.md));
2. list the endpoints ([endpoint inventory](endpoint-inventory.md#endpoint_inventory));
3. write a router blocklist ([endpoint blocklists](endpoint-inventory.md#endpoint_blocklist));
4. check capture and send paths ([privacy surface](privacy-surface.md)).

All of them are in the `carve` group: call `enable_tools` with `{"groups": ["carve"]}` first, or start the server
with `--all-tools`. The examples use committed fixtures, so the names they find are reserved example names.

## 1. Unpack the update

Run `list_dir` on the folder holding the update. It names each file's format from its first bytes:

```json
{"path": "tests/fixtures/fsimages"}
```

```json
{"name": "squashfs-xz.img", "kind": "file", "size": 4096, "format": "squashfs"}
```

- If the format is `squashfs`, `ext`, `android_sparse`, `ota_payload`, `cpio` or `tar`, list it with `fs_list` and
  extract it with `fs_extract` into a new, empty directory.
- If the image sits inside a vendor container, find its offset with `carve` or `file_layout` and pass it as
  `image_offset`. Nested images (a partition inside an OTA payload) open with `inner`.
- If the update is a microcontroller image rather than a filesystem, see
  [how to read the code in a firmware update file](firmware-walkthrough.md); this guide assumes programs and
  configuration files.

```json
{"path": "tests/fixtures/fsimages/squashfs-xz.img", "output_dir": "/work/rootfs"}
```

```json
{"files": 7, "dirs": 8, "symlinks": 2, "bytes": 16946,
 "executables": [{"path": "/work/rootfs/bin/hello", "format": "elf"}],
 "skipped": [{"path": "dev/console", "reason": "device node not written"}]}
```

Extraction never writes outside `output_dir`, never follows symlinks and skips device nodes; see
[extracting](firmware-images.md#extracting) for the limits.

## 2. List the endpoints

Run `endpoint_inventory` on the extracted directory. It scans the executables and configuration-like text files,
and groups what it finds by registrable domain, most files first:

```json
{"path": "/work/rootfs"}
```

```json
{"domains": [{"domain": "example.invalid", "hosts": ["telemetry.example.invalid"],
              "components": ["etc/device.conf"], "local": true, "network_code": false}],
 "ignored_entries": [{"path": "etc/hostname", "reason": "neither an executable nor configuration-like text ..."}]}
```

A large tree is scanned in pages: pass `next_cursor` back as `cursor` until it is `null`. To see which code uses an
endpoint, run `endpoint_inventory` on one program: each finding then names the functions referencing the string
and the networking APIs they call (`signal: network_code`). From the endpoints fixture:

```json
{"value": "2001:db8:10::25", "form": "ip", "signal": "network_code",
 "evidence": [{"functions": ["connect_v6@0x1002140"], "network_apis": ["connect", "inet_pton", "socket"]}]}
```

Add `"decode": true` to include strings the program decodes at run time.
[What is found](endpoint-inventory.md#what-is-found) lists the kinds and what counts as noise.

## 3. Block them at the router

`endpoint_blocklist` writes the hosts as a list your router can load. Pick the `format` your router uses:
`dnsmasq`, `hosts`, `unbound`, `domains` (Pi-hole, AdGuard Home) or `ips`. `output` is an absolute path to a new
file:

```json
{"path": "/work/rootfs", "output": "/work/blocklist.conf", "format": "dnsmasq"}
```

On the endpoints fixture, with `"include_local": true` because its names are reserved example names:

```text
# rampage endpoint blocklist (dnsmasq format, domain level): 1 entry
address=/vendor-cloud.example/0.0.0.0
```

- To keep a service working (time, updates), name it in `allow`.
- To block only some hosts, list them in `deny`, or pass the chosen hosts as `entries` instead of `path`.
- Use `"level": "host"` to block exact host names rather than whole domains. Shared cloud and CDN domains stay at
  host level whatever the level, so a blocklist never cuts off other customers' services.
- Addresses go in a separate `"format": "ips"` list for firewall rules.

Blocking at the router changes nothing on the device, and survives firmware updates. Some features may stop working
when their servers are blocked. See [endpoint_blocklist](endpoint-inventory.md#endpoint_blocklist) for the formats
and what is never written.

## 4. Find what the programs can capture

Run `privacy_surface` on each program that links audio, video or input libraries. On the privacy fixture:

```json
{"path": "crates/rampage-api/tests/fixtures/privacy-x64.elf"}
```

```text
23 capture sources in 10 functions (microphone 15, camera 3, input devices 5); 3 functions can send over the
network or a socket and 1 more can write files; 4 capture-to-send paths; 3 captures are reached from program
start with no user-facing trigger found among their callers.
```

Read the sections in this order:

1. **Capture triggers.** A `no_user_trigger` finding says a capture is reached from program start with no input or
   UI handling found among its callers, such as `main -> record_loop` here.
2. **Capture-to-send paths.** How closely each capture is tied to a send: in the same function, a direct call, a
   few calls down, or a shared caller, with the chain (`record_loop -> upload_chunk`, a libcurl send).
3. **Capture sources** and **Send and write sinks**, with the evidence for each.

Then follow `next_steps`: they name the functions to `decompile` to read what is recorded and where it goes. The
report is evidence of what the code can do and how it is reached, never of intent or that it runs; see
[evidence levels](privacy-surface.md#evidence-levels) and [limits](privacy-surface.md#limits).

## Where next

- To stop a capture or upload path in your own firmware rather than at the router, patch the image and fix its
  checksums: [firmware patching](firmware-patching.md).
- A device that refuses repaired or replaced parts: [lock mechanisms](lock-mechanisms.md).
