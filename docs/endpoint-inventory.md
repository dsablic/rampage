# Endpoint inventory and blocklists

A device's firmware usually names the servers it talks to: update and telemetry hosts in URLs, bare host names in
scripts and configuration, IP literals for fallbacks, certificate pins for the servers it trusts. `endpoint_inventory`
lists them for one binary or for a whole extracted firmware tree, with the evidence for each, and
`endpoint_blocklist` writes the chosen ones as a blocklist for a router's DNS or firewall. Blocking at the router is
the least invasive fix an owner has: the device is not modified, and the block survives firmware updates.

Both are file tools in the `carve` group. They take a path, open no project and need no other tool first.

## The owner's flow

1. `fs_extract` the firmware's filesystem image into a directory (see [firmware filesystem images](firmware-images.md)).
2. `endpoint_inventory` with `path` set to that directory. Read `domains`: each registrable domain, the hosts under
   it and the files naming it, most files first, so "five programs and a boot script talk to `*.vendor-cloud.example`"
   reads at a glance.
3. Look closer at one program: `endpoint_inventory` on its path alone traces references, so each finding names the
   functions using the string and the networking APIs they call; `decode` adds strings decoded at run time.
4. `endpoint_blocklist` with the same `path` (or the chosen hosts as `entries`) writes the list in the router's
   format.

## endpoint_inventory

```json
{"path":"/work/rootfs","cursor":null,"max_files":200,"timeout_ms":20000,"xrefs":false,"decode":false,
 "kinds":["url","host","ip"],"limit":100}
```

- `path` is an executable or any other file, or a directory. A directory is walked without following symlinks; its
  executables (ELF, PE, Mach-O, by their magic) and configuration-like text files (a `#!` line, or `.sh`, `.conf`,
  `.cfg`, `.json`, `.xml`, `.prop`, `.properties`, `.ini`, `.yaml`, `.yml`, `.rc`, `.service`, `.env`, `.lua`) are
  scanned, in path order. Other files are counted as `ignored`.
- A directory scan stops after `max_files` scanned files (default 200, at most 5000) or `timeout_ms` (default
  20000, at most 120000), whichever comes first, and always after at least one file. It then returns `next_cursor`
  and `stopped` (`max_files` or `timeout_ms`): pass `next_cursor` as `cursor` to continue. Analysis of one binary is
  not interrupted, so a page can run past its time budget by one file. Executables over 256 MiB and text files over
  4 MiB are skipped with their reason.
- `xrefs` looks up the functions referencing each string. It defaults to on for a file and off for a directory,
  where analysing every executable would be slow.
- `decode` runs the candidate string decoders that [`string_decoding`](mcp.md) finds in emulation (bounded as
  `string_decoding` with `evaluate`) and reads endpoints from their output.
- `kinds` keeps only rows of those kinds; `limit` caps the rows returned (default 100, at most 500). The whole
  result stays within about 56,000 bytes: rows and then groups are cut until it fits, and `endpoints_omitted` says
  how many rows were left out.

### What is found

| Kind | What |
| --- | --- |
| `url` | `http`, `https`, `ws`, `wss`, `mqtt`, `mqtts`, `coap`, `coaps`, `ftp`, `ftps`, `sftp`, `tftp`, `rtsp`, `rtsps`, `rtmp`, `rtmps` URLs. A URL whose host is built at run time (`https://%s/api`) is kept without a host. |
| `host` | A host name whose suffix the Public Suffix List knows. A two-label name outside a URL counts only under a common TLD (`com`, `net`, `org`, `io`, country codes that are not words...), since `user.name` or `self.id` are identifiers. |
| `ip` | An IPv4 dotted quad (no leading zeros, optional `:port`) or an IPv6 literal. |
| `local` | A name or address that no outside server answers: private, shared, loopback, link-local and multicast addresses, documentation ranges (RFC 5737, RFC 3849, RFC 9637), reserved names (`example`, `test`, `invalid`, `localhost`, `local`, `internal`, `home.arpa`, any `example.<suffix>`), single-label names and names under an unknown suffix. `reason` says which; `form` says whether it was a URL, host or address. |
| `pin` | `sha256/<base64>` and `pin-sha256="<base64>"` pins, and a string that is exactly a base64 SHA-256 (with `reason`, since that is a pin only by shape). `pins_certificate` names a certificate in the inventory whose public key it pins. |
| `certificate` | A PEM block or DER certificate, parsed: subject, issuer, common name, subject alternative names, expiry, self-signed and CA flags, SHA-256 and SPKI pin. Strings inside it are not reported again. |
| `package` | A reversed-DNS package or class name (`com.example.app`): not a host. |

Look-alikes are counted under `noise` with a few examples, never reported as endpoints:

| Noise | Rule |
| --- | --- |
| `version` | A dotted quad after `version`, `ver`, `build`, `release`, `firmware`, `fw`, `revision`, `rev`, `sdk` or `v` (within three words), or written `v1.2.3.4`. |
| `filename` | A name whose last label is a file extension (`config.json`, `run.sh`), a shared library (`libfoo.so.1`), or a name right after a path separator. |
| `namespace` | A URL on an XML namespace or schema host (`www.w3.org`, `schemas.android.com`, ...) or any URL in a string with `xmlns`. |
| `license` | A licence URL (`www.apache.org/licenses`, `www.gnu.org/licenses`, ...). |
| `netmask` | A dotted quad that is a contiguous mask (`255.255.255.0`). |
| `identifier` | A dotted name with mixed-case labels (`Settings.Builder`), followed by `(`, or two labels under a TLD that doubles as a word. |

### Evidence

Each row is one value in one file (`component`), with `occurrences` and up to four `evidence` items:

- `origin`: `string` (a readable string in the image, with its `address` and `encoding`), `decoded` (emulated
  decoder output, with the blob's `address` and `decoded_by`), `text` (a `line` of a text file), `bytes` (an
  `offset` in a file no loader opened) or `certificate`;
- `functions`: the functions referencing the string (`name@0xaddress`), and `network_apis`: the networking APIs those
  functions call, from the list `network_surface` uses.

`signal` ranks the row: `network_code` (referenced from a function that calls a networking API), `referenced`,
`unreferenced` (references were looked up and none found) or `not_traced`.

### Groups

- `domains`: one entry per registrable domain (or IP address), with its hosts, the components naming it, the kinds
  seen, whether it is `local` and whether any finding is tied to networking code; most components first.
- `components`: each scanned file with its format, its finding count by kind and the non-local domains it names.

Paged directory scans group within the page; merge the pages to see the whole tree.

## endpoint_blocklist

```json
{"path":"/work/rootfs","output":"/work/blocklist.conf","format":"dnsmasq","level":"domain",
 "allow":["time.vendor-cloud.example"],"deny":[],"include_local":false}
```

- The hosts come from an inventory of `path` (a file or directory; the scan must finish within `max_files` and
  `timeout_ms`, otherwise nothing is written), or from `entries`: host names, URLs or IP addresses, taken as given.
- By default only `url`, `host` and `ip` findings are written. `include_local` adds `local` ones (documentation,
  reserved and single-label names, documentation ranges); loopback, unspecified, private, link-local, shared and
  multicast addresses are never written, since blocking them at a router means nothing or cuts devices off their own
  network.
- `level`: `domain` (default) writes registrable domains, `host` the host names seen.
- `allow`: names (with everything under them), addresses or CIDR blocks that stay reachable. An allowed name under a
  domain keeps that domain at host level, so blocking the rest of the domain does not block it;
  `kept_at_host_level` lists such domains.
- `deny`: when given, only entries matching one of its patterns are written.
- `output` must be an absolute path to a new file or an existing regular file, in an existing directory; a symlink is
  refused. The list is written to a temporary file beside it and renamed over it.

| `format` | Lines | For |
| --- | --- | --- |
| `hosts` | `0.0.0.0 host` | `/etc/hosts`, routers with a hosts list. A hosts file cannot block a whole domain, so at domain level it lists the domain and every host seen under it. |
| `dnsmasq` | `address=/domain/0.0.0.0` | dnsmasq (blocks the domain and everything under it) |
| `dnsmasq_server` | `server=/domain/` | dnsmasq, answering locally only |
| `unbound` | `server:` then `local-zone: "domain" always_nxdomain` | unbound |
| `domains` | one name per line | Pi-hole and AdGuard Home lists |
| `ips` | one address per line | firewall rules |

DNS formats leave out addresses and `ips` leaves out names; `left_out` counts them, with the local, allowed and
not-denied entries. Each file starts with one `#` comment line naming the format, level and entry count.

## Limits

- Matching is lexical: addresses built at run time, encrypted or compressed data, and IPv4 addresses stored as
  integers in code are not found; strings decoded at run time are found only with `decode`, and only for decoders
  `string_decoding` recognises.
- `network_code` means a referencing function calls a networking API directly; a string passed to a helper that
  makes the call reads as `referenced`.
- The Public Suffix List is the one compiled into the `psl` crate (MPL-2.0 data; see THIRD-PARTY-NOTICES), so
  suffixes added later are unknown and names under them read as `local`.
- A blocklist blocks names and addresses, not traffic: a device can still reach a server through an address it
  hard-codes elsewhere, a DNS-over-HTTPS resolver, or a name the firmware builds at run time.
