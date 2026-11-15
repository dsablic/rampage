//! `endpoint_blocklist`: the hosts and addresses an inventory found (or the caller lists) written as a hosts file,
//! dnsmasq or unbound configuration, a plain domain list (Pi-hole, AdGuard Home) or an IP list (firewall rules).

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use crate::output_file::{check_output, write_atomically};

use serde_json::{Value, json};

use super::classify::valid_name;
use super::{Form, InventoryQuery, Kind, extract, registrable, scan};

/// Explicit entries and allow/deny patterns a call may give, and the lines quoted back in the result.
const MAX_ENTRIES: usize = 10_000;
const MAX_PATTERNS: usize = 1000;
const PREVIEW_LINES: usize = 20;
/// The first line of every file this tool writes; an existing file is replaced only when it starts with it, or
/// with `overwrite`.
const HEADER: &str = "# rampage endpoint blocklist";
/// Shared hosting, cloud and CDN domains (and everything under them). Many unrelated customers' hosts live under
/// each, so a host under one is never widened to its domain: blocking the domain would block them all.
const SHARED_INFRASTRUCTURE: [&str; 34] = [
    "amazonaws.com",
    "amazonaws.com.cn",
    "cloudfront.net",
    "elasticbeanstalk.com",
    "azure-devices.net",
    "azurewebsites.net",
    "azureedge.net",
    "azurefd.net",
    "cloudapp.net",
    "cloudapp.azure.com",
    "windows.net",
    "trafficmanager.net",
    "googleapis.com",
    "googleusercontent.com",
    "gstatic.com",
    "appspot.com",
    "firebaseio.com",
    "firebaseapp.com",
    "web.app",
    "akamai.net",
    "akamaiedge.net",
    "akamaihd.net",
    "akamaized.net",
    "akamaitechnologies.com",
    "edgekey.net",
    "edgesuite.net",
    "fastly.net",
    "fastlylb.net",
    "herokuapp.com",
    "cloudflare.net",
    "workers.dev",
    "github.io",
    "githubusercontent.com",
    "digitaloceanspaces.com",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Format {
    Hosts,
    Dnsmasq,
    DnsmasqServer,
    Unbound,
    Domains,
    Ips,
}

impl Format {
    const ALL: [(&'static str, Format); 6] = [
        ("hosts", Format::Hosts),
        ("dnsmasq", Format::Dnsmasq),
        ("dnsmasq_server", Format::DnsmasqServer),
        ("unbound", Format::Unbound),
        ("domains", Format::Domains),
        ("ips", Format::Ips),
    ];

    fn parse(name: &str) -> Result<Self, String> {
        Self::ALL.iter().find(|(known, _)| *known == name).map(|(_, format)| *format).ok_or_else(|| {
            let names: Vec<&str> = Self::ALL.iter().map(|(name, _)| *name).collect();
            format!("unknown format `{name}` (formats: {})", names.join(", "))
        })
    }

    fn name(self) -> &'static str {
        Self::ALL.iter().find(|(_, format)| *format == self).map_or("", |(name, _)| name)
    }

    /// The configuration lines blocking `entries` (names, or addresses for `Ips`).
    fn lines(self, entries: &BTreeSet<String>) -> Vec<String> {
        let mut lines = Vec::new();
        if self == Format::Unbound {
            lines.push("server:".to_owned());
        }
        lines.extend(entries.iter().map(|entry| match self {
            Format::Hosts => format!("0.0.0.0 {entry}\n:: {entry}"),
            Format::Dnsmasq => format!("address=/{entry}/0.0.0.0"),
            Format::DnsmasqServer => format!("server=/{entry}/"),
            Format::Unbound => format!("    local-zone: \"{entry}\" always_nxdomain"),
            Format::Domains | Format::Ips => entry.clone(),
        }));
        lines
    }
}

pub struct BlocklistQuery {
    /// A file or directory to inventory, or `None` with `entries`.
    pub path: Option<PathBuf>,
    pub entries: Option<Vec<String>>,
    pub output: PathBuf,
    pub format: String,
    /// `domain` (default) or `host`.
    pub level: Option<String>,
    pub allow: Vec<String>,
    pub deny: Vec<String>,
    pub include_local: bool,
    /// Replace an existing file that is not a blocklist this tool wrote.
    pub overwrite: bool,
    pub decode: bool,
    pub max_files: Option<usize>,
    pub timeout_ms: Option<u64>,
}

/// An allow or deny pattern: a name and every name under it, or an address or CIDR block.
enum Pattern {
    Name(String),
    Network(IpAddr, u8),
}

impl Pattern {
    fn parse(text: &str) -> Result<Self, String> {
        let text = text.trim().trim_start_matches("*.").trim_start_matches('.').trim_end_matches('.');
        if let Some((address, bits)) = text.split_once('/') {
            let address: IpAddr = address.parse().map_err(|_| format!("`{text}` is not a CIDR block"))?;
            let max = if address.is_ipv4() { 32 } else { 128 };
            let bits = bits.parse::<u8>().ok().filter(|bits| *bits <= max).ok_or(format!("bad prefix in `{text}`"))?;
            return Ok(Pattern::Network(address, bits));
        }
        if let Ok(address) = text.parse::<IpAddr>() {
            let bits = if address.is_ipv4() { 32 } else { 128 };
            return Ok(Pattern::Network(address, bits));
        }
        if text.is_empty() || text.contains(char::is_whitespace) {
            return Err(format!("`{text}` is not a host, domain, address or CIDR block"));
        }
        Ok(Pattern::Name(text.to_ascii_lowercase()))
    }

    fn matches(&self, entry: &str) -> bool {
        match self {
            Pattern::Name(name) => {
                entry == name || entry.strip_suffix(name.as_str()).is_some_and(|rest| rest.ends_with('.'))
            }
            Pattern::Network(network, bits) => {
                entry.parse::<IpAddr>().is_ok_and(|address| in_network(address, *network, *bits))
            }
        }
    }

    /// Whether the pattern names something strictly under `domain`.
    fn under(&self, domain: &str) -> bool {
        matches!(self, Pattern::Name(name) if name.strip_suffix(domain).is_some_and(|rest| rest.ends_with('.')))
    }
}

/// The shared-infrastructure domain `name` is, or is under, if any.
fn shared_infrastructure(name: &str) -> Option<&'static str> {
    SHARED_INFRASTRUCTURE
        .iter()
        .copied()
        .find(|domain| name == *domain || name.strip_suffix(domain).is_some_and(|rest| rest.ends_with('.')))
}

fn in_network(address: IpAddr, network: IpAddr, bits: u8) -> bool {
    match (address, network) {
        (IpAddr::V4(address), IpAddr::V4(network)) => {
            let mask = u32::MAX.checked_shl(32 - u32::from(bits)).unwrap_or(0);
            u32::from(address) & mask == u32::from(network) & mask
        }
        (IpAddr::V6(address), IpAddr::V6(network)) => {
            let mask = u128::MAX.checked_shl(128 - u32::from(bits)).unwrap_or(0);
            u128::from(address) & mask == u128::from(network) & mask
        }
        _ => false,
    }
}

fn patterns(texts: &[String], what: &str) -> Result<Vec<Pattern>, String> {
    if texts.len() > MAX_PATTERNS {
        return Err(format!("{what} takes at most {MAX_PATTERNS} patterns"));
    }
    texts.iter().map(|text| Pattern::parse(text)).collect()
}

/// The host or address an explicit entry names, which must be the whole entry: a URL (its host), an address, or a
/// host name (internationalized names become punycode).
fn entry_target(text: &str) -> Result<(String, bool), String> {
    let refused = || format!("`{}` is not one host, URL or IP address", text.escape_debug());
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(refused());
    }
    let bare = trimmed.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(trimmed);
    if let Ok(address) = bare.parse::<IpAddr>() {
        return Ok((address.to_string(), true));
    }
    if trimmed.contains("://") {
        let found = extract(trimmed).found;
        let url = found.iter().find(|candidate| candidate.form == Some(Form::Url) && candidate.value == trimmed);
        let host = url.and_then(|candidate| candidate.host.clone()).ok_or_else(refused)?;
        let address = host.parse::<IpAddr>().is_ok();
        return Ok((host, address));
    }
    let name = trimmed.trim_end_matches('.');
    let name =
        if name.is_ascii() { name.to_ascii_lowercase() } else { idna::domain_to_ascii(name).map_err(|_| refused())? };
    if valid_name(&name) { Ok((name, false)) } else { Err(refused()) }
}

/// Whether the regular file at `path` starts with [`HEADER`], so this tool wrote it.
fn is_our_blocklist(path: &Path) -> bool {
    let mut head = [0u8; HEADER.len()];
    std::fs::File::open(path).and_then(|mut file| file.read_exact(&mut head)).is_ok() && head == HEADER.as_bytes()
}

/// Builds the blocklist `query` asks for and writes it to `query.output`.
pub fn endpoint_blocklist(query: &BlocklistQuery) -> Result<Value, String> {
    let format = Format::parse(&query.format)?;
    let domain_level = match query.level.as_deref().unwrap_or("domain") {
        "domain" => true,
        "host" => false,
        other => return Err(format!("unknown level `{other}` (levels: domain, host)")),
    };
    let allow = patterns(&query.allow, "allow")?;
    let deny = patterns(&query.deny, "deny")?;
    let target = check_output("output", &query.output, query.overwrite, is_our_blocklist)?;

    let mut left_out: BTreeMap<&str, usize> = BTreeMap::new();
    // Each target: (host or address, whether it is an address).
    let mut targets: BTreeSet<(String, bool)> = BTreeSet::new();
    match (&query.path, &query.entries) {
        (Some(path), None) => {
            let inventory = scan(&InventoryQuery {
                path: path.clone(),
                cursor: None,
                max_files: query.max_files,
                timeout_ms: query.timeout_ms,
                xrefs: Some(false),
                decode: query.decode,
                kinds: None,
                limit: None,
            })?;
            if let (Some(cursor), Some(stopped)) = (&inventory.next_cursor, inventory.stopped) {
                return Err(format!(
                    "the scan stopped at {cursor} ({stopped}) before covering the tree; nothing was written. Raise \
                     max_files or timeout_ms, or pass the hosts as entries"
                ));
            }
            for row in inventory.rows.values() {
                // Blocking these at a router means nothing or cuts devices off their own network.
                if row.on_network {
                    *left_out.entry("never_blocked").or_default() += 1;
                    continue;
                }
                let wanted = matches!(row.kind, Kind::Url | Kind::Host | Kind::Ip)
                    || (row.kind == Kind::Local && query.include_local && row.form.is_some());
                if !wanted {
                    if row.kind == Kind::Local {
                        *left_out.entry("local").or_default() += 1;
                    }
                    continue;
                }
                match &row.host {
                    Some(host) => {
                        // A URL's host can be an address too.
                        targets.insert((host.clone(), host.parse::<IpAddr>().is_ok()));
                    }
                    None => *left_out.entry("url_without_literal_host").or_default() += 1,
                }
            }
        }
        (None, Some(entries)) => {
            if entries.len() > MAX_ENTRIES {
                return Err(format!("entries takes at most {MAX_ENTRIES} items"));
            }
            for entry in entries {
                targets.insert(entry_target(entry)?);
            }
        }
        _ => return Err("give exactly one of path and entries".to_owned()),
    }

    let mut names: BTreeSet<String> = BTreeSet::new();
    let mut addresses: BTreeSet<String> = BTreeSet::new();
    for (target, address) in targets {
        if allow.iter().any(|pattern| pattern.matches(&target)) {
            *left_out.entry("allowed").or_default() += 1;
        } else if !deny.is_empty() && !deny.iter().any(|pattern| pattern.matches(&target)) {
            *left_out.entry("not_denied").or_default() += 1;
        } else if address {
            addresses.insert(target);
        } else if !target.contains('.') {
            // A single-label name is no DNS name a router can block.
            *left_out.entry("single_label").or_default() += 1;
        } else if psl::domain(target.as_bytes()).is_none() {
            // A public suffix itself (`co.uk`, `s3.amazonaws.com`): blocking it blocks every domain under it.
            *left_out.entry("public_suffix").or_default() += 1;
        } else {
            names.insert(target);
        }
    }

    // Domain (or host) to why its hosts stay listed one by one.
    let mut kept_at_host_level: BTreeMap<String, &str> = BTreeMap::new();
    if domain_level {
        let mut by_domain: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut reduced = BTreeSet::new();
        for name in &names {
            // Under a shared cloud or CDN domain, even the suffix list's registrable name can be shared by many
            // customers (`iot.us-east-1.amazonaws.com`), so such hosts are never widened.
            if let Some(shared) = shared_infrastructure(name) {
                kept_at_host_level
                    .insert(shared.to_owned(), "shared hosting or cloud domain: other customers use it too");
                reduced.insert(name.clone());
                continue;
            }
            let domain = registrable(name);
            by_domain.entry(domain).or_default().push(name.clone());
        }
        for (domain, hosts) in by_domain {
            let why = if allow.iter().any(|pattern| pattern.under(&domain)) {
                Some("allow keeps a name under it reachable")
            } else if !deny.is_empty() && !deny.iter().any(|pattern| pattern.matches(&domain)) {
                Some("deny names hosts under it, not the whole domain")
            } else {
                None
            };
            if let Some(why) = why {
                kept_at_host_level.insert(domain, why);
                reduced.extend(hosts);
            } else {
                // A hosts file cannot block a whole domain, so it lists the domain and every host seen under it.
                if format == Format::Hosts {
                    reduced.extend(hosts);
                }
                reduced.insert(domain);
            }
        }
        names = reduced;
    }
    let entries = if format == Format::Ips {
        if !names.is_empty() {
            left_out.insert("names_in_ip_format", names.len());
        }
        addresses
    } else {
        if !addresses.is_empty() {
            left_out.insert("addresses_in_dns_format", addresses.len());
        }
        names
    };
    if entries.is_empty() {
        let reasons: Vec<String> = left_out.iter().map(|(reason, count)| format!("{count} {reason}")).collect();
        return Err(format!(
            "nothing to write: no entries remain after filtering (left out: {}); nothing was written. Local names and \
             addresses need include_local; IP findings need format ips",
            if reasons.is_empty() { "none".to_owned() } else { reasons.join(", ") }
        ));
    }
    let level = if domain_level { "domain" } else { "host" };
    let count = if entries.len() == 1 { "1 entry".to_owned() } else { format!("{} entries", entries.len()) };
    let mut lines = vec![format!("{HEADER} ({} format, {level} level): {count}", format.name())];
    lines.extend(format.lines(&entries));
    let mut text = lines.join("\n");
    text.push('\n');
    write_atomically(&target, text.as_bytes())?;
    let kept_at_host_level: Vec<Value> =
        kept_at_host_level.iter().map(|(domain, reason)| json!({"domain": domain, "reason": reason})).collect();
    Ok(json!({
        "output": target.path(),
        "replaced": target.replaces(),
        "format": format.name(),
        "level": level,
        "entries": entries.len(),
        "bytes": text.len(),
        "preview": lines.iter().take(PREVIEW_LINES).collect::<Vec<_>>(),
        "left_out": left_out,
        "kept_at_host_level": kept_at_host_level,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_match_names_under_them_and_cidr_blocks() {
        let name = Pattern::parse("*.vendor-cloud.example").unwrap();
        assert!(name.matches("vendor-cloud.example") && name.matches("a.vendor-cloud.example"));
        assert!(!name.matches("evilvendor-cloud.example"));
        assert!(name.under("example") && !name.under("vendor-cloud.example"));
        let block = Pattern::parse("198.51.100.0/24").unwrap();
        assert!(block.matches("198.51.100.7") && !block.matches("198.51.101.7") && !block.matches("2001:db8::1"));
        let six = Pattern::parse("2001:db8::/32").unwrap();
        assert!(six.matches("2001:db8:10::25"));
        assert!(Pattern::parse("10.0.0.0/33").is_err());
        assert!(Pattern::parse("not a name").is_err());
    }

    #[test]
    fn shared_infrastructure_matches_whole_labels() {
        // The suffix list widens this host only to a name AWS shares among customers.
        assert_eq!(registrable("abc-ats.iot.us-east-1.amazonaws.com"), "iot.us-east-1.amazonaws.com");
        assert_eq!(shared_infrastructure("abc-ats.iot.us-east-1.amazonaws.com"), Some("amazonaws.com"));
        assert_eq!(shared_infrastructure("amazonaws.com"), Some("amazonaws.com"));
        assert_eq!(shared_infrastructure("notamazonaws.com"), None);
    }

    #[test]
    fn explicit_entries_name_hosts_and_addresses() {
        assert_eq!(
            entry_target("https://Telemetry.Vendor-Cloud.example/x").unwrap(),
            ("telemetry.vendor-cloud.example".to_owned(), false)
        );
        assert_eq!(entry_target("[2001:db8::1]").unwrap(), ("2001:db8::1".to_owned(), true));
        assert_eq!(
            entry_target("updates.vendor-cloud.example.").unwrap(),
            ("updates.vendor-cloud.example".to_owned(), false)
        );
        assert!(entry_target("not a host").is_err());
        assert!(entry_target("foo bar.com").is_err());
        assert!(entry_target("a.example.com\nb.example.com").is_err());
        assert!(entry_target("https://a.example.com/x y").is_err());
        assert_eq!(entry_target("bücher.example").unwrap(), ("xn--bcher-kva.example".to_owned(), false));
        assert_eq!(entry_target("https://203.0.113.9:8443/x").unwrap(), ("203.0.113.9".to_owned(), true));
    }
}
