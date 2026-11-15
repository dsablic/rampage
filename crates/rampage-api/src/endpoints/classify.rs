//! Lexical endpoint extraction: URLs, host names, IPv4 and IPv6 literals and certificate pins in one piece of text,
//! each classified, with the look-alikes (version numbers, file names, package names, XML namespaces, netmasks,
//! identifiers) counted as noise instead. Host names are checked against the bundled Public Suffix List.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::Serialize;

/// What a finding is. `local` holds the network names and addresses that never leave the device's network or name
/// no real peer: private, loopback and link-local addresses, documentation names and ranges, single-label names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Url,
    Host,
    Ip,
    Local,
    Pin,
    Certificate,
    Package,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Url => "url",
            Self::Host => "host",
            Self::Ip => "ip",
            Self::Local => "local",
            Self::Pin => "pin",
            Self::Certificate => "certificate",
            Self::Package => "package",
        }
    }

    /// The kind called `name`.
    pub fn parse(name: &str) -> Option<Self> {
        [Self::Url, Self::Host, Self::Ip, Self::Local, Self::Pin, Self::Certificate, Self::Package]
            .into_iter()
            .find(|kind| kind.name() == name)
    }
}

/// The shape of a network finding, kept for `local` ones too.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Form {
    Url,
    Host,
    Ip,
}

/// Why a look-alike was not taken as an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Noise {
    /// A dotted quad in a version context (`version 1.2.3.4`, `v1.2.3.4`).
    Version,
    /// A file name or library (`config.json`, `libfoo.so.1`) or a name after a path separator.
    Filename,
    /// An XML namespace or schema URI (`xmlns`, w3.org, schemas.android.com).
    Namespace,
    /// A licence or specification URL.
    License,
    /// A dotted quad that is a netmask (`255.255.255.0`).
    Netmask,
    /// A dotted identifier (`Settings.Builder`, `obj.method(`, a word under a TLD that doubles as one).
    Identifier,
}

impl Noise {
    pub fn name(self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Filename => "filename",
            Self::Namespace => "namespace",
            Self::License => "license",
            Self::Netmask => "netmask",
            Self::Identifier => "identifier",
        }
    }
}

/// One endpoint found in a text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub kind: Kind,
    /// The URL, host, address, pin or package as written (hosts lowercased).
    pub value: String,
    /// The shape of a network finding (also for `local`).
    pub form: Option<Form>,
    /// The host a URL names, or the host or address itself; `None` for a URL whose host is built at run time.
    pub host: Option<String>,
    /// The registrable domain of `host` (Public Suffix List), or the last two labels under a reserved name.
    pub domain: Option<String>,
    /// Why a finding is `local`, or a note on its form (an e-mail address's domain, a bare pin).
    pub reason: Option<&'static str>,
    /// A name or address that only the device, its host or its own network answers (loopback, private,
    /// link-local, multicast, single-label...): never written to a blocklist.
    pub on_network: bool,
}

#[derive(Debug, Default)]
pub struct Extracted {
    pub found: Vec<Candidate>,
    pub noise: Vec<(Noise, String)>,
}

/// URL schemes taken as network endpoints.
const SCHEMES: [&str; 16] = [
    "http", "https", "ws", "wss", "mqtt", "mqtts", "coap", "coaps", "ftp", "ftps", "sftp", "rtsp", "rtsps", "rtmp",
    "rtmps", "tftp",
];

/// Hosts that serve XML namespaces and schemas, not device traffic.
const NAMESPACE_HOSTS: [&str; 12] = [
    "w3.org",
    "www.w3.org",
    "schemas.android.com",
    "schemas.xmlsoap.org",
    "schemas.microsoft.com",
    "schemas.openxmlformats.org",
    "purl.org",
    "ns.adobe.com",
    "xmlns.com",
    "www.xml.org",
    "xml.org",
    "java.sun.com",
];

/// URL prefixes (host and path) of licence texts, which appear in notices, not traffic.
const LICENSE_URLS: [&str; 6] = [
    "www.gnu.org/licenses",
    "gnu.org/licenses",
    "www.apache.org/licenses",
    "apache.org/licenses",
    "opensource.org/licenses",
    "creativecommons.org/licenses",
];

/// Last labels that are file extensions: a dotted name ending in one is a file name. Some are also TLDs (`so`,
/// `sh`, `py`, `pl`, `md`, `rs`, `cc`, `zip`, `mov`), which is why the list wins over the suffix list.
const FILE_EXTENSIONS: [&str; 78] = [
    "a",
    "o",
    "so",
    "ko",
    "sh",
    "bash",
    "py",
    "pyc",
    "pl",
    "pm",
    "rb",
    "rs",
    "go",
    "md",
    "cc",
    "cpp",
    "cxx",
    "c",
    "h",
    "hh",
    "hpp",
    "js",
    "mjs",
    "ts",
    "json",
    "xml",
    "html",
    "htm",
    "css",
    "txt",
    "log",
    "conf",
    "cfg",
    "ini",
    "prop",
    "properties",
    "yaml",
    "yml",
    "toml",
    "dat",
    "bin",
    "img",
    "zip",
    "gz",
    "tgz",
    "xz",
    "bz2",
    "tar",
    "lz4",
    "zst",
    "png",
    "jpg",
    "jpeg",
    "gif",
    "bmp",
    "svg",
    "ico",
    "mp3",
    "mp4",
    "mov",
    "wav",
    "ogg",
    "apk",
    "dex",
    "jar",
    "class",
    "lua",
    "exe",
    "dll",
    "sys",
    "pem",
    "crt",
    "der",
    "key",
    "db",
    "pid",
    "sock",
    "service",
];

/// First labels of reversed-DNS package and class names (`com.example.app`).
const PACKAGE_ROOTS: [&str; 16] = [
    "com", "org", "net", "edu", "gov", "io", "android", "androidx", "java", "javax", "kotlin", "kotlinx", "dalvik",
    "sun", "de", "uk",
];

/// TLDs a reversed-DNS package name never ends in: a dotted name starting with a package root (`net.`, `io.`)
/// but ending in one of these is a host (`io.x-cloud.com`, `net.vendor-cloud.org`).
const CLASSIC_TLDS: [&str; 11] = ["com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "io", "co"];

/// Second labels of Linux sysctl keys (`net.core.somaxconn`), which read as package names but are neither.
const SYSCTL_GROUPS: [&str; 8] = ["ipv4", "ipv6", "core", "unix", "netfilter", "bridge", "nf_conntrack_max", "inet"];

/// TLDs that a two-label name outside a URL may end in. Other suffixes double as words in dotted identifiers
/// (`user.name`, `self.id`, `this.is`), so such names count only inside URLs or with three or more labels.
const STRONG_TLDS: [&str; 47] = [
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "io", "co", "tv", "cloud", "app", "dev", "xyz",
    "top", "online", "site", "tech", "onion", "cn", "de", "uk", "jp", "kr", "ru", "fr", "nl", "eu", "us", "ca", "au",
    "br", "es", "se", "ch", "tw", "hk", "sg", "vn", "tr", "ua", "cz", "dk", "fi", "pl",
];

/// Words among the three before a dotted quad that make it a version number.
const VERSION_WORDS: [&str; 10] =
    ["version", "ver", "build", "release", "firmware", "fw", "revision", "rev", "sdk", "v"];

/// Reserved top-level names (RFC 2606, RFC 6761, RFC 6762, the `internal` TLD) and why each is local.
const RESERVED_TLDS: [(&str, &str); 6] = [
    ("example", "documentation name (RFC 2606)"),
    ("test", "reserved test name (RFC 2606)"),
    ("invalid", "reserved invalid name (RFC 2606)"),
    ("localhost", "loopback name (RFC 6761)"),
    ("local", "multicast DNS name (RFC 6762)"),
    ("internal", "private-use name (internal TLD)"),
];

/// Every endpoint in `text`, plus the look-alikes taken as noise.
pub fn extract(text: &str) -> Extracted {
    let mut extracted = Extracted::default();
    // Spans already taken (URLs, pins), blanked before the token pass.
    let mut taken: Vec<(usize, usize)> = Vec::new();
    let lower = text.to_ascii_lowercase();
    let namespaced = lower.contains("xmlns");

    let mut search = 0;
    while let Some(found) = lower[search..].find("://") {
        let at = search + found;
        search = at + 3;
        let scheme_start =
            lower[..at].rfind(|c: char| !(c.is_ascii_alphanumeric() || "+.-".contains(c))).map_or(0, |index| index + 1);
        let scheme = &lower[scheme_start..at];
        if !SCHEMES.contains(&scheme) {
            continue;
        }
        let rest = &text[search..];
        let end = rest.find(|c: char| c.is_whitespace() || "\"'<>`{}|\\^".contains(c)).unwrap_or(rest.len());
        let url = text[scheme_start..search + end].trim_end_matches(['.', ',', ';', ')', ']', '}']);
        if url.len() <= scheme.len() + 3 {
            continue;
        }
        taken.push((scheme_start, scheme_start + url.len()));
        search = scheme_start + url.len();
        if namespaced {
            extracted.noise.push((Noise::Namespace, url.to_owned()));
            continue;
        }
        classify_url(url, scheme.len() + 3, &mut extracted);
    }

    pins(text, &lower, &mut taken, &mut extracted);

    let mut blanked = text.as_bytes().to_vec();
    for &(start, end) in &taken {
        blanked[start..end].fill(b' ');
    }
    let blanked = String::from_utf8_lossy(&blanked).into_owned();
    let token_char = |c: char| c.is_ascii_alphanumeric() || "._:%-".contains(c);
    let mut index = 0;
    let bytes = blanked.as_bytes();
    while index < bytes.len() {
        if !token_char(bytes[index] as char) {
            index += 1;
            continue;
        }
        let start = index;
        while index < bytes.len() && token_char(bytes[index] as char) {
            index += 1;
        }
        let before = blanked[..start].chars().next_back();
        let after = blanked[index..].chars().next();
        token(&blanked[start..index], before, after, &lower[..start], &mut extracted);
    }
    extracted
}

/// Classifies one URL whose authority starts at byte `authority`.
fn classify_url(url: &str, authority: usize, extracted: &mut Extracted) {
    let rest = &url[authority..];
    let lower_rest = rest.to_ascii_lowercase();
    if LICENSE_URLS.iter().any(|prefix| lower_rest.starts_with(prefix)) {
        extracted.noise.push((Noise::License, url.to_owned()));
        return;
    }
    let host_part = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let host_part = host_part.rsplit_once('@').map_or(host_part, |(_, host)| host);
    let host = if let Some(bracketed) = host_part.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or("")
    } else {
        host_part.split(':').next().unwrap_or("")
    };
    let mut candidate = Candidate {
        kind: Kind::Url,
        value: url.to_owned(),
        form: Some(Form::Url),
        host: None,
        domain: None,
        reason: None,
        on_network: false,
    };
    if host.is_empty() {
        return;
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        candidate.host = Some(address.to_string());
        if let Some(local) = local_address(address) {
            candidate.kind = Kind::Local;
            candidate.reason = Some(local.reason);
            candidate.on_network = local.on_network;
        }
        extracted.found.push(candidate);
        return;
    }
    let host = host.trim_end_matches('.');
    let name = if host.is_ascii() {
        host.to_ascii_lowercase()
    } else {
        // An internationalized name, written as its punycode (ASCII) form, which is what DNS carries.
        match idna::domain_to_ascii(host) {
            Ok(ascii) if !ascii.is_empty() => ascii,
            _ => {
                candidate.reason = Some("host is not a valid internationalized name");
                extracted.found.push(candidate);
                return;
            }
        }
    };
    if !valid_name(&name) {
        // A host built at run time (`%s`, `{host}`) or not a name at all: the URL is kept, its host is unknown.
        candidate.reason = Some("host is not a literal name (built at run time)");
        extracted.found.push(candidate);
        return;
    }
    if NAMESPACE_HOSTS.contains(&name.as_str()) {
        extracted.noise.push((Noise::Namespace, url.to_owned()));
        return;
    }
    candidate.domain = Some(registrable(&name));
    if let Some(reason) = reserved(&name) {
        candidate.kind = Kind::Local;
        candidate.reason = Some(reason);
        candidate.on_network = on_network_name(&name);
    } else if !name.contains('.') {
        candidate.kind = Kind::Local;
        candidate.reason = Some("single-label name (resolves only on a local network)");
        candidate.on_network = true;
    } else if !known_suffix(&name) {
        candidate.kind = Kind::Local;
        candidate.reason = Some("name under a suffix the public suffix list does not know (a local network name)");
    }
    candidate.host = Some(name);
    extracted.found.push(candidate);
}

/// `sha256/<base64>` and `pin-sha256="<base64>"` pins, and a whole text that is a bare base64 SHA-256.
fn pins(text: &str, lower: &str, taken: &mut Vec<(usize, usize)>, extracted: &mut Extracted) {
    for prefix in ["sha256/", "pin-sha256=\"", "pin-sha256='"] {
        let mut search = 0;
        while let Some(found) = lower[search..].find(prefix) {
            let start = search + found;
            let value_start = start + prefix.len();
            search = value_start;
            let Some(value) = text.get(value_start..value_start + 44) else { continue };
            if !is_sha256_base64(value) || taken.iter().any(|&(from, to)| start < to && value_start + 44 > from) {
                continue;
            }
            taken.push((start, value_start + 44));
            let written = if prefix == "sha256/" { format!("sha256/{value}") } else { value.to_owned() };
            extracted.found.push(Candidate {
                kind: Kind::Pin,
                value: written,
                form: None,
                host: None,
                domain: None,
                reason: None,
                on_network: false,
            });
        }
    }
    let trimmed = text.trim();
    if taken.is_empty() && is_sha256_base64(trimmed) {
        taken.push((0, text.len()));
        extracted.found.push(Candidate {
            kind: Kind::Pin,
            value: trimmed.to_owned(),
            form: None,
            host: None,
            domain: None,
            reason: Some("bare base64 SHA-256 digest, a pin only by shape"),
            on_network: false,
        });
    }
}

/// 43 base64 characters and one `=`: exactly 32 bytes, the size of a SHA-256 digest.
pub fn is_sha256_base64(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 44
        && bytes[43] == b'='
        && bytes[..43].iter().all(|&byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
        // The last character carries 2 bits of padding, which must be zero.
        && b"AEIMQUYcgkosw048".contains(&bytes[42])
        && bytes[..43].iter().any(u8::is_ascii_digit)
        && bytes[..43].iter().any(u8::is_ascii_lowercase)
        && bytes[..43].iter().any(u8::is_ascii_uppercase)
}

/// Classifies a token outside URLs and pins. `before` and `after` are the characters around it, `prefix` the
/// lowercased text before it.
fn token(raw: &str, before: Option<char>, after: Option<char>, prefix: &str, extracted: &mut Extracted) {
    let token = raw.trim_end_matches(['.', '-']);
    let token = if token.starts_with("::") { token } else { token.trim_end_matches(':') };
    let token = token.trim_start_matches(['.', '-']);
    if token.is_empty() || token.contains('%') {
        return;
    }
    if let Some(address) = ipv4(token) {
        let mut words = prefix.rsplit(|c: char| !c.is_ascii_alphanumeric()).filter(|word| !word.is_empty());
        if words.by_ref().take(3).any(|word| VERSION_WORDS.contains(&word) || word.starts_with("version")) {
            extracted.noise.push((Noise::Version, token.to_owned()));
            return;
        }
        if is_netmask(address) {
            extracted.noise.push((Noise::Netmask, token.to_owned()));
            return;
        }
        push_ip(IpAddr::V4(address), token, extracted);
        return;
    }
    if is_version_token(token) {
        extracted.noise.push((Noise::Version, token.to_owned()));
        return;
    }
    if token.contains(':') {
        let bare = token.trim_start_matches('[').trim_end_matches(']');
        if let Ok(address) = bare.parse::<Ipv6Addr>()
            && bare.matches(':').count() >= 2
            && bare.bytes().any(|byte| byte.is_ascii_digit())
        {
            push_ip(IpAddr::V6(address), bare, extracted);
            return;
        }
        // host:port
        let Some((host, port)) = token.split_once(':') else { return };
        if port.parse::<u16>().is_err() {
            return;
        }
        host_token(host, before, after, extracted);
        return;
    }
    host_token(token, before, after, extracted);
}

fn host_token(token: &str, before: Option<char>, after: Option<char>, extracted: &mut Extracted) {
    if token.contains('_') || !token.contains('.') {
        return;
    }
    let labels: Vec<&str> = token.split('.').collect();
    if labels.iter().any(|label| label.is_empty()) {
        return;
    }
    let lower = token.to_ascii_lowercase();
    let lower_labels: Vec<&str> = lower.split('.').collect();
    let last = *lower_labels.last().expect("split yields one label");
    if labels.len() >= 3
        && PACKAGE_ROOTS.contains(&lower_labels[0])
        && labels.iter().all(|label| label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-'))
        && !ends_like_a_host(&lower_labels)
    {
        if lower_labels[0] == "net" && SYSCTL_GROUPS.contains(&lower_labels[1]) {
            return;
        }
        extracted.found.push(Candidate {
            kind: Kind::Package,
            value: token.to_owned(),
            form: None,
            host: None,
            domain: None,
            reason: None,
            on_network: false,
        });
        return;
    }
    if matches!(before, Some('/' | '\\')) || FILE_EXTENSIONS.contains(&last) || is_library_name(&lower_labels) {
        extracted.noise.push((Noise::Filename, token.to_owned()));
        return;
    }
    // DNS names are case-insensitive (`Api.Vendor-Cloud.com` is a host); a mixed-case last label is a type or
    // member name (`Settings.Builder`), and so is a name before `(`.
    let original_last = labels.last().expect("split yields one label");
    let mixed_last = original_last.bytes().any(|byte| byte.is_ascii_uppercase())
        && original_last.bytes().any(|byte| byte.is_ascii_lowercase());
    if mixed_last || after == Some('(') {
        extracted.noise.push((Noise::Identifier, token.to_owned()));
        return;
    }
    if last.bytes().all(|byte| byte.is_ascii_digit()) || !valid_name(&lower) {
        return;
    }
    let mixed_case = labels.iter().any(|label| {
        label.bytes().any(|byte| byte.is_ascii_uppercase()) && label.bytes().any(|byte| byte.is_ascii_lowercase())
    });
    if NAMESPACE_HOSTS.contains(&lower.as_str()) {
        extracted.noise.push((Noise::Namespace, token.to_owned()));
        return;
    }
    let mut candidate = Candidate {
        kind: Kind::Host,
        value: lower.clone(),
        form: Some(Form::Host),
        host: Some(lower.clone()),
        domain: Some(registrable(&lower)),
        reason: (before == Some('@')).then_some("domain of an e-mail address"),
        on_network: false,
    };
    if let Some(reason) = reserved(&lower) {
        // Two-label names under the word-like reserved TLDs (`unit.test`, `value.invalid`) are identifiers.
        if labels.len() == 2 && !["example", "localhost", "local"].contains(&last) {
            return;
        }
        candidate.kind = Kind::Local;
        candidate.reason = Some(reason);
        candidate.on_network = on_network_name(&lower);
    } else if !known_suffix(&lower) {
        if mixed_case {
            extracted.noise.push((Noise::Identifier, token.to_owned()));
        }
        return;
    } else if labels.len() == 2 && !STRONG_TLDS.contains(&last) {
        extracted.noise.push((Noise::Identifier, token.to_owned()));
        return;
    }
    extracted.found.push(candidate);
}

fn push_ip(address: IpAddr, written: &str, extracted: &mut Extracted) {
    let local = local_address(address);
    extracted.found.push(Candidate {
        kind: if local.is_some() { Kind::Local } else { Kind::Ip },
        value: written.to_owned(),
        form: Some(Form::Ip),
        host: Some(address.to_string()),
        domain: None,
        reason: local.map(|local| local.reason),
        on_network: local.is_some_and(|local| local.on_network),
    });
}

/// Endings a reversed-DNS package name does not have but a host does: the classic generic TLDs, or a country code
/// in a name of four or more labels or one that starts with a country code too (`de.pool.ntp.org`).
fn ends_like_a_host(labels: &[&str]) -> bool {
    let last = labels[labels.len() - 1];
    let country =
        |label: &str| label.len() == 2 && psl::suffix(label.as_bytes()).is_some_and(|suffix| suffix.is_known());
    CLASSIC_TLDS.contains(&last) || country(last) && (labels.len() >= 4 || country(labels[0]))
}

/// Whether a reserved name resolves only on the device or its own network (`localhost`, mDNS `.local`, `home.arpa`)
/// rather than naming nothing at all (documentation and test names).
fn on_network_name(name: &str) -> bool {
    let last = name.rsplit('.').next().unwrap_or(name);
    matches!(last, "localhost" | "local" | "internal") || name == "home.arpa" || name.ends_with(".home.arpa")
}

/// A dotted quad without leading zeros (which some parsers read as octal), optionally followed by `:port`.
fn ipv4(token: &str) -> Option<Ipv4Addr> {
    let (address, port) = match token.split_once(':') {
        Some((address, port)) => (address, Some(port)),
        None => (token, None),
    };
    if port.is_some_and(|port| port.parse::<u16>().is_err()) {
        return None;
    }
    let octets: Vec<&str> = address.split('.').collect();
    if octets.len() != 4
        || octets.iter().any(|octet| octet.is_empty() || octet.len() > 3 || octet.len() > 1 && octet.starts_with('0'))
    {
        return None;
    }
    address.parse().ok()
}

/// `v1.2.3.4`, `V2.10.0.1`: a version number written with a leading `v`.
fn is_version_token(token: &str) -> bool {
    token
        .strip_prefix(['v', 'V'])
        .is_some_and(|rest| rest.split('.').count() >= 2 && rest.split('.').all(|part| part.parse::<u32>().is_ok()))
}

/// A contiguous run of one bits from the top, at least a /8 and short of all ones.
fn is_netmask(address: Ipv4Addr) -> bool {
    let bits = u32::from(address);
    bits != u32::MAX && bits >= 0xff00_0000 && (!bits).wrapping_add(1).is_power_of_two()
}

/// `libfoo.so.1`, `libc.so.6.0`: a shared library name with a version after `.so`.
fn is_library_name(labels: &[&str]) -> bool {
    labels.iter().position(|label| *label == "so").is_some_and(|at| {
        at > 0 && labels[at + 1..].iter().all(|label| label.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

/// Labels of 1..=63 letters, digits and hyphens, not starting or ending with a hyphen, 253 bytes at most.
pub(super) fn valid_name(name: &str) -> bool {
    name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        && name.bytes().any(|byte| byte.is_ascii_alphabetic())
}

/// Whether the Public Suffix List knows `name`'s suffix (its TLD at least).
fn known_suffix(name: &str) -> bool {
    psl::suffix(name.as_bytes()).is_some_and(|suffix| suffix.is_known())
}

/// The registrable domain of a lowercase name: one label under its public suffix (the list's private section
/// included, so `x.github.io` stays itself), or under the TLD when the list does not know it (reserved and local
/// names), or the name itself when it is a public suffix or has no registrable part.
pub fn registrable(name: &str) -> String {
    psl::domain(name.as_bytes())
        .and_then(|domain| std::str::from_utf8(domain.as_bytes()).ok().map(str::to_owned))
        .unwrap_or_else(|| name.to_owned())
}

/// Why a lowercase name is reserved, if it is: a reserved TLD, `localhost`, or a documentation domain
/// (`example.com`, `example.co.uk`).
fn reserved(name: &str) -> Option<&'static str> {
    let last = name.rsplit('.').next().unwrap_or(name);
    if let Some((_, reason)) = RESERVED_TLDS.iter().find(|(tld, _)| *tld == last) {
        return Some(reason);
    }
    if name.ends_with(".home.arpa") || name == "home.arpa" {
        return Some("home network name (RFC 8375)");
    }
    let domain = registrable(name);
    (domain.split('.').next() == Some("example") && known_suffix(name)).then_some("documentation name (RFC 2606)")
}

/// Why an address is local, and whether it is on the device's own host or network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Local {
    pub reason: &'static str,
    /// Loopback, unspecified, private, shared, link-local, site-local, multicast, broadcast and reserved addresses;
    /// not documentation and benchmarking ranges, which name nothing.
    pub on_network: bool,
}

/// Why an address is local, if it is: unspecified, loopback, private, shared, link-local, documentation,
/// benchmarking, multicast, broadcast or reserved.
pub fn local_address(address: IpAddr) -> Option<Local> {
    let on_network = |reason| Some(Local { reason, on_network: true });
    let names_nothing = |reason| Some(Local { reason, on_network: false });
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, _] = address.octets();
            match (a, b, c) {
                (0, ..) => on_network("unspecified or this-network address"),
                (127, ..) => on_network("loopback address"),
                (10, ..) | (172, 16..=31, _) | (192, 168, _) => on_network("private address (RFC 1918)"),
                (100, 64..=127, _) => on_network("shared address space (RFC 6598)"),
                (169, 254, _) => on_network("link-local address"),
                (192, 0, 2) | (198, 51, 100) | (203, 0, 113) => names_nothing("documentation range (RFC 5737)"),
                (198, 18..=19, _) => names_nothing("benchmarking range (RFC 2544)"),
                (192, 0, 0) => on_network("IETF protocol assignment"),
                (224..=239, ..) => on_network("multicast address"),
                (240..=255, ..) => on_network("reserved or broadcast address"),
                _ => None,
            }
        }
        IpAddr::V6(address) => {
            if let Some(mapped) = address.to_ipv4_mapped() {
                return local_address(IpAddr::V4(mapped));
            }
            let segments = address.segments();
            if address.is_unspecified() {
                on_network("unspecified address")
            } else if address.is_loopback() {
                on_network("loopback address")
            } else if segments[0] & 0xffc0 == 0xfe80 {
                on_network("link-local address")
            } else if segments[0] & 0xffc0 == 0xfec0 {
                on_network("site-local address (deprecated)")
            } else if segments[0] & 0xfe00 == 0xfc00 {
                on_network("unique local address (RFC 4193)")
            } else if segments[0] == 0x2001 && segments[1] == 0x0db8 {
                names_nothing("documentation range (RFC 3849)")
            } else if segments[0] == 0x3fff && segments[1] & 0xf000 == 0 {
                names_nothing("documentation range (RFC 9637)")
            } else if segments[0] & 0xff00 == 0xff00 {
                on_network("multicast address")
            } else {
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<(Kind, String)> {
        extract(text).found.into_iter().map(|found| (found.kind, found.value)).collect()
    }

    fn noise(text: &str) -> Vec<Noise> {
        extract(text).noise.into_iter().map(|(noise, _)| noise).collect()
    }

    #[test]
    fn urls_of_every_scheme_name_their_host_and_domain() {
        for scheme in SCHEMES {
            let url = format!("{scheme}://pool.ntp.org:1234/path?q=1");
            let found = extract(&format!("connect to {url}, then")).found;
            assert_eq!(found.len(), 1, "{scheme}: {found:?}");
            assert_eq!((found[0].kind, found[0].value.as_str()), (Kind::Url, url.as_str()));
            assert_eq!(found[0].host.as_deref(), Some("pool.ntp.org"));
            assert_eq!(found[0].domain.as_deref(), Some("ntp.org"));
        }
        let found = &extract("\"https://user@[2001:db8::7]:8443/x\"").found[0];
        assert_eq!((found.kind, found.host.as_deref()), (Kind::Local, Some("2001:db8::7")));
        let found = &extract("https://%s/api/v1").found[0];
        assert_eq!((found.kind, found.host.as_deref()), (Kind::Url, None));
    }

    #[test]
    fn hosts_ips_and_pins() {
        assert_eq!(kinds("ntpd -p pool.ntp.org"), [(Kind::Host, "pool.ntp.org".to_owned())]);
        assert_eq!(kinds("peer 45.13.7.9:443 up"), [(Kind::Ip, "45.13.7.9:443".to_owned())]);
        assert_eq!(kinds("2a01:5:1::7"), [(Kind::Ip, "2a01:5:1::7".to_owned())]);
        let pin = "sha256/DYZYMp8/e065XzTsuXKwdXrutL9ps0MnN5ZfB4jjjIs=";
        assert_eq!(kinds(pin), [(Kind::Pin, pin.to_owned())]);
        assert_eq!(
            kinds("pin-sha256=\"DYZYMp8/e065XzTsuXKwdXrutL9ps0MnN5ZfB4jjjIs=\"; max-age=1"),
            [(Kind::Pin, "DYZYMp8/e065XzTsuXKwdXrutL9ps0MnN5ZfB4jjjIs=".to_owned())]
        );
        let bare = &extract("DYZYMp8/e065XzTsuXKwdXrutL9ps0MnN5ZfB4jjjIs=").found[0];
        assert_eq!((bare.kind, bare.reason.is_some()), (Kind::Pin, true));
        assert!(kinds("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_empty());
        let mail = &extract("support@vendor-cloud.example").found[0];
        assert_eq!(mail.reason, Some("documentation name (RFC 2606)"));
    }

    #[test]
    fn local_names_and_addresses_are_labelled_not_dropped() {
        for (text, reason) in [
            ("192.168.1.1", "private address (RFC 1918)"),
            ("10.0.0.1", "private address (RFC 1918)"),
            ("169.254.0.7", "link-local address"),
            ("127.0.0.1", "loopback address"),
            ("203.0.113.45", "documentation range (RFC 5737)"),
            ("fe80::1", "link-local address"),
            ("::1", "loopback address"),
            ("fd00:1::2", "unique local address (RFC 4193)"),
            ("3fff:10::5", "documentation range (RFC 9637)"),
            ("updates.example.com", "documentation name (RFC 2606)"),
            ("cdn.example.co.uk", "documentation name (RFC 2606)"),
            ("broker.vendor-cloud.example", "documentation name (RFC 2606)"),
            ("a.b.test", "reserved test name (RFC 2606)"),
            ("printer.local", "multicast DNS name (RFC 6762)"),
        ] {
            let found = extract(text).found;
            assert_eq!(found.len(), 1, "{text}: {found:?}");
            assert_eq!((found[0].kind, found[0].reason), (Kind::Local, Some(reason)), "{text}");
        }
        let localhost = &extract("http://localhost:8080/debug").found[0];
        assert_eq!((localhost.kind, localhost.form), (Kind::Local, Some(Form::Url)));
        let router = &extract("http://router/admin").found[0];
        assert_eq!(router.kind, Kind::Local);
        assert_eq!(extract("cdn.example.co.uk").found[0].domain.as_deref(), Some("example.co.uk"));
    }

    #[test]
    fn noise_is_counted_not_reported() {
        for (text, expected) in [
            ("firmware version 1.2.3.4", Noise::Version),
            ("v2.10.0.1", Noise::Version),
            ("ro.build.version=4.2.1.0", Noise::Version),
            ("libfoo.so.1", Noise::Filename),
            ("config.json", Noise::Filename),
            ("run.sh", Noise::Filename),
            ("/opt/network.de", Noise::Filename),
            ("http://www.w3.org/2001/XMLSchema-instance", Noise::Namespace),
            ("xmlns:android=\"http://schemas.android.com/apk/res/android\"", Noise::Namespace),
            ("see http://www.apache.org/licenses/LICENSE-2.0", Noise::License),
            ("netmask 255.255.255.0", Noise::Netmask),
            ("Settings.Builder", Noise::Identifier),
            ("call obj.connect() now", Noise::Identifier),
            ("user.name", Noise::Identifier),
        ] {
            assert_eq!(noise(text), [expected], "{text}");
            assert!(extract(text).found.is_empty(), "{text}: {:?}", extract(text).found);
        }
        for text in [
            "1.2.3.4.5",
            "256.1.1.1",
            "01.02.03.04",
            "GLIBC_2.2.5",
            "my_host.example.com",
            "std::vector",
            "12:30:45",
            "net.core.somaxconn",
            "unit.test",
            "foo.bar",
            "Connection refused",
            "server 45.13.7.9",
        ] {
            if text.starts_with("server") {
                assert_eq!(kinds(text), [(Kind::Ip, "45.13.7.9".to_owned())]);
                continue;
            }
            assert!(extract(text).found.is_empty(), "{text}: {:?}", extract(text).found);
        }
    }

    #[test]
    fn reversed_dns_names_are_packages() {
        assert_eq!(kinds("com.example.app"), [(Kind::Package, "com.example.app".to_owned())]);
        assert_eq!(kinds("Lorg/apache/http"), []);
        assert_eq!(kinds("android.intent.action.BOOT_COMPLETED"), []);
        assert_eq!(kinds("androidx.core.app"), [(Kind::Package, "androidx.core.app".to_owned())]);
    }

    #[test]
    fn host_endings_beat_package_roots_and_case() {
        for host in ["de.pool.ntp.org", "uk.pool.ntp.org", "io.x-cloud.com", "net.x-cloud.com"] {
            assert_eq!(kinds(host), [(Kind::Host, host.to_owned())], "{host}");
        }
        assert_eq!(kinds("Api.Vendor-Cloud.com"), [(Kind::Host, "api.vendor-cloud.com".to_owned())]);
        assert_eq!(kinds("MQTT.VendorCloud.com"), [(Kind::Host, "mqtt.vendorcloud.com".to_owned())]);
        assert_eq!(noise("Foo.BarBaz"), [Noise::Identifier]);
        assert_eq!(kinds("com.example.app"), [(Kind::Package, "com.example.app".to_owned())]);
        // The list makes amazonaws.com registrable but s3.amazonaws.com a suffix (the blocklist keeps both shared
        // domains at host level).
        assert_eq!(extract("cdn.amazonaws.com").found[0].domain.as_deref(), Some("amazonaws.com"));
        assert_eq!(extract("s3.amazonaws.com").found[0].domain.as_deref(), Some("s3.amazonaws.com"));
        assert_eq!(extract("api.vendor-cloud.co.uk").found[0].domain.as_deref(), Some("vendor-cloud.co.uk"));
        assert_eq!(extract("docs.someone.github.io").found[0].domain.as_deref(), Some("someone.github.io"));
    }

    #[test]
    fn internationalized_url_hosts_become_punycode() {
        let found = &extract("https://bücher.example/x").found[0];
        assert_eq!(found.host.as_deref(), Some("xn--bcher-kva.example"));
        assert_eq!(found.reason, Some("documentation name (RFC 2606)"));
    }

    #[test]
    fn on_network_addresses_and_names_are_flagged() {
        for (text, on_network) in [
            ("fec0::1", true),
            ("fe80::1", true),
            ("192.168.1.1", true),
            ("http://localhost/", true),
            ("http://router/", true),
            ("printer.local", true),
            ("203.0.113.5", false),
            ("2001:db8::5", false),
            ("a.vendor-cloud.example", false),
        ] {
            assert_eq!(extract(text).found[0].on_network, on_network, "{text}");
        }
    }

    #[test]
    fn netmasks_and_kinds_round_trip() {
        assert!(is_netmask("255.255.0.0".parse().unwrap()));
        assert!(!is_netmask("255.255.255.255".parse().unwrap()));
        assert!(!is_netmask("255.0.255.0".parse().unwrap()));
        for kind in [Kind::Url, Kind::Host, Kind::Ip, Kind::Local, Kind::Pin, Kind::Certificate, Kind::Package] {
            assert_eq!(Kind::parse(kind.name()), Some(kind));
            assert_eq!(serde_json::to_value(kind).unwrap(), kind.name());
        }
    }
}
