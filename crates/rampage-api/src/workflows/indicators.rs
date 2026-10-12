//! Classifies readable strings as notable indicators: URLs, IPv4 addresses, domain names, registry keys and file
//! paths. Purely lexical: a match says what a string looks like, not that the program uses it that way.

use serde::Serialize;

use super::Confidence;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorKind {
    Url,
    Ipv4,
    Domain,
    RegistryKey,
    FilePath,
}

impl IndicatorKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Url => "URL",
            Self::Ipv4 => "IPv4-like address",
            Self::Domain => "domain-like name",
            Self::RegistryKey => "registry key",
            Self::FilePath => "file path",
        }
    }

    /// Whether the kind points at a network peer.
    pub fn is_network(self) -> bool {
        matches!(self, Self::Url | Self::Ipv4 | Self::Domain)
    }

    /// How reliably the lexical shape identifies the kind. Dotted quads include version numbers, and domain-like
    /// names include identifiers that happen to end in a country code.
    pub fn confidence(self) -> Confidence {
        match self {
            Self::Url | Self::RegistryKey | Self::FilePath => Confidence::High,
            Self::Ipv4 => Confidence::Medium,
            Self::Domain => Confidence::Low,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Indicator {
    pub kind: IndicatorKind,
    /// The matched part of the string.
    pub value: String,
}

const URL_SCHEMES: [&str; 5] = ["http://", "https://", "ftp://", "ws://", "wss://"];

/// Top-level domains accepted for domain-like names. Kept short and free of names that double as file extensions
/// or module paths (`so`, `py`, `sh`, `pl`, `in`, `rs`, `md`, `cc`, `io`, `ws`, `info`...) so that file names such
/// as `str_cat.cc` or `std.io` do not read as hosts; such hosts are still found inside URLs.
const TLDS: [&str; 22] = [
    "com", "net", "org", "biz", "xyz", "top", "onion", "ru", "cn", "su", "tk", "de", "uk", "fr", "jp", "kr", "br",
    "nl", "ir", "us", "eu", "gov",
];

const UNIX_ROOTS: [&str; 19] = [
    "/etc/",
    "/tmp/",
    "/var/",
    "/usr/",
    "/bin/",
    "/sbin/",
    "/dev/",
    "/proc/",
    "/sys/",
    "/home/",
    "/root/",
    "/opt/",
    "/lib/",
    "/lib64/",
    "/Library/",
    "/System/",
    "/Users/",
    "/Applications/",
    "/private/",
];

const WINDOWS_VARIABLES: [&str; 7] =
    ["%appdata%", "%temp%", "%systemroot%", "%userprofile%", "%programdata%", "%localappdata%", "%windir%"];

const REGISTRY_PREFIXES: [&str; 8] =
    ["hkey_", "hklm\\", "hkcu\\", "hkcr\\", "hku\\", "software\\", "system\\currentcontrolset", "\\registry\\"];

/// The most notable indicator in `text`, by priority URL, registry key, IPv4, domain, path.
pub fn classify(text: &str) -> Option<Indicator> {
    let indicator = |kind, value: &str| Some(Indicator { kind, value: value.to_owned() });
    if let Some(url) = url(text) {
        return indicator(IndicatorKind::Url, url);
    }
    let lower = text.to_ascii_lowercase();
    if REGISTRY_PREFIXES.iter().any(|prefix| lower.starts_with(prefix)) || lower.contains("\\software\\") {
        return indicator(IndicatorKind::RegistryKey, text);
    }
    // `_` stays inside tokens so that `str_cat.cc` is one token, which no host name can be.
    let tokens = || text.split(|c: char| !(c.is_ascii_alphanumeric() || "._-:".contains(c)));
    if let Some(address) = tokens().find(|token| is_ipv4(token)) {
        return indicator(IndicatorKind::Ipv4, address);
    }
    if let Some(domain) = tokens().find(|token| is_domain(token) && !in_path(text, token)) {
        return indicator(IndicatorKind::Domain, domain);
    }
    if is_path(text, &lower) {
        return indicator(IndicatorKind::FilePath, text);
    }
    None
}

fn url(text: &str) -> Option<&str> {
    let lower = text.to_ascii_lowercase();
    let start = URL_SCHEMES.iter().filter_map(|scheme| lower.find(scheme).map(|at| (at, scheme.len()))).min()?;
    let rest = &text[start.0..];
    let end = rest.find(|c: char| c.is_whitespace() || "\"'<>`".contains(c)).unwrap_or(rest.len());
    let url = &rest[..end];
    let host = &url[start.1..];
    host.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '[').then_some(url)
}

/// A dotted quad with every octet at most 255, optionally followed by a `:port`.
fn is_ipv4(token: &str) -> bool {
    let (address, port) = match token.split_once(':') {
        Some((address, port)) => (address, Some(port)),
        None => (token, None),
    };
    let octets: Vec<&str> = address.split('.').collect();
    let octets_valid =
        octets.len() == 4 && octets.iter().all(|octet| (1..=3).contains(&octet.len()) && octet.parse::<u8>().is_ok());
    let port_valid = port.is_none_or(|port| port.parse::<u16>().is_ok_and(|port| port > 0));
    octets_valid && port_valid
}

fn is_domain(token: &str) -> bool {
    let host = token.split(':').next().unwrap_or(token).trim_end_matches('.');
    let labels: Vec<&str> = host.split('.').collect();
    let Some(tld) = labels.last() else { return false };
    labels.len() >= 2
        && host.len() <= 253
        && TLDS.contains(&tld.to_ascii_lowercase().as_str())
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        && labels[..labels.len() - 1].iter().any(|label| label.chars().any(|c| c.is_ascii_alphabetic()))
}

/// Whether `token`, a subslice of `text`, follows a path separator, as a file name in `src/foo.cc` does.
fn in_path(text: &str, token: &str) -> bool {
    let start = token.as_ptr() as usize - text.as_ptr() as usize;
    text[..start].ends_with(['/', '\\'])
}

fn is_path(text: &str, lower: &str) -> bool {
    let bytes = text.as_bytes();
    let drive = bytes.len() > 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\';
    let unc = text.starts_with("\\\\") && text.len() > 3;
    let unix = UNIX_ROOTS.iter().any(|root| text.starts_with(root)) && !text.contains(char::is_whitespace);
    text.len() <= 260 && (drive || unc || unix || WINDOWS_VARIABLES.iter().any(|variable| lower.contains(variable)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(text: &str) -> Option<IndicatorKind> {
        classify(text).map(|indicator| indicator.kind)
    }

    #[test]
    fn classifies_network_indicators() {
        let url = classify("GET http://updates.example.com:8080/check HTTP/1.1").unwrap();
        assert_eq!(url, Indicator { kind: IndicatorKind::Url, value: "http://updates.example.com:8080/check".into() });
        assert_eq!(classify("198.51.100.23").unwrap().value, "198.51.100.23");
        assert_eq!(classify("peer 10.0.0.1:443 up").unwrap().value, "10.0.0.1:443");
        assert_eq!(kind("c2.example.com"), Some(IndicatorKind::Domain));
    }

    #[test]
    fn rejects_lookalikes() {
        assert_eq!(kind("1.2.3.4.5"), None);
        assert_eq!(kind("256.1.1.1"), None);
        assert_eq!(kind("libc.so.6"), None);
        assert_eq!(kind("GLIBC_2.2.5"), None);
        assert_eq!(kind("http://"), None);
        assert_eq!(kind("Connection refused"), None);
        assert_eq!(kind("/ not a path"), None);
        assert_eq!(kind("src/foo.cc"), None);
        assert_eq!(kind("absl/strings/str_cat.cc"), None);
        assert_eq!(kind("Assertion failed at third_party/net/session.com"), None);
        assert_eq!(kind("src\\net\\client.de"), None);
        assert_eq!(kind("std.io"), None);
        assert_eq!(kind("config.info"), None);
        assert_eq!(kind("my_host.example.com"), None);
    }

    #[test]
    fn hosts_survive_next_to_paths() {
        assert_eq!(classify("evil.ru/gate.php").unwrap().value, "evil.ru");
        assert_eq!(classify("connect to evil.de:443").unwrap().value, "evil.de:443");
        assert_eq!(kind("https://tunnel.ngrok.io/x"), Some(IndicatorKind::Url));
    }

    #[test]
    fn classifies_host_indicators() {
        assert_eq!(kind("HKEY_LOCAL_MACHINE\\Software\\Run"), Some(IndicatorKind::RegistryKey));
        assert_eq!(kind("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), Some(IndicatorKind::RegistryKey));
        assert_eq!(kind("C:\\Windows\\System32\\cmd.exe"), Some(IndicatorKind::FilePath));
        assert_eq!(kind("%APPDATA%\\tool.dat"), Some(IndicatorKind::FilePath));
        assert_eq!(kind("/dev/null"), Some(IndicatorKind::FilePath));
    }
}
