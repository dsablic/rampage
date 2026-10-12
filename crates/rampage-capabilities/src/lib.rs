//! Capability detection: tags a binary with likely behaviors (networking, process injection, anti-debugging,
//! cryptography, ...) from the names it imports and the strings it contains. This is triage-grade evidence in
//! the spirit of Mandiant's capa, not proof: a match means the building blocks are present, not that the
//! behavior is reached or malicious. Corroborated rules require independent metadata groups, but establish
//! neither call ordering nor argument/data-flow relationships. No binary is executed by this detector.

use std::borrow::Cow;

use serde::Serialize;

mod capa;
mod corroborated;
pub mod names;

pub use capa::{CapaError, CapaRule, CapaRuleSet, detect_capa, load_capa_rules, load_capa_rules_from_str};

/// A detected capability and the evidence that triggered it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Capability {
    /// Borrowed for the built-in rules (static), owned for rules loaded at runtime (e.g. capa).
    pub id: Cow<'static, str>,
    pub name: Cow<'static, str>,
    pub category: Cow<'static, str>,
    /// Evidence as `kind:value`: legacy rules emit canonical matched terms; corroborated rules emit original inputs.
    pub evidence: Vec<String>,
}

/// How a rule term is matched against a candidate name.
#[derive(Clone, Copy)]
enum Match {
    /// An import whose [`names::import_stem`] matches this lowercase pattern under [`names::stem_matches`]: exact
    /// or with one trailing `A`/`W` charset suffix, or by prefix for a `*`-terminated pattern.
    Import(&'static str),
    /// A string contains this substring (case-sensitive, so `AES` does not match `aes` in a path).
    String(&'static str),
    /// A string contains this lowercase ASCII substring, ignoring ASCII case.
    StringAsciiInsensitive(&'static str),
    /// A lowercase registry path anchored after an optional recognized hive, ending at a key boundary.
    RegistryPath { path: &'static str, hive: RegistryHive, exact_key: bool },
}

#[derive(Clone, Copy)]
enum RegistryHive {
    Machine,
    UserOrMachine,
}

/// Detection inputs with the per-call normalizations computed once.
struct Inputs<'a> {
    imports: &'a [String],
    /// [`names::import_stem`] of each import.
    stems: Vec<String>,
    strings: &'a [String],
    /// ASCII-lowercased copy of each string.
    lowered: Vec<String>,
}

impl<'a> Inputs<'a> {
    fn new(imports: &'a [String], strings: &'a [String]) -> Self {
        Inputs {
            imports,
            stems: imports.iter().map(|name| names::import_stem(name)).collect(),
            strings,
            lowered: strings.iter().map(|value| value.to_ascii_lowercase()).collect(),
        }
    }
}

impl Match {
    /// `lowered` is `value` ASCII-lowercased.
    fn matches_string(self, value: &str, lowered: &str) -> bool {
        match self {
            Self::Import(_) => false,
            Self::String(needle) => value.contains(needle),
            Self::StringAsciiInsensitive(needle) => lowered.contains(needle),
            Self::RegistryPath { path, hive, exact_key } => {
                let prefixes: &[&str] = match hive {
                    RegistryHive::Machine => &["hklm\\", "hkey_local_machine\\", "\\registry\\machine\\"],
                    RegistryHive::UserOrMachine => {
                        &["hklm\\", "hkey_local_machine\\", "\\registry\\machine\\", "hkcu\\", "hkey_current_user\\"]
                    }
                };
                let relative = prefixes.iter().find_map(|prefix| lowered.strip_prefix(*prefix)).unwrap_or(lowered);
                relative
                    .strip_prefix(path)
                    .is_some_and(|suffix| suffix.is_empty() || (!exact_key && suffix.starts_with('\\')))
            }
        }
    }

    /// The evidence kind this term reports and its canonical (rule-table) spelling.
    fn canonical(self) -> (&'static str, &'static str) {
        match self {
            Self::Import(needle) => ("import", needle),
            Self::String(needle) | Self::StringAsciiInsensitive(needle) | Self::RegistryPath { path: needle, .. } => {
                ("string", needle)
            }
        }
    }

    /// The original inputs this term matches, in input order.
    fn hits<'a>(self, inputs: &Inputs<'a>) -> Vec<&'a str> {
        match self {
            Self::Import(pattern) => inputs
                .imports
                .iter()
                .zip(&inputs.stems)
                .filter(|(_, stem)| names::stem_matches(pattern, stem))
                .map(|(original, _)| original.as_str())
                .collect(),
            _ => inputs
                .strings
                .iter()
                .zip(&inputs.lowered)
                .filter(|(value, lowered)| self.matches_string(value, lowered))
                .map(|(value, _)| value.as_str())
                .collect(),
        }
    }
}

fn add_evidence(evidence: &mut Vec<String>, kind: &str, value: &str) {
    let entry = format!("{kind}:{value}");
    if !evidence.contains(&entry) {
        evidence.push(entry);
    }
}

struct Rule {
    id: &'static str,
    name: &'static str,
    category: &'static str,
    /// The rule fires when at least `threshold` distinct terms match; most rules need one, combinations need more.
    threshold: usize,
    terms: &'static [Match],
}

struct CorroboratedRule {
    id: &'static str,
    name: &'static str,
    category: &'static str,
    /// Every group must match; alternatives within a group provide only one corroborating indicator.
    groups: &'static [&'static [Match]],
}

const RULES: &[Rule] = &[
    Rule {
        id: "network-socket",
        name: "Network communication",
        category: "networking",
        threshold: 1,
        terms: &[
            Match::Import("socket"),
            Match::Import("connect"),
            Match::Import("recv"),
            Match::Import("send"),
            Match::Import("bind"),
            Match::Import("listen"),
            Match::Import("accept"),
            Match::Import("gethostbyname"),
            Match::Import("getaddrinfo"),
            Match::Import("wsastartup"),
            Match::Import("wsasocket"),
            Match::Import("inet_addr"),
        ],
    },
    Rule {
        id: "http-client",
        name: "HTTP client",
        category: "networking",
        threshold: 1,
        terms: &[
            Match::Import("internetopen"),
            Match::Import("internetopenurl"),
            Match::Import("httpsendrequest"),
            Match::Import("winhttpopen"),
            Match::Import("curl_easy_init"),
            Match::String("User-Agent:"),
            Match::String("http://"),
            Match::String("https://"),
        ],
    },
    Rule {
        id: "process-exec",
        name: "Process creation",
        category: "execution",
        threshold: 1,
        terms: &[
            Match::Import("execve"),
            Match::Import("execvp"),
            Match::Import("fork"),
            Match::Import("posix_spawn"),
            Match::Import("system"),
            Match::Import("popen"),
            Match::Import("createprocess"),
            Match::Import("shellexecute"),
            Match::Import("shellexecuteex"),
            Match::Import("winexec"),
        ],
    },
    Rule {
        id: "process-injection",
        name: "Process injection",
        category: "evasion",
        threshold: 2,
        terms: &[
            Match::Import("virtualallocex"),
            Match::Import("writeprocessmemory"),
            Match::Import("createremotethread"),
            Match::Import("ntunmapviewofsection"),
            Match::Import("queueuserapc"),
            Match::Import("setthreadcontext"),
            Match::Import("openprocess"),
        ],
    },
    Rule {
        id: "anti-debug",
        name: "Anti-debugging",
        category: "evasion",
        threshold: 1,
        terms: &[
            Match::Import("isdebuggerpresent"),
            Match::Import("checkremotedebuggerpresent"),
            Match::Import("ntqueryinformationprocess"),
            Match::Import("ptrace"),
            Match::Import("outputdebugstring"),
        ],
    },
    Rule {
        id: "dynamic-loading",
        name: "Dynamic code loading",
        category: "execution",
        threshold: 1,
        terms: &[
            Match::Import("dlopen"),
            Match::Import("dlsym"),
            Match::Import("loadlibrary"),
            Match::Import("loadlibraryex"),
            Match::Import("getprocaddress"),
        ],
    },
    Rule {
        id: "executable-memory",
        name: "Writable-executable memory",
        category: "evasion",
        threshold: 1,
        terms: &[
            Match::Import("virtualprotect"),
            Match::Import("virtualalloc"),
            Match::Import("mprotect"),
            Match::Import("mmap"),
        ],
    },
    Rule {
        id: "cryptography",
        name: "Cryptography",
        category: "crypto",
        threshold: 1,
        terms: &[
            Match::Import("cryptacquirecontext"),
            Match::Import("cryptencrypt"),
            Match::Import("cryptdecrypt"),
            Match::Import("bcryptencrypt"),
            Match::Import("evp_encryptinit_ex"),
            Match::Import("evp_decryptinit_ex"),
            Match::Import("aes_encrypt"),
            Match::String("-----BEGIN "),
        ],
    },
    Rule {
        id: "filesystem",
        name: "Filesystem access",
        category: "host",
        threshold: 1,
        terms: &[
            Match::Import("createfile"),
            Match::Import("readfile"),
            Match::Import("writefile"),
            Match::Import("fopen"),
            Match::Import("opendir"),
        ],
    },
    Rule {
        id: "registry",
        name: "Windows registry access",
        category: "host",
        threshold: 1,
        terms: &[
            Match::Import("regopenkeyex"),
            Match::Import("regsetvalueex"),
            Match::Import("regcreatekeyex"),
            Match::RegistryPath {
                path: "software\\microsoft\\windows\\currentversion\\run",
                hive: RegistryHive::UserOrMachine,
                exact_key: false,
            },
        ],
    },
    Rule {
        id: "keylogging",
        name: "Input capture",
        category: "collection",
        threshold: 1,
        terms: &[
            Match::Import("getasynckeystate"),
            Match::Import("getkeystate"),
            Match::Import("setwindowshookex"),
            Match::Import("getrawinputdata"),
        ],
    },
    Rule {
        id: "console-output",
        name: "Console output",
        category: "host",
        threshold: 1,
        terms: &[Match::Import("puts"), Match::Import("printf"), Match::Import("fwrite"), Match::Import("write")],
    },
];

/// Detects capabilities from import names and strings. Imports should be the names the binary imports (and its
/// import-slot names); strings should be the readable strings found in the image.
pub fn detect(imports: &[String], strings: &[String]) -> Vec<Capability> {
    let inputs = Inputs::new(imports, strings);
    let mut found = Vec::new();
    for rule in RULES {
        let mut evidence = Vec::new();
        for term in rule.terms {
            if !term.hits(&inputs).is_empty() {
                let (kind, needle) = term.canonical();
                evidence.push(format!("{kind}:{needle}"));
            }
        }
        if evidence.len() >= rule.threshold {
            found.push(Capability {
                id: Cow::Borrowed(rule.id),
                name: Cow::Borrowed(rule.name),
                category: Cow::Borrowed(rule.category),
                evidence,
            });
        }
    }
    for rule in corroborated::RULES {
        let mut evidence = Vec::new();
        let matched = rule.groups.iter().all(|group| {
            let mut matched_group = false;
            for term in *group {
                let (kind, _) = term.canonical();
                for value in term.hits(&inputs) {
                    matched_group = true;
                    add_evidence(&mut evidence, kind, value);
                }
            }
            matched_group
        });
        if matched {
            found.push(Capability {
                id: Cow::Borrowed(rule.id),
                name: Cow::Borrowed(rule.name),
                category: Cow::Borrowed(rule.category),
                evidence,
            });
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| value.to_string()).collect()
    }

    #[test]
    fn detects_networking_from_a_single_import() {
        let caps = detect(&strings(&["connect", "malloc"]), &[]);
        let network = caps.iter().find(|cap| cap.id == "network-socket").expect("networking");
        assert_eq!(network.evidence, vec!["import:connect"]);
    }

    #[test]
    fn import_names_are_normalized() {
        // A Mach-O underscore prefix and an ELF @plt suffix still match.
        let caps = detect(&strings(&["_ptrace", "connect@plt"]), &[]);
        assert!(caps.iter().any(|cap| cap.id == "anti-debug"));
        assert!(caps.iter().any(|cap| cap.id == "network-socket"));
    }

    #[test]
    fn wide_only_and_thunk_imports_match_charset_neutral_terms() {
        let imports = strings(&[
            "ShellExecuteW",
            "__imp_InternetOpenW",
            "HttpSendRequestW",
            "WSASocketW",
            "RegOpenKeyExW",
            "OutputDebugStringW",
            "SetWindowsHookExW",
            "CryptAcquireContextW",
            "LoadLibraryExW",
            "_imp__CreateFileW@28",
        ]);
        let caps = detect(&imports, &[]);
        for (id, term) in [
            ("process-exec", "import:shellexecute"),
            ("http-client", "import:internetopen"),
            ("http-client", "import:httpsendrequest"),
            ("network-socket", "import:wsasocket"),
            ("registry", "import:regopenkeyex"),
            ("anti-debug", "import:outputdebugstring"),
            ("keylogging", "import:setwindowshookex"),
            ("cryptography", "import:cryptacquirecontext"),
            ("dynamic-loading", "import:loadlibraryex"),
            ("filesystem", "import:createfile"),
        ] {
            let cap = caps.iter().find(|cap| cap.id == id).unwrap_or_else(|| panic!("missing {id}"));
            assert!(cap.evidence.iter().any(|value| value == term), "{id}: {:?}", cap.evidence);
        }
    }

    #[test]
    fn registry_autorun_term_is_case_insensitive_and_anchored() {
        let found = |path: &str| detect(&[], &strings(&[path])).iter().any(|cap| cap.id == "registry");
        assert!(found("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"));
        assert!(found("HKCU\\software\\microsoft\\windows\\currentversion\\run\\Updater"));
        assert!(!found("Vendor\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
        assert!(!found("Software\\Microsoft\\Windows\\CurrentVersion\\Runtime"));
    }

    #[test]
    fn combination_rules_need_their_threshold() {
        // One injection primitive alone is not enough.
        let one = detect(&strings(&["VirtualAllocEx"]), &[]);
        assert!(!one.iter().any(|cap| cap.id == "process-injection"));
        // Two cross the threshold.
        let two = detect(&strings(&["VirtualAllocEx", "WriteProcessMemory"]), &[]);
        let injection = two.iter().find(|cap| cap.id == "process-injection").expect("injection");
        assert_eq!(injection.evidence.len(), 2);
    }

    #[test]
    fn strings_contribute_evidence() {
        let caps = detect(&[], &strings(&["GET / HTTP/1.1", "connect to https://example.com"]));
        assert!(caps.iter().any(|cap| cap.id == "http-client"));
    }

    #[test]
    fn nothing_matches_an_empty_binary() {
        assert!(detect(&[], &[]).is_empty());
    }
}
