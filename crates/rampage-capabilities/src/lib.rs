//! Capability detection: tags a binary with likely behaviors (networking, process injection, anti-debugging,
//! cryptography, ...) from the names it imports and the strings it contains. This is triage-grade evidence in
//! the spirit of Mandiant's capa, not proof: a match means the building blocks are present, not that the
//! behavior is reached or malicious. Corroborated rules require independent metadata groups, but establish
//! neither call ordering nor argument/data-flow relationships. No binary is executed by this detector.

use serde::Serialize;

mod corroborated;

/// A detected capability and the evidence that triggered it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Capability {
    pub id: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    /// Evidence as `kind:value`: legacy rules emit canonical matched terms; corroborated rules emit original inputs.
    pub evidence: Vec<String>,
}

/// How a rule term is matched against a candidate name.
#[derive(Clone, Copy)]
enum Match {
    /// The import name equals this (case-insensitive), ignoring a leading underscore or `@plt`/ordinal suffix.
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

impl Match {
    fn matches_string(self, value: &str) -> bool {
        match self {
            Self::Import(_) => false,
            Self::String(needle) => value.contains(needle),
            Self::StringAsciiInsensitive(needle) => value.to_ascii_lowercase().contains(needle),
            Self::RegistryPath { path, hive, exact_key } => {
                let value = value.to_ascii_lowercase();
                let prefixes: &[&str] = match hive {
                    RegistryHive::Machine => &["hklm\\", "hkey_local_machine\\", "\\registry\\machine\\"],
                    RegistryHive::UserOrMachine => {
                        &["hklm\\", "hkey_local_machine\\", "\\registry\\machine\\", "hkcu\\", "hkey_current_user\\"]
                    }
                };
                let relative = prefixes.iter().find_map(|prefix| value.strip_prefix(*prefix)).unwrap_or(&value);
                relative
                    .strip_prefix(path)
                    .is_some_and(|suffix| suffix.is_empty() || (!exact_key && suffix.starts_with('\\')))
            }
        }
    }

    fn collect_evidence(
        self,
        imports: &[String],
        normalized: &[String],
        strings: &[String],
        evidence: &mut Vec<String>,
    ) -> bool {
        let mut matched = false;
        match self {
            Self::Import(needle) => {
                for (original, name) in imports.iter().zip(normalized) {
                    if name == needle {
                        matched = true;
                        add_evidence(evidence, "import", original);
                    }
                }
            }
            _ => {
                for value in strings {
                    if self.matches_string(value) {
                        matched = true;
                        add_evidence(evidence, "string", value);
                    }
                }
            }
        }
        matched
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

/// Normalizes an import name for comparison: lowercased, without a leading underscore, a `@`-suffix (`foo@plt`)
/// or a trailing `a`/`w` ANSI/wide marker is kept (handled per-term instead).
fn normal(name: &str) -> String {
    let name = name.trim_start_matches('_');
    let name = name.split('@').next().unwrap_or(name);
    name.to_ascii_lowercase()
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
            Match::Import("wsasocketa"),
            Match::Import("inet_addr"),
        ],
    },
    Rule {
        id: "http-client",
        name: "HTTP client",
        category: "networking",
        threshold: 1,
        terms: &[
            Match::Import("internetopena"),
            Match::Import("internetopenurla"),
            Match::Import("httpsendrequesta"),
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
            Match::Import("createprocessa"),
            Match::Import("createprocessw"),
            Match::Import("shellexecutea"),
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
            Match::Import("outputdebugstringa"),
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
            Match::Import("loadlibrarya"),
            Match::Import("loadlibraryw"),
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
            Match::Import("cryptacquirecontexta"),
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
            Match::Import("createfilea"),
            Match::Import("createfilew"),
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
            Match::Import("regopenkeyexa"),
            Match::Import("regsetvalueexa"),
            Match::Import("regcreatekeyexa"),
            Match::String("Software\\Microsoft\\Windows\\CurrentVersion\\Run"),
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
            Match::Import("setwindowshookexa"),
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
    let normalized: Vec<String> = imports.iter().map(|name| normal(name)).collect();
    let mut found = Vec::new();
    for rule in RULES {
        let mut evidence = Vec::new();
        for term in rule.terms {
            let (kind, needle, matched) = match *term {
                Match::Import(needle) => ("import", needle, normalized.iter().any(|name| name == needle)),
                Match::String(needle)
                | Match::StringAsciiInsensitive(needle)
                | Match::RegistryPath { path: needle, .. } => {
                    ("string", needle, strings.iter().any(|value| term.matches_string(value)))
                }
            };
            if matched {
                evidence.push(format!("{kind}:{needle}"));
            }
        }
        if evidence.len() >= rule.threshold {
            found.push(Capability { id: rule.id, name: rule.name, category: rule.category, evidence });
        }
    }
    for rule in corroborated::RULES {
        let mut evidence = Vec::new();
        let matched = rule.groups.iter().all(|group| {
            let mut matched_group = false;
            for term in *group {
                matched_group |= term.collect_evidence(imports, &normalized, strings, &mut evidence);
            }
            matched_group
        });
        if matched {
            found.push(Capability { id: rule.id, name: rule.name, category: rule.category, evidence });
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
