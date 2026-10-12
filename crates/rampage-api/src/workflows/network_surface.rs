//! `network_surface`: networking imports, network-like strings and the functions that reference them, with the
//! related capability tags. It maps where the communication surface is, as evidence; it does not judge intent.

use std::collections::{BTreeMap, BTreeSet};

use rampage_loaders::SymbolKind;
use serde_json::json;

use super::{Confidence, Finding, ReportLimits, Section, WorkflowReport, api_matches, classify, match_api, quote};
use crate::{ApiError, Project, XrefQuery};

/// Networking API patterns (see `api_matches`), each with the area it belongs to.
const NETWORK_APIS: &[(&str, &str)] = &[
    ("socket", "sockets"),
    ("connect", "sockets"),
    ("bind", "sockets"),
    ("listen", "sockets"),
    ("accept", "sockets"),
    ("accept4", "sockets"),
    ("recv", "sockets"),
    ("recvfrom", "sockets"),
    ("recvmsg", "sockets"),
    ("send", "sockets"),
    ("sendto", "sockets"),
    ("sendmsg", "sockets"),
    ("setsockopt", "sockets"),
    ("closesocket", "sockets"),
    ("ioctlsocket", "sockets"),
    ("wsastartup", "sockets"),
    ("wsasocket", "sockets"),
    ("wsaconnect", "sockets"),
    ("wsarecv", "sockets"),
    ("wsasend", "sockets"),
    ("gethostbyname", "name resolution"),
    ("gethostbyaddr", "name resolution"),
    ("getaddrinfo", "name resolution"),
    ("getnameinfo", "name resolution"),
    ("freeaddrinfo", "name resolution"),
    ("res_query", "name resolution"),
    ("res_search", "name resolution"),
    ("dnsquery_*", "name resolution"),
    ("inet_addr", "address conversion"),
    ("inet_pton", "address conversion"),
    ("inet_ntoa", "address conversion"),
    ("inet_ntop", "address conversion"),
    ("internetopen", "HTTP/FTP client"),
    ("internetopenurl", "HTTP/FTP client"),
    ("internetconnect", "HTTP/FTP client"),
    ("internetreadfile", "HTTP/FTP client"),
    ("internetwritefile", "HTTP/FTP client"),
    ("httpopenrequest", "HTTP/FTP client"),
    ("httpsendrequest", "HTTP/FTP client"),
    ("winhttpopen", "HTTP/FTP client"),
    ("winhttpconnect", "HTTP/FTP client"),
    ("winhttpopenrequest", "HTTP/FTP client"),
    ("winhttpsendrequest", "HTTP/FTP client"),
    ("winhttpreceiveresponse", "HTTP/FTP client"),
    ("winhttpreaddata", "HTTP/FTP client"),
    ("urldownloadtofile", "HTTP/FTP client"),
    ("urlopenstream", "HTTP/FTP client"),
    ("curl_easy_init", "HTTP/FTP client"),
    ("curl_easy_setopt", "HTTP/FTP client"),
    ("curl_easy_perform", "HTTP/FTP client"),
    ("ssl_connect", "TLS"),
    ("ssl_read", "TLS"),
    ("ssl_write", "TLS"),
    ("ssl_ctx_new", "TLS"),
    ("initializesecuritycontext", "TLS"),
    ("acquirecredentialshandle", "TLS"),
];

/// Imports that let code load a library or look up any API at run time, so networking can be reached without
/// importing it (patterns, see `api_matches`).
const RUNTIME_RESOLVERS: [&str; 7] =
    ["dlopen", "dlsym", "getprocaddress", "loadlibrary", "loadlibraryex", "ldrloaddll", "ldrgetprocedureaddress"];
/// References read per API or string when looking for the functions that use it.
const REFERENCES_PER_ITEM: usize = 200;
/// Functions suggested for decompilation in next steps.
const SUGGESTED_FUNCTIONS: usize = 3;

/// The area of a networking API, if `name` is one.
fn network_api(name: &str) -> Option<&'static str> {
    match_api(NETWORK_APIS, name)
}

/// Where an API is used from: the functions containing references to any of `targets`.
pub(super) struct Users {
    /// Function start to name, for every referencing function found.
    functions: BTreeMap<u64, String>,
    references: usize,
}

impl Project {
    /// The binary's networking surface: imports, strings and the functions that reference them.
    pub fn network_surface(&self, limits: ReportLimits) -> Result<WorkflowReport, ApiError> {
        let mut report = WorkflowReport::new("network_surface", self);
        let analysis_error = self.analysis().err().map(|error| error.to_string());
        if let Some(error) = &analysis_error {
            report.limitation(format!(
                "Code references are unavailable ({error}); referencing functions are not listed."
            ));
        }
        // Function start to (name, evidence), across APIs and strings.
        let mut users: BTreeMap<u64, (String, Vec<String>)> = BTreeMap::new();

        let mut apis = Section::new("Networking APIs", limits);
        let mut seen = BTreeSet::new();
        for import in &self.binary.imports {
            let Some(area) = network_api(&import.name) else { continue };
            if !seen.insert(import.name.clone()) {
                continue;
            }
            let mut targets: Vec<u64> = self
                .binary
                .import_slots
                .iter()
                .filter(|slot| slot.name == import.name)
                .map(|slot| slot.address)
                .collect();
            targets.extend(self.resolve(&import.name).ok());
            let found = self.users(&targets, analysis_error.is_none());
            let library = import.library.as_deref().unwrap_or("an unrecorded library");
            apis.push(self.api_finding(
                format!("imports `{}` from {library} ({area})", import.name),
                &found,
                targets.first().copied(),
            ));
            record(&mut users, &found, &format!("calls `{}` ({area})", import.name));
        }
        for symbol in &self.binary.symbols {
            if symbol.kind != SymbolKind::Function
                || !self.binary.is_code(symbol.address)
                || seen.contains(&symbol.name)
            {
                continue;
            }
            let Some(area) = network_api(&symbol.name) else { continue };
            seen.insert(symbol.name.clone());
            let found = self.users(&[symbol.address], analysis_error.is_none());
            apis.push(self.api_finding(
                format!("contains function `{}` ({area}), statically linked or local", symbol.name),
                &found,
                Some(symbol.address),
            ));
            record(&mut users, &found, &format!("calls `{}` ({area})", symbol.name));
        }

        let mut indicators = Section::new("Network indicators in strings", limits);
        let mut first_indicator = None;
        for found in self.scanned_strings() {
            let Some(indicator) = classify(&found.text).filter(|indicator| indicator.kind.is_network()) else {
                continue;
            };
            first_indicator.get_or_insert(found.address);
            let referenced = self.users(&[found.address], analysis_error.is_none());
            let mut evidence = vec![format!("string {} at {:#x}", quote(&found.text), found.address)];
            evidence.extend(referencing(&referenced));
            indicators.push(
                Finding::new(
                    "list_strings",
                    indicator.kind.confidence(),
                    format!("{}: {}", indicator.kind.label(), quote(&indicator.value)),
                )
                .at(found.address)
                .evidence(evidence),
            );
            record(
                &mut users,
                &referenced,
                &format!("references {} {}", indicator.kind.label(), quote(&indicator.value)),
            );
        }

        let mut ranked: Vec<(u64, (String, Vec<String>))> = users.into_iter().collect();
        ranked.sort_by(|a, b| b.1.1.len().cmp(&a.1.1.len()).then(a.0.cmp(&b.0)));
        let mut functions = Section::new("Functions referencing networking evidence", limits);
        for (address, (name, evidence)) in &ranked {
            functions.push(
                Finding::new(
                    "xrefs",
                    Confidence::Observed,
                    format!("`{name}` {} networking evidence", count(evidence.len())),
                )
                .at(*address)
                .evidence(evidence.iter().cloned()),
            );
        }

        let mut tags = Section::new("Networking capability tags", limits);
        for capability in self.capabilities().iter().filter(|capability| capability.category == "networking") {
            tags.push(
                Finding::new(
                    "capabilities",
                    Confidence::Low,
                    format!(
                        "building blocks of '{}' are present; this does not show the behavior executes",
                        capability.name
                    ),
                )
                .evidence(capability.evidence.iter().cloned()),
            );
        }

        let empty = apis.total == 0 && indicators.total == 0 && tags.total == 0;
        report.summary.push(if empty {
            "No networking APIs, network-like strings or networking capability tags were observed.".to_owned()
        } else {
            format!(
                "{} networking APIs, {} network-like strings and {} networking capability tags observed; {} functions \
                 reference them.",
                apis.total, indicators.total, tags.total, functions.total
            )
        });
        for (address, (name, _)) in ranked.iter().take(SUGGESTED_FUNCTIONS) {
            report.step(
                "decompile",
                json!({ "at": format!("{address:#x}") }),
                format!("`{name}` references networking evidence; read how it builds and uses the connection."),
            );
        }
        if let Some(address) = first_indicator {
            report.step(
                "xrefs",
                json!({ "to": format!("{address:#x}") }),
                "Trace every reference to the first network-like string.",
            );
        }
        report.sections.extend([apis, indicators, functions, tags]);

        let resolvers: Vec<&str> = self
            .binary
            .imports
            .iter()
            .map(|import| import.name.as_str())
            .filter(|name| RUNTIME_RESOLVERS.iter().any(|pattern| api_matches(pattern, name)))
            .collect();
        if !resolvers.is_empty() {
            report.limitation(format!(
                "The binary imports {}: APIs resolved by name at run time do not appear as imports, so the import \
                 list may understate the networking surface.",
                resolvers.join(", ")
            ));
        }
        report.limitation(
            "Absence of evidence is not evidence of absence: raw system calls, runtime-resolved APIs, and encoded or \
             runtime-built addresses are not detected.",
        );
        report.limitation(
            "Strings are matched lexically (an IPv4-like string can be a version number); references come from \
             static analysis and miss indirect or computed uses.",
        );
        report.limitation("This maps where networking code and data are, not what is sent, to whom, or why.");
        Ok(report)
    }

    pub(super) fn users(&self, targets: &[u64], analyzed: bool) -> Users {
        let mut users = Users { functions: BTreeMap::new(), references: 0 };
        if !analyzed {
            return users;
        }
        for &target in targets {
            let Ok(page) = self.xrefs(XrefQuery::To(target), None, Some(REFERENCES_PER_ITEM)) else { continue };
            for row in page.items {
                // A PLT stub or the API's own body referencing it is plumbing, not a user.
                if let Ok(Some(function)) = self.function_containing(row.from)
                    && !targets.contains(&function)
                {
                    users.references += 1;
                    users.functions.entry(function).or_insert_with(|| self.function_name(function));
                }
            }
        }
        users
    }

    fn api_finding(&self, observation: String, users: &Users, address: Option<u64>) -> Finding {
        let mut finding = Finding::new("list_imports", Confidence::Observed, observation)
            .evidence([format!("{} references from discovered functions", users.references)])
            .evidence(referencing(users));
        if let Some(address) = address {
            finding = finding.at(address);
        }
        finding
    }
}

pub(super) fn referencing(users: &Users) -> Vec<String> {
    users.functions.iter().map(|(address, name)| format!("referenced from `{name}` ({address:#x})")).collect()
}

pub(super) fn record(users: &mut BTreeMap<u64, (String, Vec<String>)>, found: &Users, evidence: &str) {
    for (&address, name) in &found.functions {
        users.entry(address).or_insert_with(|| (name.clone(), Vec::new())).1.push(evidence.to_owned());
    }
}

pub(super) fn count(items: usize) -> String {
    if items == 1 { "references 1 item of".to_owned() } else { format!("references {items} items of") }
}

#[cfg(test)]
mod tests {
    use super::{RUNTIME_RESOLVERS, api_matches, network_api};

    #[test]
    fn matches_decorated_networking_names() {
        assert_eq!(network_api("connect"), Some("sockets"));
        assert_eq!(network_api("__imp_InternetOpenUrlW"), Some("HTTP/FTP client"));
        assert_eq!(network_api("getaddrinfo@plt"), Some("name resolution"));
        assert_eq!(network_api("DnsQuery_A"), Some("name resolution"));
        assert_eq!(network_api("puts"), None);
        assert_eq!(network_api("sendfile"), None);
        assert_eq!(network_api("connected"), None);
    }

    #[test]
    fn recognizes_decorated_runtime_resolvers() {
        let resolver = |name: &str| RUNTIME_RESOLVERS.iter().any(|pattern| api_matches(pattern, name));
        for name in ["__imp_GetProcAddress", "LoadLibraryExA", "LoadLibraryW", "dlopen", "LdrGetProcedureAddress"] {
            assert!(resolver(name), "{name}");
        }
        assert!(!resolver("GetProcessId"));
    }
}
