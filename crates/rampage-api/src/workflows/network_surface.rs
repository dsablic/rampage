//! `network_surface`: networking imports, network-like strings and the functions that reference them, with the
//! related capability tags. It maps where the communication surface is, as evidence; it does not judge intent.

use serde_json::json;

use super::{
    Finding, ReportLimits, Section, Tracer, WorkflowReport, api_matches, capability_section, classify, match_api, quote,
};
use crate::{ApiError, Project};

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
/// Functions suggested for decompilation in next steps.
const SUGGESTED_FUNCTIONS: usize = 3;

/// The area of a networking API, if `name` is one.
fn network_api(name: &str) -> Option<&'static str> {
    match_api(NETWORK_APIS, name)
}

impl Project {
    /// The binary's networking surface: imports, strings and the functions that reference them.
    pub fn network_surface(&self, limits: ReportLimits) -> Result<WorkflowReport, ApiError> {
        let mut report = WorkflowReport::new("network_surface", self);
        let mut tracer = Tracer::new(self, &mut report);
        let apis = tracer.api_section("Networking APIs", limits, network_api);

        let mut indicators = Section::new("Network indicators in strings", limits);
        let mut first_indicator = None;
        for found in self.scanned_strings() {
            let Some(indicator) = classify(&found.text).filter(|indicator| indicator.kind.is_network()) else {
                continue;
            };
            first_indicator.get_or_insert(found.address);
            let referenced = tracer.users(&[found.address]);
            let mut evidence = vec![format!("string {} at {:#x}", quote(&found.text), found.address)];
            evidence.extend(referenced.evidence());
            indicators.push(
                Finding::new(
                    "list_strings",
                    indicator.kind.confidence(),
                    format!("{}: {}", indicator.kind.label(), quote(&indicator.value)),
                )
                .at(found.address)
                .evidence(evidence),
            );
            tracer.record(&referenced, &format!("references {} {}", indicator.kind.label(), quote(&indicator.value)));
        }

        let (functions, ranked) =
            tracer.finish(&mut report, "Functions referencing networking evidence", "networking evidence", limits);
        let capabilities = self.capabilities();
        let tags = capability_section(
            "Networking capability tags",
            limits,
            capabilities.iter().filter(|capability| capability.category == "networking"),
        );

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
        for (address, name) in ranked.iter().take(SUGGESTED_FUNCTIONS) {
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
