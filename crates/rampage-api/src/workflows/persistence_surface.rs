//! `persistence_surface`: static indicators of persistence mechanisms -- autostart locations named in strings
//! (registry Run keys and services, scheduled tasks, launchd plists, systemd units, cron, XDG autostart, shell
//! startup files), the service, registry and file-writing APIs that could act on them, the functions referencing
//! either, and persistence capability tags. Indicators show where such code and data are, not that they run.

use serde_json::json;

use super::{Confidence, Finding, ReportLimits, Section, Tracer, WorkflowReport, capability_section, match_api, quote};
use crate::{ApiError, Project};

/// Lowercase substrings of autostart locations and commands, each with the mechanism it names and how specific
/// the match is. Path separators are matched as written: registry paths use `\`, Unix paths `/`.
const LOCATIONS: &[(&str, &str, Confidence)] = &[
    ("currentversion\\runonce", "Windows RunOnce registry key", Confidence::High),
    ("currentversion\\runservices", "Windows RunServices registry key", Confidence::High),
    ("currentversion\\run", "Windows Run registry key", Confidence::High),
    ("policies\\explorer\\run", "Windows policy Run registry key", Confidence::High),
    ("currentversion\\winlogon", "Windows Winlogon registry key", Confidence::Medium),
    ("image file execution options", "Windows Image File Execution Options key", Confidence::Medium),
    ("appinit_dlls", "Windows AppInit_DLLs value", Confidence::High),
    ("currentcontrolset\\services", "Windows service registry key", Confidence::Medium),
    ("start menu\\programs\\startup", "Windows Startup folder", Confidence::High),
    ("system32\\tasks", "Windows scheduled task folder", Confidence::High),
    ("schtasks", "Windows scheduled task command", Confidence::Medium),
    ("schedule.service", "Windows Task Scheduler COM class", Confidence::Medium),
    ("sc create", "Windows service creation command", Confidence::Medium),
    ("sc.exe create", "Windows service creation command", Confidence::Medium),
    ("library/launchagents", "macOS LaunchAgents plist location", Confidence::High),
    ("library/launchdaemons", "macOS LaunchDaemons plist location", Confidence::High),
    ("library/startupitems", "macOS StartupItems location", Confidence::High),
    ("com.apple.loginitems", "macOS login items", Confidence::Medium),
    ("launchctl", "macOS launchctl command", Confidence::Medium),
    ("runatload", "launchd RunAtLoad key", Confidence::Medium),
    ("/etc/systemd/", "systemd unit location", Confidence::High),
    ("/lib/systemd/system", "systemd unit location", Confidence::High),
    ("systemd/user", "systemd user unit location", Confidence::High),
    ("execstart=", "systemd unit ExecStart line", Confidence::Medium),
    ("wantedby=", "systemd unit install target", Confidence::Medium),
    ("systemctl enable", "systemctl enable command", Confidence::Medium),
    ("/etc/cron", "cron table location", Confidence::High),
    ("/var/spool/cron", "cron table location", Confidence::High),
    ("crontab", "crontab file or command", Confidence::Medium),
    ("@reboot", "cron @reboot schedule", Confidence::Medium),
    (".config/autostart", "XDG autostart entry location", Confidence::High),
    ("/etc/xdg/autostart", "XDG autostart entry location", Confidence::High),
    ("/etc/rc.local", "rc.local init script", Confidence::High),
    ("/etc/init.d/", "SysV init script location", Confidence::High),
    ("/etc/ld.so.preload", "dynamic loader preload list", Confidence::High),
    ("/etc/profile", "shell startup file", Confidence::Medium),
    (".bashrc", "shell startup file", Confidence::Medium),
    (".bash_profile", "shell startup file", Confidence::Medium),
    (".bash_login", "shell startup file", Confidence::Medium),
    (".zshrc", "shell startup file", Confidence::Medium),
    (".zprofile", "shell startup file", Confidence::Medium),
    (".zshenv", "shell startup file", Confidence::Medium),
];

/// APIs that install services, write the registry or schedule tasks (patterns, see `api_matches`), always listed.
const MECHANISM_APIS: &[(&str, &str)] = &[
    ("openscmanager", "service installation"),
    ("createservice", "service installation"),
    ("changeserviceconfig", "service installation"),
    ("changeserviceconfig2", "service installation"),
    ("regcreatekey", "registry write"),
    ("regcreatekeyex", "registry write"),
    ("regsetvalue", "registry write"),
    ("regsetvalueex", "registry write"),
    ("regsetkeyvalue", "registry write"),
    ("ntsetvaluekey", "registry write"),
    ("zwsetvaluekey", "registry write"),
    ("shsetvalue", "registry write"),
    ("netschedulejobadd", "scheduled task"),
];

/// File-writing and command APIs, listed only beside an autostart location string: on their own they are ordinary
/// program behavior, not a persistence indicator.
const SUPPORTING_APIS: &[(&str, &str)] = &[
    ("createfile", "file write"),
    ("writefile", "file write"),
    ("copyfile", "file write"),
    ("copyfileex", "file write"),
    ("movefile", "file write"),
    ("movefileex", "file write"),
    ("fopen", "file write"),
    ("fopen64", "file write"),
    ("fputs", "file write"),
    ("fwrite", "file write"),
    ("fprintf", "file write"),
    ("creat", "file write"),
    ("rename", "file write"),
    ("symlink", "file write"),
    ("system", "command execution"),
    ("popen", "command execution"),
    ("execve", "command execution"),
    ("execvp", "command execution"),
    ("execl", "command execution"),
    ("execlp", "command execution"),
    ("posix_spawn", "command execution"),
    ("createprocess", "command execution"),
    ("shellexecute", "command execution"),
    ("shellexecuteex", "command execution"),
    ("winexec", "command execution"),
];

/// Capability rules outside the "persistence" category that describe service or registry building blocks.
const RELATED_CAPABILITIES: [&str; 2] = ["service-control", "registry"];
/// Functions suggested for decompilation in next steps.
const SUGGESTED_FUNCTIONS: usize = 3;

/// The mechanism and match confidence of the first autostart location `text` names.
fn location(text: &str) -> Option<(&'static str, &'static str, Confidence)> {
    let lower = text.to_ascii_lowercase();
    LOCATIONS
        .iter()
        .find(|(pattern, ..)| contains_token(&lower, pattern))
        .map(|&(pattern, mechanism, confidence)| (pattern, mechanism, confidence))
}

/// Whether `pattern` occurs in `text` without running into a word: a pattern that starts (ends) with a letter or
/// digit must not have one right before (after) it, so that `disc create` does not read as `sc create`, nor
/// `CurrentVersion\Runtime` as the Run key, while `/etc/systemd/` still matches inside a longer path.
fn contains_token(text: &str, pattern: &str) -> bool {
    let word = |c: char| c.is_ascii_alphanumeric();
    let open_start = !pattern.starts_with(word);
    let open_end = !pattern.ends_with(word);
    text.match_indices(pattern).any(|(at, _)| {
        (open_start || !text[..at].ends_with(word)) && (open_end || !text[at + pattern.len()..].starts_with(word))
    })
}

impl Project {
    /// The binary's persistence indicators: autostart locations in strings, the APIs that could act on them, the
    /// functions referencing either, and persistence capability tags.
    pub fn persistence_surface(&self, limits: ReportLimits) -> Result<WorkflowReport, ApiError> {
        let mut report = WorkflowReport::new("persistence_surface", self);
        let mut tracer = Tracer::new(self, &mut report);

        let mut locations = Section::new("Autostart locations in strings", limits);
        let mut first_location = None;
        for found in self.scanned_strings() {
            let Some((pattern, mechanism, confidence)) = location(&found.text) else { continue };
            first_location.get_or_insert(found.address);
            let referenced = tracer.users(&[found.address]);
            let mut evidence =
                vec![format!("string {} at {:#x}", quote(&found.text), found.address), format!("contains `{pattern}`")];
            evidence.extend(referenced.evidence());
            locations.push(
                Finding::new("list_strings", confidence, format!("{mechanism}: {}", quote(&found.text)))
                    .at(found.address)
                    .evidence(evidence),
            );
            tracer.record(&referenced, &format!("references {mechanism} {}", quote(&found.text)));
        }

        let with_locations = locations.total > 0;
        let apis = tracer.api_section("Persistence-related APIs", limits, |name| {
            match_api(MECHANISM_APIS, name)
                .or_else(|| with_locations.then(|| match_api(SUPPORTING_APIS, name)).flatten())
        });
        let (functions, ranked) = tracer.finish(
            &mut report,
            "Functions referencing persistence indicators",
            "persistence indicators",
            limits,
        );
        let capabilities = self.capabilities();
        let tags = capability_section(
            "Persistence capability tags",
            limits,
            capabilities.iter().filter(|capability| {
                capability.category == "persistence" || RELATED_CAPABILITIES.contains(&capability.id.as_ref())
            }),
        );

        let empty = locations.total == 0 && apis.total == 0 && tags.total == 0;
        report.summary.push(if empty {
            "No autostart location strings, persistence-related APIs or persistence capability tags were observed."
                .to_owned()
        } else {
            format!(
                "{} autostart location strings, {} persistence-related APIs and {} persistence capability tags \
                 observed; {} functions reference them. These are indicators, not evidence that persistence is set up.",
                locations.total, apis.total, tags.total, functions.total
            )
        });
        for (address, name) in ranked.iter().take(SUGGESTED_FUNCTIONS) {
            report.step(
                "decompile",
                json!({ "at": format!("{address:#x}") }),
                format!("`{name}` references persistence indicators; read what it writes and where."),
            );
        }
        if let Some(address) = first_location {
            report.step(
                "xrefs",
                json!({ "to": format!("{address:#x}") }),
                "Trace every reference to the first autostart location string.",
            );
        }
        report.sections.extend([locations, apis, functions, tags]);

        if !with_locations {
            report.limitation(
                "File-writing and command APIs are listed only beside an autostart location string; none was \
                 found, so they were not listed.",
            );
        }
        report.limitation(
            "Absence of evidence is not evidence of absence: locations built at run time, encoded strings, APIs \
             resolved by name at run time, COM task registration without these strings, and raw system calls are not \
             detected.",
        );
        report.limitation(
            "Strings are matched lexically against known autostart locations; a match can be documentation, an \
             uninstaller, or a check that only reads the location. References come from static analysis and miss \
             indirect or computed uses.",
        );
        report.limitation(
            "This maps where persistence-shaped code and data are, not whether the program installs itself, what it \
             registers, or why.",
        );
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mechanism(text: &str) -> Option<&'static str> {
        location(text).map(|(_, mechanism, _)| mechanism)
    }

    #[test]
    fn recognizes_autostart_locations_across_platforms() {
        assert_eq!(mechanism("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), Some("Windows Run registry key"));
        assert_eq!(
            mechanism("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
            Some("Windows RunOnce registry key")
        );
        assert_eq!(mechanism("SYSTEM\\CurrentControlSet\\Services\\x"), Some("Windows service registry key"));
        assert_eq!(mechanism("schtasks /create /tn x"), Some("Windows scheduled task command"));
        assert_eq!(mechanism("/Library/LaunchDaemons/com.x.plist"), Some("macOS LaunchDaemons plist location"));
        assert_eq!(mechanism("~/Library/LaunchAgents/"), Some("macOS LaunchAgents plist location"));
        assert_eq!(mechanism("/etc/systemd/system/x.service"), Some("systemd unit location"));
        assert_eq!(mechanism("/usr/lib/systemd/system/x.service"), Some("systemd unit location"));
        assert_eq!(mechanism("/home/u/.config/systemd/user/x.service"), Some("systemd user unit location"));
        assert_eq!(mechanism("/etc/cron.d/x"), Some("cron table location"));
        assert_eq!(mechanism("@reboot /usr/bin/x"), Some("cron @reboot schedule"));
        assert_eq!(mechanism(".config/autostart/x.desktop"), Some("XDG autostart entry location"));
        assert_eq!(mechanism("/root/.bashrc"), Some("shell startup file"));
    }

    #[test]
    fn rejects_lookalikes() {
        assert_eq!(mechanism("disc create"), None);
        assert_eq!(mechanism("rerun the test"), None);
        assert_eq!(mechanism("Software\\Microsoft\\Windows\\CurrentVersion"), None);
        assert_eq!(mechanism("/etc/passwd"), None);
        assert_eq!(mechanism("Software\\Microsoft\\Windows\\CurrentVersion\\Runtime"), None);
        assert_eq!(mechanism("/opt/x/launchctlx"), None);
    }

    #[test]
    fn supporting_apis_match_decorated_names() {
        assert_eq!(match_api(MECHANISM_APIS, "__imp_CreateServiceW"), Some("service installation"));
        assert_eq!(match_api(MECHANISM_APIS, "RegSetValueExA"), Some("registry write"));
        assert_eq!(match_api(MECHANISM_APIS, "RegOpenKeyExA"), None);
        assert_eq!(match_api(SUPPORTING_APIS, "fopen@plt"), Some("file write"));
        assert_eq!(match_api(SUPPORTING_APIS, "ShellExecuteExW"), Some("command execution"));
        assert_eq!(match_api(SUPPORTING_APIS, "systemd_notify"), None);
    }
}
