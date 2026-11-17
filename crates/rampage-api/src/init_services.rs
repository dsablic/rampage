//! How programs in an extracted firmware tree are started: Android init `.rc` files (services with their class,
//! `oneshot`/`disabled`, and the actions that start them, `on boot`, `on property:...`), systemd units
//! (`ExecStart=` with `[Install] WantedBy=`), SysV init scripts (`etc/init.d`, `rcS`) and `inittab`. Services may be
//! defined in one file and started from another, so actions are resolved across every file read. Reading is
//! bounded: file count, bytes per file and in all, lines per file, line length and entries.

use std::collections::BTreeMap;
use std::path::Path;

/// Init files read at most, bytes read per file and in all, lines per file, characters per line, entries kept.
const MAX_FILES: usize = 2000;
const MAX_FILE_BYTES: u64 = 1 << 20;
const MAX_TOTAL_BYTES: u64 = 16 << 20;
const MAX_LINES: usize = 100_000;
const MAX_LINE_CHARS: usize = 4096;
const MAX_ENTRIES: usize = 10_000;

/// Action triggers that run while the device boots.
const BOOT_TRIGGERS: [&str; 14] = [
    "early-init",
    "init",
    "late-init",
    "early-fs",
    "fs",
    "post-fs",
    "late-fs",
    "post-fs-data",
    "zygote-start",
    "early-boot",
    "boot",
    "nonencrypted",
    "firmware_mounts_complete",
    "load_persist_props_action",
];
/// systemd targets reached at boot.
const BOOT_TARGETS: [&str; 6] =
    ["multi-user.target", "default.target", "graphical.target", "sysinit.target", "basic.target", "network.target"];

/// One way a program is started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Start {
    /// The program's path as the init file writes it (absolute on the device).
    pub(crate) program: String,
    /// What starts it, in words (`init service voiced, class main`).
    pub(crate) how: String,
    /// Whether it starts while the device boots, with no other trigger.
    pub(crate) boot: bool,
    /// The init file (relative to the tree) and line.
    pub(crate) file: String,
    pub(crate) line: usize,
}

#[derive(Debug, Default)]
struct Service {
    program: String,
    class: Vec<String>,
    disabled: bool,
    oneshot: bool,
    file: String,
    line: usize,
}

/// Everything read from the init files of a tree.
#[derive(Debug, Default)]
pub(crate) struct Starts {
    pub(crate) starts: Vec<Start>,
    pub(crate) files: usize,
    /// Bounds hit, as sentences.
    pub(crate) notes: Vec<String>,
}

/// What kind of init file a tree path (relative, `/`-separated) is.
fn kind(relative: &str) -> Option<&'static str> {
    let name = relative.rsplit('/').next().unwrap_or(relative);
    if name.ends_with(".rc") {
        Some("rc")
    } else if name.ends_with(".service") && (relative.contains("systemd/") || relative.starts_with("systemd")) {
        Some("systemd")
    } else if name == "inittab" {
        Some("inittab")
    } else if relative.contains("init.d/") || relative.contains("rc.d/") || matches!(name, "rcS" | "rc.local") {
        Some("sysv")
    } else {
        None
    }
}

fn boot_trigger(trigger: &str) -> bool {
    trigger.split("&&").any(|part| {
        let part = part.trim();
        BOOT_TRIGGERS.contains(&part)
            || part == "property:sys.boot_completed=1"
            || part == "property:dev.bootcomplete=1"
            || part == "property:vold.decrypt=trigger_restart_framework"
    })
}

/// Reads the init files among `files` (`(relative path, full path, size)`).
pub(crate) fn scan<'a>(files: impl Iterator<Item = (&'a str, &'a Path, u64)>) -> Starts {
    let mut out = Starts::default();
    let mut services: BTreeMap<String, Service> = BTreeMap::new();
    // (trigger, command words, file, line)
    let mut actions: Vec<(String, Vec<String>, String, usize)> = Vec::new();
    let mut total = 0u64;
    for (relative, path, size) in files {
        let Some(kind) = kind(relative) else { continue };
        if out.files >= MAX_FILES {
            out.notes.push(format!("only the first {MAX_FILES} init files were read"));
            break;
        }
        if total >= MAX_TOTAL_BYTES {
            out.notes.push(format!("init files were read up to {} MiB in all", MAX_TOTAL_BYTES >> 20));
            break;
        }
        let Some(text) = read_capped(path, size, &mut out.notes, relative) else { continue };
        total += text.len() as u64;
        out.files += 1;
        let lines = numbered_lines(&text, relative, &mut out.notes);
        match kind {
            "rc" => parse_rc(&lines, relative, &mut services, &mut actions),
            "systemd" => out.starts.extend(parse_systemd(&lines, relative)),
            "inittab" => out.starts.extend(parse_inittab(&lines, relative)),
            _ => out.starts.extend(parse_sysv(&lines, relative)),
        }
        if out.starts.len() + services.len() + actions.len() > MAX_ENTRIES {
            out.notes
                .push(format!("init files named more than {MAX_ENTRIES} services and actions; the rest were not read"));
            break;
        }
    }
    // Classes the boot actions start, and services they start by name.
    let mut class_starts: BTreeMap<&str, (&str, &str, usize)> = BTreeMap::new();
    for (trigger, words, file, line) in &actions {
        let boot = boot_trigger(trigger);
        match words.first().map(String::as_str) {
            Some("class_start" | "class_restart") if boot => {
                for class in &words[1..] {
                    class_starts.entry(class.as_str()).or_insert((trigger.as_str(), file.as_str(), *line));
                }
            }
            Some("start" | "restart" | "exec_start" | "enable") if words.len() > 1 => {
                if let Some(service) = services.get(&words[1]) {
                    out.starts.push(Start {
                        program: service.program.clone(),
                        how: format!("init service {} started by `{}` on `{trigger}`", words[1], words.join(" ")),
                        boot,
                        file: file.clone(),
                        line: *line,
                    });
                }
            }
            Some("exec" | "exec_background") => {
                if let Some(at) = words.iter().position(|word| word == "--")
                    && let Some(program) = words.get(at + 1)
                {
                    out.starts.push(Start {
                        program: program.clone(),
                        how: format!("init `{}` on `{trigger}`", words[0]),
                        boot,
                        file: file.clone(),
                        line: *line,
                    });
                }
            }
            _ => {}
        }
    }
    for (name, service) in &services {
        if service.disabled {
            continue;
        }
        let classes = if service.class.is_empty() { vec!["default".to_owned()] } else { service.class.clone() };
        let how = match classes.iter().find_map(|class| class_starts.get(class.as_str()).map(|found| (class, found))) {
            Some((class, (trigger, file, line))) => {
                format!(
                    "init service {name}, class {class} started by `class_start {class}` on `{trigger}` ({file}:{line})"
                )
            }
            None => format!(
                "init service {name}, class {} (init starts every service of its class at boot unless the service \
                 is disabled)",
                classes.join(" ")
            ),
        };
        let oneshot = if service.oneshot { ", oneshot" } else { "" };
        out.starts.push(Start {
            program: service.program.clone(),
            how: format!("{how}{oneshot}"),
            boot: true,
            file: service.file.clone(),
            line: service.line,
        });
    }
    if out.starts.len() > MAX_ENTRIES {
        out.starts.truncate(MAX_ENTRIES);
        out.notes.push(format!("only the first {MAX_ENTRIES} ways programs are started were kept"));
    }
    out.starts.sort_by(|a, b| (&a.program, !a.boot, &a.file, a.line).cmp(&(&b.program, !b.boot, &b.file, b.line)));
    out.starts.dedup();
    out.notes.sort();
    out.notes.dedup();
    out
}

fn read_capped(path: &Path, size: u64, notes: &mut Vec<String>, relative: &str) -> Option<String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path).ok()?.take(MAX_FILE_BYTES).read_to_end(&mut bytes).ok()?;
    if size > MAX_FILE_BYTES {
        notes.push(format!("{relative} was read up to its first {} KiB", MAX_FILE_BYTES >> 10));
    }
    if bytes[..bytes.len().min(4096)].contains(&0) {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// Lines with their numbers, comments dropped, `\` continuations joined, each cut to [`MAX_LINE_CHARS`].
fn numbered_lines(text: &str, relative: &str, notes: &mut Vec<String>) -> Vec<(usize, String)> {
    let mut lines = Vec::new();
    let mut pending: Option<(usize, String)> = None;
    for (index, raw) in text.lines().enumerate() {
        if index >= MAX_LINES {
            notes.push(format!("{relative} was read up to line {MAX_LINES}"));
            break;
        }
        let raw: String = raw.chars().take(MAX_LINE_CHARS).collect();
        let (number, mut line) = match pending.take() {
            Some((number, mut joined)) => {
                if joined.len() < MAX_LINE_CHARS {
                    joined.push(' ');
                    joined.push_str(raw.trim());
                }
                (number, joined)
            }
            None => (index + 1, raw),
        };
        if line.ends_with('\\') {
            line.pop();
            pending = Some((number, line));
            continue;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        lines.push((number, line));
    }
    lines
}

fn parse_rc(
    lines: &[(usize, String)],
    file: &str,
    services: &mut BTreeMap<String, Service>,
    actions: &mut Vec<(String, Vec<String>, String, usize)>,
) {
    enum At {
        None,
        Service(String),
        Action(String),
    }
    let mut at = At::None;
    for (number, line) in lines {
        let words: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        match words[0].as_str() {
            "service" if words.len() >= 3 => {
                let name = words[1].clone();
                if services.len() >= MAX_ENTRIES && !services.contains_key(&name) {
                    at = At::None;
                    continue;
                }
                // A later definition of the same service is ignored by init, as here.
                services.entry(name.clone()).or_insert_with(|| Service {
                    program: words[2].clone(),
                    file: file.to_owned(),
                    line: *number,
                    ..Service::default()
                });
                at = At::Service(name);
            }
            "on" if words.len() >= 2 => at = At::Action(words[1..].join(" ")),
            "import" => at = At::None,
            _ => match &at {
                At::Service(name) => {
                    let Some(service) = services.get_mut(name) else { continue };
                    if service.file != file || service.line > *number {
                        continue;
                    }
                    match words[0].as_str() {
                        "class" => service.class = words[1..].to_vec(),
                        "disabled" => service.disabled = true,
                        "oneshot" => service.oneshot = true,
                        _ => {}
                    }
                }
                At::Action(trigger) if actions.len() < MAX_ENTRIES => {
                    actions.push((trigger.clone(), words, file.to_owned(), *number));
                }
                At::Action(_) => {}
                At::None => {}
            },
        }
    }
}

/// `ExecStart=` programs, at boot when `[Install] WantedBy=` names a boot target.
fn parse_systemd(lines: &[(usize, String)], file: &str) -> Vec<Start> {
    let unit = file.rsplit('/').next().unwrap_or(file);
    let mut programs = Vec::new();
    let mut wanted: Vec<String> = Vec::new();
    for (number, line) in lines {
        let Some((key, value)) = line.split_once('=') else { continue };
        match key.trim() {
            "ExecStart" | "ExecStartPre" | "ExecStartPost" => {
                let value = value.trim().trim_start_matches(['-', '@', ':', '+', '!']);
                if let Some(program) = value.split_whitespace().next().filter(|word| word.starts_with('/')) {
                    programs.push((program.to_owned(), key.trim().to_owned(), *number));
                }
            }
            "WantedBy" | "RequiredBy" => wanted.extend(value.split_whitespace().map(str::to_owned)),
            _ => {}
        }
    }
    let boot = wanted.iter().find(|target| BOOT_TARGETS.contains(&target.as_str()));
    programs
        .into_iter()
        .map(|(program, key, line)| Start {
            program,
            how: match boot {
                Some(target) => format!("systemd unit {unit} ({key}, WantedBy={target})"),
                None => format!("systemd unit {unit} ({key}; no boot target in [Install])"),
            },
            boot: boot.is_some(),
            file: file.to_owned(),
            line,
        })
        .collect()
}

/// `id:runlevels:action:process` entries that run at boot or respawn.
fn parse_inittab(lines: &[(usize, String)], file: &str) -> Vec<Start> {
    let mut found = Vec::new();
    for (number, line) in lines {
        let fields: Vec<&str> = line.splitn(4, ':').collect();
        let [_, _, action, process] = fields.as_slice() else { continue };
        let boot = matches!(*action, "sysinit" | "respawn" | "once" | "wait" | "boot" | "bootwait");
        if let Some(program) = process.split_whitespace().find(|word| word.starts_with('/')) {
            found.push(Start {
                program: program.to_owned(),
                how: format!("inittab entry ({action})"),
                boot,
                file: file.to_owned(),
                line: *number,
            });
        }
    }
    found
}

/// Programs an init script runs: absolute paths in a `bin` or `sbin` directory.
fn parse_sysv(lines: &[(usize, String)], file: &str) -> Vec<Start> {
    let script = file.rsplit('/').next().unwrap_or(file);
    let mut found = Vec::new();
    for (number, line) in lines {
        for word in line.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ';' | '=' | '`' | '(' | ')')) {
            if word.starts_with('/') && (word.contains("/bin/") || word.contains("/sbin/")) && !word.ends_with('/') {
                found.push(Start {
                    program: word.to_owned(),
                    how: format!("init script {script}"),
                    boot: true,
                    file: file.to_owned(),
                    line: *number,
                });
            }
        }
    }
    found
}

/// Whether the device path `program` names the tree file at `relative`, and how sure that is: the whole path
/// (`/system/bin/x` is `system/bin/x`), the tree being a partition (`/system/bin/x` ends with `bin/x`), or the file
/// name alone (`None` otherwise).
pub(crate) fn names(program: &str, relative: &str) -> Option<&'static str> {
    let program = program.trim_start_matches('/');
    if program == relative {
        return Some("path");
    }
    if relative.contains('/') && program.ends_with(&format!("/{relative}")) {
        return Some("path within the partition");
    }
    let name = relative.rsplit('/').next()?;
    (program.rsplit('/').next() == Some(name)).then_some("file name only")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn starts(files: &[(&str, &str)]) -> Starts {
        let dir = std::env::temp_dir().join(format!("rampage-init-{}-{}", std::process::id(), files.len()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut paths = Vec::new();
        for (relative, text) in files {
            let path = dir.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            paths.push((relative.to_string(), path, text.len() as u64));
        }
        let found = scan(paths.iter().map(|(relative, path, size)| (relative.as_str(), path.as_path(), *size)));
        std::fs::remove_dir_all(&dir).unwrap();
        found
    }

    #[test]
    fn rc_services_systemd_units_and_scripts_are_read_across_files() {
        let found = starts(&[
            ("system/etc/init/voiced.rc", "service voiced /system/bin/voiced --listen\n    class main\n    oneshot\n"),
            (
                "vendor/etc/init/later.rc",
                "service later /vendor/bin/later\n    disabled\n\non property:sys.boot_completed=1\n    start later\n\
                 on property:persist.debug=1\n    exec - root -- /vendor/bin/dbg\n",
            ),
            ("init.rc", "on boot\n    class_start main\n"),
            (
                "lib/systemd/system/cam.service",
                "[Service]\nExecStart=-/usr/bin/camd -f\n[Install]\nWantedBy=multi-user.target\n",
            ),
            ("etc/init.d/S50mic", "#!/bin/sh\nstart-stop-daemon -S -x /usr/sbin/micd -- -d\n"),
            ("etc/inittab", "::respawn:/sbin/getty -L ttyS0\n"),
        ]);
        let find = |program: &str| found.starts.iter().filter(|start| start.program == program).collect::<Vec<_>>();
        let voiced = find("/system/bin/voiced");
        assert_eq!(voiced.len(), 1);
        assert!(voiced[0].boot);
        assert!(voiced[0].how.contains("class_start main") && voiced[0].how.contains("oneshot"), "{voiced:?}");
        assert_eq!((voiced[0].file.as_str(), voiced[0].line), ("system/etc/init/voiced.rc", 1));
        let later = find("/vendor/bin/later");
        assert!(later.len() == 1 && later[0].boot && later[0].how.contains("sys.boot_completed"), "{later:?}");
        let debug = find("/vendor/bin/dbg");
        assert!(debug.len() == 1 && !debug[0].boot);
        assert!(find("/usr/bin/camd")[0].boot);
        assert!(find("/usr/sbin/micd")[0].how.contains("S50mic"));
        assert!(find("/sbin/getty")[0].how.contains("respawn"));
        assert_eq!(names("/system/bin/voiced", "system/bin/voiced"), Some("path"));
        assert_eq!(names("/system/bin/voiced", "bin/voiced"), Some("path within the partition"));
        assert_eq!(names("/system/bin/voiced", "other/voiced"), Some("file name only"));
        assert_eq!(names("/system/bin/voiced", "voicedx"), None);
    }

    #[test]
    fn huge_and_hostile_init_files_stay_bounded() {
        let mut huge = String::new();
        for index in 0..200_000 {
            huge.push_str(&format!("service s{index} /system/bin/s{index}\n    class main\n"));
        }
        let long_line = format!("service long /system/bin/{}\n", "x".repeat(1 << 20));
        let continued = "on boot\n".to_owned() + &"    start a \\\n".repeat(50_000);
        let started = std::time::Instant::now();
        let found = starts(&[("huge.rc", &huge), ("long.rc", &long_line), ("continued.rc", &continued)]);
        assert!(started.elapsed() < std::time::Duration::from_secs(10), "{:?}", started.elapsed());
        eprintln!("huge init files: {:?}", started.elapsed());
        assert!(found.notes.iter().any(|note| note.contains("huge.rc was read up to")), "{:?}", found.notes);
        assert!(found.starts.len() <= MAX_ENTRIES + 64);
        assert!(found.starts.iter().all(|start| start.program.len() <= MAX_LINE_CHARS));
    }
}
