//! Isolation for the code loop (docs/flywheel.md, "The code loop"): the macOS sandbox profile every
//! agent-influenced process runs in, the pinned programs the harness itself runs, the proxy that is the session's only
//! way out, the runner of logged child processes, the sweep that finds every process a sandbox started, and the
//! interrupt handler that cleans up on Ctrl-C.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// The sandbox launcher; present on every macOS.
pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

/// What a sandboxed process may reach over the network.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Network {
    /// No restriction (only for trusted harness steps).
    #[default]
    Open,
    /// Nothing: no outbound connection, local or remote, and no listening socket.
    Denied,
    /// Only the loopback port of [`Proxy`].
    Proxy(u16),
}

/// Which inter-process channels a sandboxed process keeps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Ipc {
    /// No restriction (only for trusted harness steps).
    #[default]
    Open,
    /// The session: no preferences daemon (which writes other apps' preferences on its behalf), pasteboard or
    /// keychain service, and no view of or signal to processes outside its sandbox.
    Session,
    /// The candidate's code: no mach service at all, no POSIX shared memory or semaphores, and no view of or signal to
    /// other processes.
    Closed,
}

/// Two files in one directory that only the code loop's profiles tell apart: the first denied, the second allowed. Anything else treats them alike, whether unsandboxed, under another sandbox, or under one that
/// denies the whole directory; a process whose sandbox answers "denied, allowed" is one of this run's, whatever it did
/// to its environment, process group or parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Marker {
    pub denied: PathBuf,
    pub allowed: PathBuf,
}

impl Marker {
    /// A marker in a fresh directory under the system temp directory.
    pub fn new(token: &str) -> Marker {
        let token: String = token.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        let directory = canonical(&std::env::temp_dir()).join(format!("rampage-code-marker-{token}"));
        let _ = std::fs::create_dir_all(&directory);
        // Both exist: a check on a missing path can answer "denied" under any sandbox.
        let (denied, allowed) = (directory.join("denied"), directory.join("allowed"));
        let _ = std::fs::write(&denied, "");
        let _ = std::fs::write(&allowed, "");
        Marker { denied, allowed }
    }

    /// Removes the marker's directory.
    pub fn remove(&self) {
        if let Some(directory) = self.allowed.parent() {
            let _ = std::fs::remove_dir_all(directory);
        }
    }
}

/// A `sandbox-exec` profile. Everything is allowed except:
/// - reading or writing `deny`;
/// - with `deny_all_reads`, reading anything but `system_read`, the carve-outs and any path's metadata;
/// - writing `protect`, or, with `deny_all_writes`, writing anything but `/dev` streams;
/// - the network, by [`Network`], and inter-process channels, by [`Ipc`].
///
/// `read_only` paths are carved back out for reading, `allow` paths for reading and writing; the later rule wins.
#[derive(Debug, Clone, Default)]
pub struct Sandbox {
    pub deny: Vec<PathBuf>,
    pub protect: Vec<PathBuf>,
    pub deny_all_writes: bool,
    pub deny_all_reads: bool,
    pub system_read: Vec<PathBuf>,
    pub read_only: Vec<PathBuf>,
    pub allow: Vec<PathBuf>,
    pub network: Network,
    pub ipc: Ipc,
    pub marker: Option<Marker>,
}

fn quote(path: &Path) -> String {
    let text = path.to_string_lossy();
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

/// Mach services the session may not look up.
const SESSION_DENIED_SERVICES: &[&str] =
    &["com.apple.pasteboard.1", "com.apple.pboard", "com.apple.SecurityServer", "com.apple.securityd.xpc"];

impl Sandbox {
    /// The profile text (SBPL). Paths must already be canonical, since the kernel checks resolved paths.
    pub fn profile(&self) -> String {
        let mut text = String::from("(version 1)\n(allow default)\n");
        if self.deny_all_reads {
            text.push_str("(deny file-read*)\n(allow file-read-metadata)\n(allow file-read* (literal \"/\"))\n");
            for path in &self.system_read {
                text.push_str(&format!("(allow file-read* (subpath {}))\n", quote(path)));
            }
        }
        for path in &self.deny {
            text.push_str(&format!("(deny file-read* file-write* (subpath {}))\n", quote(path)));
        }
        for path in &self.protect {
            text.push_str(&format!("(deny file-write* (subpath {}))\n", quote(path)));
        }
        if self.deny_all_writes {
            text.push_str(
                "(deny file-write*)\n(allow file-write* (literal \"/dev/null\") (literal \"/dev/zero\") \
                 (literal \"/dev/dtracehelper\") (regex #\"^/dev/tty\") (regex #\"^/dev/fd/\"))\n",
            );
        }
        // The carved-out paths' ancestors may be looked up (stat, realpath) but not listed or read: cargo and the
        // loaders canonicalize paths, which walks every component.
        let carved: Vec<&PathBuf> = self.read_only.iter().chain(&self.allow).collect();
        let mut ancestors: Vec<&Path> = carved.iter().flat_map(|path| path.ancestors().skip(1)).collect();
        ancestors.retain(|ancestor| ancestor.parent().is_some());
        ancestors.sort();
        ancestors.dedup();
        for ancestor in ancestors {
            text.push_str(&format!("(allow file-read-metadata (literal {}))\n", quote(ancestor)));
        }
        for path in &self.read_only {
            text.push_str(&format!("(allow file-read* (subpath {}))\n", quote(path)));
        }
        for path in &self.allow {
            text.push_str(&format!("(allow file-read* file-write* (subpath {}))\n", quote(path)));
        }
        if let Some(marker) = &self.marker {
            text.push_str(&format!("(deny file-read* (literal {}))\n", quote(&marker.denied)));
            text.push_str(&format!("(allow file-read* (literal {}))\n", quote(&marker.allowed)));
        }
        match self.network {
            Network::Open => {}
            Network::Denied => text.push_str("(deny network*)\n"),
            Network::Proxy(port) => {
                text.push_str(&format!("(deny network*)\n(allow network-outbound (remote ip \"localhost:{port}\"))\n"))
            }
        }
        match self.ipc {
            Ipc::Open => {}
            Ipc::Session => {
                text.push_str("(deny mach-lookup (global-name-prefix \"com.apple.cfprefsd\"))\n");
                for service in SESSION_DENIED_SERVICES {
                    text.push_str(&format!("(deny mach-lookup (global-name \"{service}\"))\n"));
                }
                text.push_str("(deny process-info* (target others))\n(deny signal (target others))\n");
            }
            Ipc::Closed => text.push_str(
                "(deny mach-lookup)\n(deny ipc-posix-shm*)\n(deny ipc-posix-sem*)\n\
                 (deny process-info* (target others))\n(deny signal (target others))\n",
            ),
        }
        text
    }

    /// Writes the profile to `profile_path` and returns a command that runs `program` inside it, with an empty
    /// environment but the pinned PATH: callers pass every variable the program needs.
    pub fn command(&self, profile_path: &Path, program: &Path) -> Result<Command, String> {
        if !Path::new(SANDBOX_EXEC).is_file() {
            return Err(format!(
                "{SANDBOX_EXEC} is missing: the code loop's isolation needs macOS (no other sandbox is implemented)"
            ));
        }
        std::fs::write(profile_path, self.profile()).map_err(|error| format!("{}: {error}", profile_path.display()))?;
        let mut command = Command::new(SANDBOX_EXEC);
        command.env_clear().env("PATH", tools().path()).arg("-f").arg(profile_path).arg(program);
        Ok(command)
    }

    /// This sandbox with `paths` also readable.
    pub fn reading(&self, paths: &[&Path]) -> Sandbox {
        let mut sandbox = self.clone();
        sandbox.read_only.extend(paths.iter().map(|path| path.to_path_buf()));
        sandbox
    }
}

/// `path` resolved, or as given when it does not exist yet (its parent resolved when that exists).
pub fn canonical(path: &Path) -> PathBuf {
    if let Ok(resolved) = std::fs::canonicalize(path) {
        return resolved;
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => canonical(parent).join(name),
        _ => path.to_path_buf(),
    }
}

/// Every program the harness runs outside the sandbox, by absolute path, resolved once before any session starts: a
/// program found on PATH later could be one a session planted. System tools come from their fixed, SIP-protected
/// locations; git, cargo and cargo-nextest from the operator's PATH at startup. The C toolchain is resolved here too,
/// because the candidate's builds cannot run `xcrun` inside their sandbox.
#[derive(Debug, Clone)]
pub struct Tools {
    pub git: PathBuf,
    pub cargo: PathBuf,
    pub nextest: Option<PathBuf>,
    pub ps: PathBuf,
    pub tar: PathBuf,
    pub cp: PathBuf,
    pub id: PathBuf,
    /// The C compiler, archiver and SDK for the candidate's builds.
    pub clang: Option<PathBuf>,
    pub ar: Option<PathBuf>,
    pub sdk: Option<PathBuf>,
    pub rustup_home: PathBuf,
}

fn on_path(name: &str) -> Option<PathBuf> {
    let search = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&search).map(|directory| directory.join(name)).find(|candidate| candidate.is_file())
}

fn xcrun(args: &[&str]) -> Option<PathBuf> {
    let output = Command::new("/usr/bin/xcrun").env_clear().env("PATH", "/usr/bin:/bin").args(args).output().ok()?;
    let text = String::from_utf8(output.stdout).ok()?;
    let path = PathBuf::from(text.trim());
    (output.status.success() && path.exists()).then_some(path)
}

impl Tools {
    fn resolve() -> Tools {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        let cargo = std::env::var_os("CARGO")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .or_else(|| on_path("cargo"))
            .unwrap_or_else(|| PathBuf::from("/usr/bin/false"));
        let git = ["/usr/bin/git"].iter().map(PathBuf::from).find(|path| path.is_file()).or_else(|| on_path("git"));
        Tools {
            git: git.unwrap_or_else(|| PathBuf::from("/usr/bin/git")),
            cargo,
            nextest: on_path("cargo-nextest"),
            ps: PathBuf::from("/bin/ps"),
            tar: PathBuf::from("/usr/bin/tar"),
            cp: PathBuf::from("/bin/cp"),
            id: PathBuf::from("/usr/bin/id"),
            clang: xcrun(&["--find", "clang"]),
            ar: xcrun(&["--find", "ar"]),
            sdk: xcrun(&["--show-sdk-path"]),
            rustup_home: std::env::var_os("RUSTUP_HOME").map(PathBuf::from).unwrap_or_else(|| home.join(".rustup")),
        }
    }

    /// The PATH every child of the harness gets: the pinned tools' directories, then the system's.
    pub fn path(&self) -> String {
        let mut directories: Vec<PathBuf> = Vec::new();
        for program in [Some(&self.cargo), self.nextest.as_ref(), Some(&self.git)].into_iter().flatten() {
            if let Some(directory) = program.parent()
                && !directories.iter().any(|known| known == directory)
            {
                directories.push(directory.to_path_buf());
            }
        }
        for system in ["/usr/bin", "/bin", "/usr/sbin", "/sbin"] {
            if !directories.iter().any(|known| known == Path::new(system)) {
                directories.push(PathBuf::from(system));
            }
        }
        directories.iter().map(|directory| directory.display().to_string()).collect::<Vec<_>>().join(":")
    }

    /// Every pinned program, for checking none lies where a session could have written.
    pub fn programs(&self) -> Vec<&Path> {
        let mut programs = vec![self.git.as_path(), &self.cargo, &self.ps, &self.tar, &self.cp, &self.id];
        programs.extend([&self.nextest, &self.clang, &self.ar].into_iter().flatten().map(PathBuf::as_path));
        programs
    }

    /// What the candidate's deny-by-default build, test, generation and naming sandboxes may read besides their own
    /// carve-outs: the system, the developer tools, the Rust toolchain and the pinned programs' installations. The
    /// home directory, other users' and shared directories, and the session's root are not among them.
    pub fn system_read(&self) -> Vec<PathBuf> {
        let mut paths: Vec<PathBuf> = [
            "/System",
            "/usr",
            "/bin",
            "/sbin",
            "/Library/Developer",
            "/Library/Preferences",
            "/private/var/db",
            "/private/etc",
            "/dev",
        ]
        .iter()
        .map(PathBuf::from)
        .collect();
        paths.push(canonical(&self.rustup_home));
        for program in [Some(&self.cargo), self.nextest.as_ref(), self.clang.as_ref()].into_iter().flatten() {
            let resolved = canonical(program);
            for path in [program, &resolved] {
                // A package manager's prefix (its libraries back the tools), or an application bundle.
                if let Some(prefix) = ["/opt/homebrew", "/usr/local"].iter().find(|prefix| path.starts_with(prefix)) {
                    paths.push(PathBuf::from(prefix));
                } else if let Some(bundle) = path.ancestors().find(|a| a.extension().is_some_and(|e| e == "app")) {
                    paths.push(bundle.to_path_buf());
                } else if let Some(directory) = path.parent() {
                    paths.push(directory.to_path_buf());
                }
            }
        }
        paths.sort();
        paths.dedup();
        paths
    }

    /// The environment that points a build at the pinned C toolchain.
    pub fn toolchain_environment(&self) -> Vec<(String, PathBuf)> {
        let mut environment = Vec::new();
        if let Some(clang) = &self.clang {
            environment.push(("CC".to_owned(), clang.clone()));
            let triple = format!("{}-apple-darwin", std::env::consts::ARCH).to_uppercase().replace('-', "_");
            environment.push((format!("CARGO_TARGET_{triple}_LINKER"), clang.clone()));
        }
        if let Some(ar) = &self.ar {
            environment.push(("AR".to_owned(), ar.clone()));
        }
        if let Some(sdk) = &self.sdk {
            environment.push(("SDKROOT".to_owned(), sdk.clone()));
        }
        environment
    }
}

static TOOLS: OnceLock<Tools> = OnceLock::new();

/// The pinned programs (resolved on first use, which the harness makes before any session starts).
pub fn tools() -> &'static Tools {
    TOOLS.get_or_init(Tools::resolve)
}

/// A command for a pinned program with the pinned PATH.
pub fn tool(program: &Path) -> Command {
    let mut command = Command::new(program);
    command.env("PATH", tools().path());
    command
}

/// Every live process below `root`, from one `ps` snapshot.
pub fn descendants(root: u32) -> BTreeSet<u32> {
    let Ok(listing) = tool(&tools().ps).args(["-A", "-o", "pid=,ppid="]).output() else { return BTreeSet::new() };
    let mut children: std::collections::BTreeMap<u32, Vec<u32>> = std::collections::BTreeMap::new();
    for line in String::from_utf8_lossy(&listing.stdout).lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if let [pid, ppid] = parts[..]
            && let (Ok(pid), Ok(ppid)) = (pid.parse(), ppid.parse())
        {
            children.entry(ppid).or_default().push(pid);
        }
    }
    let mut found = BTreeSet::new();
    let mut pending = vec![root];
    while let Some(next) = pending.pop() {
        for &child in children.get(&next).into_iter().flatten() {
            if found.insert(child) {
                pending.push(child);
            }
        }
    }
    found
}

/// The processes whose environment holds `variable=token`, from one `ps` snapshot (the user's own processes).
fn tagged(variable: &str, token: &str) -> BTreeSet<u32> {
    let Ok(listing) = tool(&tools().ps).args(["-A", "-wwE", "-o", "pid=,command="]).output() else {
        return BTreeSet::new();
    };
    let needle = format!(" {variable}={token}");
    String::from_utf8_lossy(&listing.stdout)
        .lines()
        .filter(|line| line.split(&needle).nth(1).is_some_and(|rest| rest.is_empty() || rest.starts_with(' ')))
        .filter_map(|line| line.split_whitespace().next()?.parse().ok())
        .filter(|&pid| pid != std::process::id())
        .collect()
}

unsafe extern "C" {
    /// libsystem_sandbox: 1 when `pid`'s sandbox denies `operation` on the filter's argument, 0 when it allows it
    /// (and for an unsandboxed process).
    fn sandbox_check(pid: libc::pid_t, operation: *const libc::c_char, filter: libc::c_int, ...) -> libc::c_int;
}

/// `SANDBOX_FILTER_PATH`.
const FILTER_PATH: libc::c_int = 1;

/// Whether `pid` runs under a profile carrying `marker`.
fn carries(pid: u32, marker: &Marker) -> bool {
    let denied = |path: &Path| -> Option<bool> {
        let path = std::ffi::CString::new(path.to_string_lossy().as_bytes()).ok()?;
        let operation = c"file-read-data";
        // SAFETY: valid NUL-terminated strings; the call only queries the kernel.
        Some(unsafe { sandbox_check(pid as libc::pid_t, operation.as_ptr(), FILTER_PATH, path.as_ptr()) } == 1)
    };
    denied(&marker.denied) == Some(true) && denied(&marker.allowed) == Some(false)
}

/// Seconds in a `ps` elapsed time (`[[dd-]hh:]mm:ss`).
fn elapsed_seconds(text: &str) -> Option<u64> {
    let (days, rest) = match text.split_once('-') {
        Some((days, rest)) => (days.parse::<u64>().ok()?, rest),
        None => (0, text),
    };
    let parts: Vec<u64> = rest.split(':').map(|part| part.parse().ok()).collect::<Option<_>>()?;
    let seconds = match parts[..] {
        [m, s] => m * 60 + s,
        [h, m, s] => h * 3600 + m * 60 + s,
        _ => return None,
    };
    Some(days * 86400 + seconds)
}

/// The user's processes started within the last `window` that run under a profile carrying `marker`: every process a
/// session or candidate started, even one that cleared its environment, left its process group and was reparented.
/// The operator's unrelated processes carry no marker.
pub fn marked(marker: &Marker, window: Duration) -> BTreeSet<u32> {
    // SAFETY: getuid has no preconditions.
    let uid = unsafe { libc::getuid() };
    let Ok(listing) = tool(&tools().ps).args(["-A", "-o", "pid=,uid=,etime="]).output() else {
        return BTreeSet::new();
    };
    String::from_utf8_lossy(&listing.stdout)
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            let [pid, owner, elapsed] = parts[..] else { return None };
            let (pid, owner): (u32, u32) = (pid.parse().ok()?, owner.parse().ok()?);
            let young = elapsed_seconds(elapsed)? <= window.as_secs() + 2;
            (owner == uid && young && pid != std::process::id() && carries(pid, marker)).then_some(pid)
        })
        .collect()
}

/// Stops `pids` (and each one's process group): TERM, then KILL.
pub fn kill_all(pids: &BTreeSet<u32>) {
    for signal in [libc::SIGTERM, libc::SIGKILL] {
        let mut alive = false;
        for &pid in pids {
            let pid = pid as libc::pid_t;
            // SAFETY: kill(2) with a pid and a signal number has no memory effects.
            alive |= unsafe { libc::kill(pid, signal) } == 0;
            // SAFETY: as above, for the process group the pid leads (an error when it leads none).
            unsafe { libc::kill(-pid, signal) };
        }
        if !alive {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// The environment variable [`run_logged_with`] tags its processes with.
const RUN_TOKEN: &str = "RAMPAGE_CODE_RUN_TOKEN";

/// The running session, for freezing it while its tree is read.
struct Running {
    pid: u32,
    token: String,
    marker: Option<Marker>,
    started: Instant,
}

static SESSION: Mutex<Option<Running>> = Mutex::new(None);

/// Every process of the running session: its tree, its tagged processes and its marked ones.
fn session_processes() -> BTreeSet<u32> {
    let session = SESSION.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(running) = session.as_ref() else { return BTreeSet::new() };
    let mut pids = descendants(running.pid);
    pids.insert(running.pid);
    pids.extend(tagged(RUN_TOKEN, &running.token));
    if let Some(marker) = &running.marker {
        pids.extend(marked(marker, running.started.elapsed()));
    }
    pids
}

/// The running session stopped (SIGSTOP) until this is dropped: nothing in it can change its tree meanwhile.
pub struct Frozen(BTreeSet<u32>);

/// Stops every process of the running session (none when no session runs).
pub fn freeze_session() -> Frozen {
    let pids = session_processes();
    for &pid in &pids {
        // SAFETY: kill(2) with a pid and a signal number has no memory effects.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) };
    }
    // Processes started between the snapshot and the signals: a second pass.
    let late: BTreeSet<u32> = session_processes().difference(&pids).copied().collect();
    for &pid in &late {
        // SAFETY: as above.
        unsafe { libc::kill(pid as libc::pid_t, libc::SIGSTOP) };
    }
    Frozen(pids.union(&late).copied().collect())
}

impl Drop for Frozen {
    fn drop(&mut self) {
        for &pid in &self.0 {
            // SAFETY: kill(2) with a pid and a signal number has no memory effects.
            unsafe { libc::kill(pid as libc::pid_t, libc::SIGCONT) };
        }
    }
}

/// Runs `command` in its own process group with its output in `log`, stopping it after `limit`. Whether it succeeded
/// in time. Output goes through pipes this process copies: a sandboxed command may not write the log's directory,
/// and the sandbox checks writes to an inherited file too. Every process it started is stopped when it ends: its
/// tree, the processes carrying its environment token, and with `marker` every process under that sandbox profile.
/// With `session`, it is registered as the session (see [`freeze_session`]).
pub fn run_logged_with(
    command: &mut Command,
    log: &Path,
    limit: Duration,
    marker: Option<&Marker>,
    session: bool,
) -> Result<bool, String> {
    use std::os::unix::process::CommandExt;
    let file = std::fs::File::create(log).map_err(|error| format!("{}: {error}", log.display()))?;
    let file = Arc::new(Mutex::new(file));
    let mut token = String::new();
    for part in [std::process::id().to_string(), format!("{:?}", Instant::now())] {
        token.push_str(&part);
    }
    let token: String = token.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    command.env(RUN_TOKEN, &token);
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
    let shown = format!("{command:?}");
    let started = Instant::now();
    let mut child = command.spawn().map_err(|error| format!("{shown}: {error}"))?;
    let pid = child.id();
    interrupt::register_child(pid);
    if session {
        *SESSION.lock().unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(Running { pid, token: token.clone(), marker: marker.cloned(), started });
    }
    let copy = |mut source: Box<dyn Read + Send>| {
        let file = Arc::clone(&file);
        std::thread::spawn(move || {
            let mut buffer = vec![0; 1 << 16];
            while let Ok(read) = source.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                let mut file = file.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let _ = file.write_all(&buffer[..read]);
            }
        })
    };
    let mut copiers = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        copiers.push(copy(Box::new(stdout)));
    }
    if let Some(stderr) = child.stderr.take() {
        copiers.push(copy(Box::new(stderr)));
    }
    let mut seen = BTreeSet::new();
    let mut last_scan = Instant::now() - Duration::from_secs(10);
    let succeeded = loop {
        if last_scan.elapsed() >= Duration::from_secs(2) {
            seen.extend(descendants(pid));
            last_scan = Instant::now();
        }
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            break status.success();
        }
        if started.elapsed() > limit {
            seen.extend(descendants(pid));
            seen.insert(pid);
            kill_all(&seen);
            let _ = child.wait();
            let note = format!("\n[stopped after {} s]\n", limit.as_secs());
            let mut file = file.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = file.write_all(note.as_bytes());
            break false;
        }
        std::thread::sleep(Duration::from_millis(200));
    };
    if session {
        SESSION.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
    }
    // Stragglers: children that outlived it (a daemon that called setsid is reparented and keeps a pipe open), found by
    // its environment token, and by the marker in their sandbox profile, which they cannot remove.
    seen.extend(tagged(RUN_TOKEN, &token));
    if let Some(marker) = marker {
        seen.extend(marked(marker, started.elapsed()));
    }
    seen.remove(&pid);
    if !seen.is_empty() {
        kill_all(&seen);
    }
    interrupt::unregister_child(pid);
    for copier in copiers {
        let _ = copier.join();
    }
    Ok(succeeded)
}

/// An HTTP CONNECT proxy on a loopback port that tunnels only to the allowed `host:port` names and refuses
/// everything else (plain HTTP included), logging each decision. The session's sandbox can reach nothing but this
/// port, so the session can reach nothing but the allowed hosts.
pub struct Proxy {
    pub port: u16,
    stop: Arc<AtomicBool>,
}

impl Proxy {
    pub fn start(allowed: Vec<String>, log: PathBuf) -> Result<Proxy, String> {
        let listener = TcpListener::bind("127.0.0.1:0").map_err(|error| format!("proxy: {error}"))?;
        let port = listener.local_addr().map_err(|error| error.to_string())?.port();
        listener.set_nonblocking(true).map_err(|error| error.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let log = Arc::new(Mutex::new(log));
        std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let (allowed, log) = (allowed.clone(), Arc::clone(&log));
                        std::thread::spawn(move || {
                            let _ = stream.set_nonblocking(false);
                            let decision = tunnel(stream, &allowed);
                            let path = log.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
                            if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                                let _ = writeln!(file, "{decision}");
                            }
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(50)),
                }
            }
        });
        Ok(Proxy { port, stop })
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

/// Serves one proxy connection; returns the logged decision.
fn tunnel(client: TcpStream, allowed: &[String]) -> String {
    let _ = client.set_read_timeout(Some(Duration::from_secs(30)));
    let mut reader = BufReader::new(match client.try_clone() {
        Ok(clone) => clone,
        Err(error) => return format!("error {error}"),
    });
    let mut request = String::new();
    if reader.read_line(&mut request).is_err() {
        return "error unreadable request".to_owned();
    }
    loop {
        let mut header = String::new();
        match reader.read_line(&mut header) {
            Ok(0) | Err(_) => break,
            Ok(_) if header == "\r\n" || header == "\n" => break,
            Ok(_) => {}
        }
    }
    let parts: Vec<&str> = request.split_whitespace().collect();
    let mut client = client;
    let target = match parts[..] {
        ["CONNECT", target, ..] => target.to_owned(),
        _ => {
            let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
            return format!("refused {}", request.trim());
        }
    };
    if !allowed.contains(&target) {
        let _ = client.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n");
        return format!("refused CONNECT {target}");
    }
    let upstream = match TcpStream::connect(&target) {
        Ok(stream) => stream,
        Err(error) => {
            let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
            return format!("failed CONNECT {target}: {error}");
        }
    };
    if client.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").is_err() {
        return format!("dropped CONNECT {target}");
    }
    let _ = client.set_read_timeout(None);
    // Bytes the reader buffered past the request belong to the tunnel.
    let buffered = reader.buffer().to_vec();
    let (Ok(mut up_write), Ok(mut down_read)) = (upstream.try_clone(), upstream.try_clone()) else {
        return format!("error CONNECT {target}");
    };
    let mut client_read = reader.into_inner();
    let mut client_write = client;
    let _ = up_write.write_all(&buffered);
    let forward = std::thread::spawn(move || {
        let _ = std::io::copy(&mut client_read, &mut up_write);
        let _ = up_write.shutdown(Shutdown::Write);
    });
    let _ = std::io::copy(&mut down_read, &mut client_write);
    let _ = client_write.shutdown(Shutdown::Write);
    let _ = forward.join();
    format!("tunnelled CONNECT {target}")
}

/// Ctrl-C and TERM: stop the registered children and run the registered cleanup before exiting, so an interrupted
/// run leaves no worktree or session directory behind.
pub mod interrupt {
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Mutex, Once};

    static RAISED: AtomicBool = AtomicBool::new(false);
    static CHILDREN: Mutex<BTreeSet<u32>> = Mutex::new(BTreeSet::new());
    type Cleanup = Box<dyn Fn() + Send>;
    static CLEANUP: Mutex<Option<Cleanup>> = Mutex::new(None);
    static MARKERS: Mutex<Vec<(super::Marker, std::time::Instant)>> = Mutex::new(Vec::new());
    static INSTALL: Once = Once::new();

    extern "C" fn raise(_: libc::c_int) {
        RAISED.store(true, Ordering::SeqCst);
    }

    /// Installs the handler (once) and the watcher that acts on it.
    pub fn install() {
        INSTALL.call_once(|| {
            // SAFETY: the handler only stores to an atomic, which is async-signal-safe.
            unsafe {
                libc::signal(libc::SIGINT, raise as *const () as libc::sighandler_t);
                libc::signal(libc::SIGTERM, raise as *const () as libc::sighandler_t);
            }
            std::thread::spawn(|| {
                loop {
                    if RAISED.load(Ordering::SeqCst) {
                        eprintln!("interrupted: stopping children and cleaning up");
                        let children = CHILDREN.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
                        let mut all = children.clone();
                        for child in &children {
                            all.extend(super::descendants(*child));
                        }
                        let markers = MARKERS.lock().unwrap_or_else(std::sync::PoisonError::into_inner).clone();
                        for (marker, since) in &markers {
                            all.extend(super::marked(marker, since.elapsed()));
                        }
                        super::kill_all(&all);
                        if let Some(cleanup) = CLEANUP.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take()
                        {
                            cleanup();
                        }
                        std::process::exit(130);
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            });
        });
    }

    /// Registers a run's sandbox marker: an interrupt stops every process carrying it.
    pub fn register_marker(marker: &super::Marker) {
        MARKERS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((marker.clone(), std::time::Instant::now()));
    }

    pub fn register_child(pid: u32) {
        CHILDREN.lock().unwrap_or_else(std::sync::PoisonError::into_inner).insert(pid);
    }

    pub fn unregister_child(pid: u32) {
        CHILDREN.lock().unwrap_or_else(std::sync::PoisonError::into_inner).remove(&pid);
    }

    /// Sets what an interrupt runs before exiting (replacing any earlier cleanup).
    pub fn set_cleanup(cleanup: Box<dyn Fn() + Send>) {
        *CLEANUP.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cleanup);
    }

    /// Clears the cleanup (the run cleaned up itself).
    pub fn clear_cleanup() {
        CLEANUP.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_profile_denies_then_carves_back_in_order() {
        let sandbox = Sandbox {
            deny: vec![PathBuf::from("/data/flywheel")],
            protect: vec![PathBuf::from("/home/user")],
            deny_all_writes: true,
            read_only: vec![PathBuf::from("/data/flywheel/code-runs/x/views/v1")],
            allow: vec![PathBuf::from("/data/flywheel/code-runs/x/out"), PathBuf::from("/odd\"path")],
            network: Network::Proxy(4242),
            ..Sandbox::default()
        };
        let profile = sandbox.profile();
        let at = |needle: &str| profile.find(needle).unwrap_or_else(|| panic!("{needle} missing:\n{profile}"));
        let deny = at("(deny file-read* file-write* (subpath \"/data/flywheel\"))");
        let protect = at("(deny file-write* (subpath \"/home/user\"))");
        let all_writes = at("(deny file-write*)\n");
        let read = at("(allow file-read* (subpath \"/data/flywheel/code-runs/x/views/v1\"))");
        let write = at("(allow file-read* file-write* (subpath \"/data/flywheel/code-runs/x/out\"))");
        assert!(deny < protect && protect < all_writes && all_writes < read && read < write, "{profile}");
        assert!(profile.contains("\"/odd\\\"path\""), "{profile}");
        assert!(profile.contains("(allow file-read-metadata (literal \"/data/flywheel/code-runs\"))"), "{profile}");
        assert!(!profile.contains("(literal \"/\")"), "{profile}");
        assert!(profile.ends_with("(deny network*)\n(allow network-outbound (remote ip \"localhost:4242\"))\n"));
        assert!(Sandbox { network: Network::Denied, ..Sandbox::default() }.profile().ends_with("(deny network*)\n"));
    }

    fn temporary(name: &str) -> PathBuf {
        let root = canonical(&std::env::temp_dir()).join(format!("rampage-code-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    /// A sandboxed command's output reaches a log the sandbox denies it: the harness copies it through pipes.
    #[test]
    #[cfg(target_os = "macos")]
    fn a_sandboxed_command_logs_into_a_directory_it_cannot_write() {
        let root = temporary("log");
        let denied = root.join("flywheel");
        std::fs::create_dir_all(&denied).unwrap();
        let sandbox = Sandbox { deny: vec![denied.clone()], ..Sandbox::default() };
        let mut command = sandbox.command(&root.join("p.sb"), Path::new("/bin/sh")).unwrap();
        command.args(["-c", "echo out; echo err >&2; : > \"$0\" && echo WROTE"]).arg(denied.join("x"));
        let log = denied.join("session.log");
        assert!(run_logged_with(&mut command, &log, Duration::from_secs(30), None, false).is_ok());
        let text = std::fs::read_to_string(&log).unwrap();
        assert!(text.contains("out") && text.contains("err") && !text.contains("WROTE"), "{text}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A process that leaves the process group with setsid is still stopped when the command ends.
    #[test]
    #[cfg(target_os = "macos")]
    fn descendants_that_setsid_are_stopped() {
        let root = temporary("setsid");
        let marker = root.join("pid");
        let script = format!(
            "import os, subprocess, sys, time\n\
             p = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)\n\
             open({:?}, 'w').write(str(p.pid))\n",
            marker.display().to_string()
        );
        let mut command = Command::new("/usr/bin/python3");
        command.args(["-c", &script]);
        assert!(run_logged_with(&mut command, &root.join("log"), Duration::from_secs(30), None, false).unwrap());
        let pid: i32 = std::fs::read_to_string(&marker).unwrap().trim().parse().unwrap();
        std::thread::sleep(Duration::from_secs(1));
        // SAFETY: signal 0 only checks that the process exists.
        assert_ne!(unsafe { libc::kill(pid, 0) }, 0, "the setsid child {pid} survived");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Network isolation: from inside the session's sandbox a TCP connection anywhere but the proxy fails, and the
    /// proxy tunnels only to allowed hosts.
    #[test]
    #[cfg(target_os = "macos")]
    fn the_session_reaches_nothing_but_allowed_hosts_through_the_proxy() {
        let root = temporary("net");
        let allowed = TcpListener::bind("127.0.0.1:0").unwrap();
        let other = TcpListener::bind("127.0.0.1:0").unwrap();
        let (allowed_port, other_port) = (allowed.local_addr().unwrap().port(), other.local_addr().unwrap().port());
        std::thread::spawn(move || {
            for mut stream in allowed.incoming().flatten() {
                let _ = stream.write_all(b"hello from the allowed host\n");
            }
        });
        let proxy = Proxy::start(vec![format!("127.0.0.1:{allowed_port}")], root.join("proxy.log")).unwrap();
        let sandbox = Sandbox { network: Network::Proxy(proxy.port), ..Sandbox::default() };
        let script = format!(
            "import socket\n\
             def tcp(port):\n\
             \x20   try:\n\
             \x20       socket.create_connection(('127.0.0.1', port), timeout=3); return 'connected'\n\
             \x20   except OSError as error: return 'failed ' + str(error.errno)\n\
             def via_proxy(target):\n\
             \x20   s = socket.create_connection(('127.0.0.1', {proxy}), timeout=3)\n\
             \x20   s.sendall(('CONNECT %s HTTP/1.1\\r\\n\\r\\n' % target).encode())\n\
             \x20   return s.recv(200).decode(errors='replace').replace('\\r\\n', ' ')\n\
             print('direct-other', tcp({other}))\n\
             print('direct-allowed', tcp({allowed}))\n\
             try:\n\
             \x20   socket.create_connection(('1.1.1.1', 443), timeout=3); print('remote connected')\n\
             except OSError as error: print('remote failed', error.errno)\n\
             print('proxy-other', via_proxy('127.0.0.1:{other}'))\n\
             print('proxy-web', via_proxy('example.com:443'))\n\
             print('proxy-allowed', via_proxy('127.0.0.1:{allowed}'))\n",
            proxy = proxy.port,
            other = other_port,
            allowed = allowed_port
        );
        let out = sandbox
            .command(&root.join("net.sb"), Path::new("/usr/bin/python3"))
            .unwrap()
            .args(["-c", &script])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        let line = |key: &str| text.lines().find(|line| line.starts_with(key)).unwrap_or_default().to_owned();
        assert!(line("direct-other ").contains("failed"), "{text}");
        assert!(line("direct-allowed ").contains("failed"), "{text}");
        assert!(line("remote ").contains("failed"), "{text}");
        assert!(line("proxy-other ").contains("403"), "{text}");
        assert!(line("proxy-web ").contains("403"), "{text}");
        assert!(line("proxy-allowed ").contains("200"), "{text}");
        let log = std::fs::read_to_string(root.join("proxy.log")).unwrap_or_default();
        assert!(log.contains("refused CONNECT example.com:443"), "{log}");
        drop(proxy);
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// Candidate processes may write only their carve-outs: a test cannot touch the gate's build target.
    #[test]
    #[cfg(target_os = "macos")]
    fn candidate_tests_cannot_write_the_gate_build_target() {
        let root = temporary("target");
        let (gate_target, test_target) = (root.join("gate/target"), root.join("run/test-target"));
        std::fs::create_dir_all(gate_target.join("release")).unwrap();
        std::fs::create_dir_all(&test_target).unwrap();
        std::fs::write(gate_target.join("release/rampage-eval"), "trusted").unwrap();
        let sandbox = Sandbox {
            deny_all_writes: true,
            read_only: vec![root.join("gate")],
            allow: vec![test_target.clone()],
            network: Network::Denied,
            ..Sandbox::default()
        };
        let script = format!(
            "echo poisoned > {binary} && echo WROTE-GATE; echo ok > {test}/x && echo WROTE-TEST; \
             echo home > $HOME/.rampage-code-test && echo WROTE-HOME; cat {binary}",
            binary = gate_target.join("release/rampage-eval").display(),
            test = test_target.display()
        );
        let home = std::env::var("HOME").unwrap_or_default();
        let out = sandbox
            .command(&root.join("t.sb"), Path::new("/bin/sh"))
            .unwrap()
            .env("HOME", &home)
            .args(["-c", &script])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!text.contains("WROTE-GATE") && !text.contains("WROTE-HOME"), "{text}");
        assert!(text.contains("WROTE-TEST") && text.contains("trusted"), "{text}");
        assert_eq!(std::fs::read_to_string(gate_target.join("release/rampage-eval")).unwrap(), "trusted");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The session's sandbox: no write outside its root (so not the package manager's bin directories ahead of the
    /// system's on PATH, where a planted `ps` or `git` would run outside the sandbox), no preferences written through
    /// the preferences daemon, no pasteboard.
    #[test]
    #[cfg(target_os = "macos")]
    fn the_session_cannot_plant_programs_preferences_or_pasteboard_data() {
        let root = temporary("session-writes");
        let domain = format!("rampage.code.probe.{}", std::process::id());
        let sandbox = Sandbox {
            deny_all_writes: true,
            allow: vec![root.clone()],
            ipc: Ipc::Session,
            network: Network::Denied,
            ..Sandbox::default()
        };
        let planted: Vec<String> = ["/opt/homebrew/bin", "/usr/local/bin", "/opt/homebrew/opt/rustup/bin"]
            .iter()
            .filter(|directory| Path::new(directory).is_dir())
            .map(|directory| format!("{directory}/rampage-code-probe"))
            .collect();
        let mut script = String::new();
        for path in &planted {
            script.push_str(&format!("echo '#!/bin/sh' > {path} && echo PLANTED-{path}; "));
        }
        script.push_str(&format!(
            "defaults write {domain} key 1 2>/dev/null; echo hi | pbcopy 2>/dev/null && echo PASTED; \
             ps -A >/dev/null 2>&1 && echo LISTED-PROCESSES; echo ok > {root}/inside && echo WROTE-INSIDE",
            root = root.display()
        ));
        let home = std::env::var("HOME").unwrap_or_default();
        let out = sandbox
            .command(&root.join("s.sb"), Path::new("/bin/sh"))
            .unwrap()
            .env("HOME", &home)
            .args(["-c", &script])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!text.contains("PLANTED") && !text.contains("PASTED") && !text.contains("LISTED"), "{text}");
        assert!(text.contains("WROTE-INSIDE"), "{text}");
        for path in &planted {
            assert!(!Path::new(path).exists(), "{path} was planted");
        }
        let read = Command::new("/usr/bin/defaults").args(["read", &domain, "key"]).output().unwrap();
        let _ = Command::new("/usr/bin/defaults").args(["delete", &domain]).output();
        assert!(!read.status.success(), "a preference was written through cfprefsd: {read:?}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// The candidate's sandboxes read by default nothing but the system and toolchain: a file a session left in a
    /// shared or temporary directory cannot be pulled into a build.
    #[test]
    #[cfg(target_os = "macos")]
    fn candidate_processes_read_nothing_outside_their_allowlist() {
        let root = temporary("reads");
        let planted = root.join("planted/blob.rs");
        std::fs::create_dir_all(planted.parent().unwrap()).unwrap();
        std::fs::write(&planted, "pub const TABLE: &str = \"truth\";").unwrap();
        let allowed = root.join("view/manifest.json");
        std::fs::create_dir_all(allowed.parent().unwrap()).unwrap();
        std::fs::write(&allowed, "{}").unwrap();
        let sandbox = Sandbox {
            deny_all_reads: true,
            system_read: tools().system_read(),
            deny_all_writes: true,
            read_only: vec![root.join("view")],
            allow: vec![root.join("out")],
            network: Network::Denied,
            ipc: Ipc::Closed,
            ..Sandbox::default()
        };
        std::fs::create_dir_all(root.join("out")).unwrap();
        let shared = Path::new("/Users").join("Shared");
        let script = format!(
            "cat {planted} && echo READ-PLANTED; cat {allowed} && echo READ-VIEW; ls {shared} && echo LISTED-SHARED; \
             ls $HOME && echo LISTED-HOME; ps -A >/dev/null 2>&1 && echo LISTED-PROCESSES",
            planted = planted.display(),
            allowed = allowed.display(),
            shared = shared.display()
        );
        let home = std::env::var("HOME").unwrap_or_default();
        let out = sandbox
            .command(&root.join("c.sb"), Path::new("/bin/sh"))
            .unwrap()
            .env("HOME", &home)
            .args(["-c", &script])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!text.contains("READ-PLANTED") && !text.contains("truth"), "{text}");
        assert!(!text.contains("LISTED-SHARED") && !text.contains("LISTED-HOME"), "{text}");
        assert!(!text.contains("LISTED-PROCESSES"), "{text}");
        assert!(text.contains("READ-VIEW"), "{text}");
        let profile = sandbox.profile();
        assert!(profile.contains("(deny mach-lookup)\n") && profile.contains("(deny ipc-posix-shm*)"), "{profile}");
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// A process that clears its environment, leaves its process group and is reparented still carries its sandbox's
    /// marker; the sweep finds it, and only it.
    #[test]
    #[cfg(target_os = "macos")]
    fn the_sweep_finds_escaped_processes_by_their_sandbox_marker_only() {
        let root = temporary("sweep");
        let marker = Marker::new(&format!("test{}", std::process::id()));
        let started = Instant::now();
        let sandbox = Sandbox { marker: Some(marker.clone()), ..Sandbox::default() };
        let pid_file = root.join("pid");
        // A double fork with an empty environment: the sleeper is reparented to launchd.
        let script =
            format!("(/usr/bin/env -i /bin/sh -c 'echo $$ > {}; exec /bin/sleep 120' &) ; exit 0", pid_file.display());
        let status =
            sandbox.command(&root.join("m.sb"), Path::new("/bin/sh")).unwrap().args(["-c", &script]).status().unwrap();
        assert!(status.success());
        let unrelated = Command::new("/bin/sleep").arg("121").spawn().unwrap();
        let other = Sandbox::default()
            .command(&root.join("o.sb"), Path::new("/bin/sleep"))
            .unwrap()
            .arg("122")
            .spawn()
            .unwrap();
        let mut escaped = 0;
        for _ in 0..50 {
            if let Some(pid) = std::fs::read_to_string(&pid_file).ok().and_then(|text| text.trim().parse::<u32>().ok())
            {
                escaped = pid;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        assert_ne!(escaped, 0);
        let found = marked(&marker, started.elapsed());
        assert!(found.contains(&escaped), "{found:?} lacks {escaped}");
        assert!(!found.contains(&unrelated.id()) && !found.contains(&other.id()), "{found:?}");
        kill_all(&found);
        marker.remove();
        // SAFETY: signal 0 only checks that the process exists.
        assert_ne!(unsafe { libc::kill(escaped as libc::pid_t, 0) }, 0, "the escaped process survived");
        for mut child in [unrelated, other] {
            let _ = child.kill();
            let _ = child.wait();
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    /// While its tree is read the session is stopped: a process writing in a loop makes no progress until released.
    #[test]
    #[cfg(target_os = "macos")]
    fn a_frozen_session_makes_no_progress() {
        let root = temporary("freeze");
        let counter = root.join("counter");
        let script = format!("while :; do echo x >> {}; sleep 0.05; done", counter.display());
        let log = root.join("log");
        let runner = std::thread::spawn(move || {
            let mut command = Command::new("/bin/sh");
            command.args(["-c", &script]);
            run_logged_with(&mut command, &log, Duration::from_secs(6), None, true)
        });
        std::thread::sleep(Duration::from_millis(1500));
        let size = |path: &Path| std::fs::metadata(path).map(|metadata| metadata.len()).unwrap_or(0);
        let (before, after) = {
            let _frozen = freeze_session();
            std::thread::sleep(Duration::from_millis(300));
            let before = size(&counter);
            std::thread::sleep(Duration::from_millis(800));
            (before, size(&counter))
        };
        assert!(before > 0 && before == after, "the session kept writing while frozen: {before} -> {after}");
        std::thread::sleep(Duration::from_millis(800));
        assert!(size(&counter) > after, "the session did not resume");
        let _ = runner.join();
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn pinned_programs_are_absolute_and_the_child_path_is_explicit() {
        let tools = tools();
        for program in tools.programs() {
            assert!(program.is_absolute(), "{}", program.display());
        }
        assert_eq!(tools.ps, Path::new("/bin/ps"));
        assert!(tools.path().ends_with("/usr/bin:/bin:/usr/sbin:/sbin"), "{}", tools.path());
        assert_eq!(elapsed_seconds("01:02"), Some(62));
        assert_eq!(elapsed_seconds("1-00:00:01"), Some(86401));
    }
}
