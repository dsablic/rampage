//! Isolation for the code loop (docs/flywheel.md, "The code loop"): the macOS sandbox profile every
//! agent-influenced process runs in, the proxy that is the session's only way out, the runner of logged child
//! processes, and the interrupt handler that cleans up on Ctrl-C.

use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
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

/// A `sandbox-exec` profile. Everything is allowed except:
/// - reading or writing `deny`;
/// - writing `protect`, or, with `deny_all_writes`, writing anything but `/dev` streams;
/// - the network, by [`Network`].
///
/// `read_only` paths are carved back out for reading, `allow` paths for reading and writing; the later rule wins.
#[derive(Debug, Clone, Default)]
pub struct Sandbox {
    pub deny: Vec<PathBuf>,
    pub protect: Vec<PathBuf>,
    pub deny_all_writes: bool,
    pub read_only: Vec<PathBuf>,
    pub allow: Vec<PathBuf>,
    pub network: Network,
}

fn quote(path: &Path) -> String {
    let text = path.to_string_lossy();
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

impl Sandbox {
    /// The profile text (SBPL). Paths must already be canonical, since the kernel checks resolved paths.
    pub fn profile(&self) -> String {
        let mut text = String::from("(version 1)\n(allow default)\n");
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
        match self.network {
            Network::Open => {}
            Network::Denied => text.push_str("(deny network*)\n"),
            Network::Proxy(port) => {
                text.push_str(&format!("(deny network*)\n(allow network-outbound (remote ip \"localhost:{port}\"))\n"))
            }
        }
        text
    }

    /// Writes the profile to `profile_path` and returns a command that runs `program` inside it.
    pub fn command(&self, profile_path: &Path, program: &Path) -> Result<Command, String> {
        if !Path::new(SANDBOX_EXEC).is_file() {
            return Err(format!(
                "{SANDBOX_EXEC} is missing: the code loop's isolation needs macOS (no other sandbox is implemented)"
            ));
        }
        std::fs::write(profile_path, self.profile()).map_err(|error| format!("{}: {error}", profile_path.display()))?;
        let mut command = Command::new(SANDBOX_EXEC);
        command.arg("-f").arg(profile_path).arg(program);
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

/// Every live process below `root`, from one `ps` snapshot.
pub fn descendants(root: u32) -> BTreeSet<u32> {
    let Ok(listing) = Command::new("ps").args(["-A", "-o", "pid=,ppid="]).output() else { return BTreeSet::new() };
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
    let Ok(listing) = Command::new("ps").args(["-A", "-wwE", "-o", "pid=,command="]).output() else {
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

/// The environment variable [`run_logged`] tags its processes with.
const RUN_TOKEN: &str = "RAMPAGE_CODE_RUN_TOKEN";

/// Runs `command` in its own process group with its output in `log`, stopping it after `limit`. Whether it succeeded
/// in time. Output goes through pipes this process copies: a sandboxed command may not write the log's directory,
/// and the sandbox checks writes to an inherited file too. Every process it started, including ones that left its
/// process group with `setsid`, is stopped when it ends.
pub fn run_logged(command: &mut Command, log: &Path, limit: Duration) -> Result<bool, String> {
    use std::os::unix::process::CommandExt;
    let file = std::fs::File::create(log).map_err(|error| format!("{}: {error}", log.display()))?;
    let file = Arc::new(Mutex::new(file));
    // A token in the environment finds the processes it started even after they left its tree with setsid.
    let token = format!("{}-{:?}", std::process::id(), Instant::now());
    let token: String = token.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    command.env(RUN_TOKEN, &token);
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).process_group(0);
    let shown = format!("{command:?}");
    let mut child = command.spawn().map_err(|error| format!("{shown}: {error}"))?;
    let pid = child.id();
    interrupt::register_child(pid);
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
    let started = Instant::now();
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
    // Stragglers: children that outlived it (a daemon that called setsid is reparented and keeps a pipe open).
    seen.extend(tagged(RUN_TOKEN, &token));
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
        assert!(run_logged(&mut command, &log, Duration::from_secs(30)).is_ok());
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
        assert!(run_logged(&mut command, &root.join("log"), Duration::from_secs(30)).unwrap());
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
        let out =
            sandbox.command(&root.join("t.sb"), Path::new("/bin/sh")).unwrap().args(["-c", &script]).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(!text.contains("WROTE-GATE") && !text.contains("WROTE-HOME"), "{text}");
        assert!(text.contains("WROTE-TEST") && text.contains("trusted"), "{text}");
        assert_eq!(std::fs::read_to_string(gate_target.join("release/rampage-eval")).unwrap(), "trusted");
        std::fs::remove_dir_all(&root).unwrap();
    }
}
