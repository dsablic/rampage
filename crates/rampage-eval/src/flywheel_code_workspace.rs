//! The code loop's workspace (docs/flywheel.md, "The code loop"): which paths a family's agent may change and what
//! added lines may not do, the diff of a worktree against its base, the macOS sandbox every agent-influenced process
//! runs in, corpus views holding only the files a process may read, and the in-session gate client.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use rampage_api::flywheel::{Corpus, CorpusBinary, CorpusManifest, Role};
use sha2::{Digest, Sha256};

/// The paths the library-identification family's agent may change: the matcher modules of `rampage-signatures`
/// (hash and callee-key lookup, PAT rows, the bundled database format, call-graph propagation, fuzzy features and
/// operand classes), new modules under `src/heuristics/`, and the crate's integration tests. A path ending in `/` is
/// a directory prefix. Left out on purpose: `Cargo.toml` (no new dependencies), `data/` (the shipped databases
/// change only through `rampage-eval bundle`), `bundled.rs` and `catalog.rs` (which assets load), `fid.rs` (Ghidra
/// FID import, not identification) and `diagnostics.rs` (reports, not matching).
pub const LIBID_ALLOWLIST: &[&str] = &[
    "crates/rampage-signatures/src/lib.rs",
    "crates/rampage-signatures/src/pat.rs",
    "crates/rampage-signatures/src/compressed.rs",
    "crates/rampage-signatures/src/callgraph.rs",
    "crates/rampage-signatures/src/fuzzy.rs",
    "crates/rampage-signatures/src/operands.rs",
    "crates/rampage-signatures/src/heuristics/",
    "crates/rampage-signatures/tests/",
];

/// Whether `path` (repository-relative, `/`-separated) is one `allowlist` admits.
pub fn allowed(path: &str, allowlist: &[&str]) -> bool {
    if path.is_empty() || path.starts_with('/') || path.split('/').any(|part| part == ".." || part == ".") {
        return false;
    }
    allowlist.iter().any(|entry| match entry.strip_suffix('/') {
        Some(directory) => path.strip_prefix(directory).is_some_and(|rest| rest.starts_with('/') && rest.len() > 1),
        None => path == *entry,
    })
}

/// Lexical markers an added line of the change may not contain. The matcher works from the binary and the
/// compiled-in databases; the build, the tests and identification run outside the session, so a change reaching
/// files, the environment, other processes or the network could read what the session may not. The check is
/// lexical and conservative: a comment mentioning one of them fails too.
const FORBIDDEN: &[&str] = &[
    "std::fs",
    "std::env",
    "std::process",
    "std::net",
    "std::os",
    "std::io::stdin",
    "File::",
    "OpenOptions",
    "read_dir",
    "include_bytes!",
    "include_str!",
    "include!",
    "env!",
    "option_env!",
    "unsafe",
    "extern ",
    "#[link",
    "#[path",
    "#![",
    "Command::",
    "TcpStream",
    "UdpSocket",
    "UnixStream",
    "libc::",
    "rustix::",
    "asm!",
    "proc_macro",
];

/// Modules that are I/O when named after `::` or in a `use` group (`use std::{fs, io}`).
const FORBIDDEN_MODULES: &[&str] = &["fs", "env", "process", "net", "os"];

/// The marker `line` holds, if any.
pub fn forbidden(line: &str) -> Option<String> {
    if let Some(marker) = FORBIDDEN.iter().find(|marker| line.contains(*marker)) {
        return Some((*marker).to_owned());
    }
    let words: Vec<&str> =
        line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':')).filter(|w| !w.is_empty()).collect();
    for word in &words {
        for module in FORBIDDEN_MODULES {
            if *word == *module && line.contains("use ") && line.contains('{') {
                return Some(format!("{module} in a use group"));
            }
            let parts: Vec<&str> = word.split("::").collect();
            if parts.len() > 1 && parts[..parts.len() - 1].contains(module) {
                return Some(format!("{module}::"));
            }
        }
    }
    None
}

/// A worktree's change against its base commit: the binary patch and the paths it touches.
#[derive(Debug, Clone, Default)]
pub struct Diff {
    pub patch: String,
    pub paths: Vec<String>,
}

impl Diff {
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
    }

    pub fn sha256(&self) -> String {
        rampage_arch::hex::bytes(&Sha256::digest(self.patch.as_bytes()))
    }

    /// Lines added and removed, as `git diff --stat` counts text lines.
    pub fn line_counts(&self) -> (usize, usize) {
        let mut counts = (0, 0);
        for line in self.patch.lines() {
            if line.starts_with("+++") || line.starts_with("---") {
                continue;
            }
            if line.starts_with('+') {
                counts.0 += 1;
            } else if line.starts_with('-') {
                counts.1 += 1;
            }
        }
        counts
    }
}

/// Every reason `diff` is refused for a family with `allowlist`: a path outside it, a symlink, submodule, mode
/// change or binary file, or an added line with a [`forbidden`] marker.
pub fn policy_violations(diff: &Diff, allowlist: &[&str]) -> Vec<String> {
    let mut violations = Vec::new();
    for path in &diff.paths {
        if !allowed(path, allowlist) {
            violations.push(format!("{path}: outside the allowlist"));
        }
    }
    let mut current = String::new();
    for line in diff.patch.lines() {
        if let Some(header) = line.strip_prefix("diff --git ") {
            current = match header.strip_prefix("a/").and_then(|rest| rest.split_once(" b/")) {
                Some((_, after)) => after.to_owned(),
                None => {
                    violations.push(format!("unusual path in `{line}`"));
                    header.to_owned()
                }
            };
            continue;
        }
        let mode = ["new file mode ", "deleted file mode ", "old mode ", "new mode "]
            .iter()
            .find_map(|prefix| line.strip_prefix(prefix));
        if let Some(mode) = mode {
            if line.starts_with("old mode ") || line.starts_with("new mode ") {
                violations.push(format!("{current}: file mode change"));
            } else if mode != "100644" {
                violations.push(format!("{current}: file mode {mode} (only plain files)"));
            }
            continue;
        }
        if line == "GIT binary patch" || line.starts_with("Binary files ") {
            violations.push(format!("{current}: binary file"));
            continue;
        }
        if let Some(added) = line.strip_prefix('+')
            && !line.starts_with("+++")
            && let Some(marker) = forbidden(added)
        {
            violations.push(format!("{current}: added line uses `{marker}`: {}", added.trim()));
        }
    }
    violations.sort();
    violations.dedup();
    violations
}

/// Runs a command and returns its standard output, or an error with its standard error.
pub fn output(command: &mut Command) -> Result<String, String> {
    let shown = format!("{command:?}");
    let output = command.output().map_err(|error| format!("{shown}: {error}"))?;
    if !output.status.success() {
        return Err(format!("{shown}: {}: {}", output.status, String::from_utf8_lossy(&output.stderr).trim()));
    }
    String::from_utf8(output.stdout).map_err(|error| format!("{shown}: {error}"))
}

pub fn git(directory: &Path) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(directory);
    command
}

/// The full commit id `revision` names in `repository`.
pub fn resolve_commit(repository: &Path, revision: &str) -> Result<String, String> {
    Ok(output(git(repository).args(["rev-parse", "--verify", &format!("{revision}^{{commit}}")]))?.trim().to_owned())
}

/// A detached worktree of `repository` at `commit` in `path` (which must not exist).
pub fn add_worktree(repository: &Path, path: &Path, commit: &str) -> Result<(), String> {
    output(git(repository).args(["worktree", "add", "--detach"]).arg(path).arg(commit)).map(|_| ())
}

/// Removes a worktree made by [`add_worktree`], with whatever it holds.
pub fn remove_worktree(repository: &Path, path: &Path) -> Result<(), String> {
    if path.exists() {
        output(git(repository).args(["worktree", "remove", "--force"]).arg(path))?;
    }
    output(git(repository).args(["worktree", "prune"])).map(|_| ())
}

/// The change in `worktree` against `base`, untracked files included and ignored ones left out, read through a
/// private index so the worktree's own index and commits do not matter.
pub fn capture_diff(worktree: &Path, base: &str, scratch_index: &Path) -> Result<Diff, String> {
    let _ = std::fs::remove_file(scratch_index);
    let with_index = |args: &[&str]| -> Result<String, String> {
        let mut command = git(worktree);
        command.env("GIT_INDEX_FILE", scratch_index).args(args);
        output(&mut command)
    };
    with_index(&["add", "-A"])?;
    let patch = with_index(&["diff", "--cached", "--binary", "--no-renames", "--full-index", base])?;
    let names = with_index(&["diff", "--cached", "--no-renames", "--name-only", "-z", base])?;
    let _ = std::fs::remove_file(scratch_index);
    let paths = names.split('\0').filter(|name| !name.is_empty()).map(str::to_owned).collect();
    Ok(Diff { patch, paths })
}

/// Resets `worktree` to `base` exactly and applies `diff` (nothing when it is empty).
pub fn apply_diff(worktree: &Path, base: &str, diff: &Diff, patch_file: &Path) -> Result<(), String> {
    output(git(worktree).args(["reset", "--quiet", "--hard", base]))?;
    output(git(worktree).args(["clean", "-q", "-ffdx"]))?;
    if diff.is_empty() {
        return Ok(());
    }
    std::fs::write(patch_file, &diff.patch).map_err(|error| format!("{}: {error}", patch_file.display()))?;
    output(git(worktree).args(["apply", "--binary", "--whitespace=nowarn"]).arg(patch_file)).map(|_| ())
}

/// A macOS sandbox (`sandbox-exec`) for every process the agent's work runs in: the session itself, the build and
/// tests of its change, and identification with the changed matcher. Everything is allowed except reading or writing
/// the denied paths (the corpus, the flywheel directory, the repository's target directory, transcripts of other
/// sessions), and writing the protected paths (the repository's own checkout); the allowed paths are carved back
/// out, the later rule winning.
#[derive(Debug, Clone, Default)]
pub struct Sandbox {
    /// Neither read nor written.
    pub deny: Vec<PathBuf>,
    /// Read but not written.
    pub protect: Vec<PathBuf>,
    /// Read and written, overriding `deny` and `protect` beneath them.
    pub allow: Vec<PathBuf>,
}

/// The sandbox launcher; present on every macOS.
pub const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

impl Sandbox {
    /// The profile text (SBPL). Paths must already be canonical, since the kernel checks resolved paths.
    pub fn profile(&self) -> String {
        let quote = |path: &Path| {
            let text = path.to_string_lossy();
            format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
        };
        let mut text = String::from("(version 1)\n(allow default)\n");
        for path in &self.deny {
            text.push_str(&format!("(deny file-read* file-write* (subpath {}))\n", quote(path)));
        }
        for path in &self.protect {
            text.push_str(&format!("(deny file-write* (subpath {}))\n", quote(path)));
        }
        for path in &self.allow {
            text.push_str(&format!("(allow file-read* file-write* (subpath {}))\n", quote(path)));
        }
        text
    }

    /// Writes the profile to `path` and returns a command that runs `program` inside it.
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

    /// This sandbox with `paths` also allowed.
    pub fn allowing(&self, paths: &[&Path]) -> Sandbox {
        let mut sandbox = self.clone();
        sandbox.allow.extend(paths.iter().map(|path| path.to_path_buf()));
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

/// A corpus view: a directory with a manifest of only the binaries of `roles`, and copies (copy-on-write clones on
/// APFS) of only their files. With `truth`, each binary's symbolized twin and objects come along (the training
/// split, whose truth the agent may read); without, the twin entry points at the stripped binary and no object is
/// copied, so nothing in the view can say what a function is called.
pub fn make_view(corpus: &Corpus, roles: &[Role], truth: bool, view: &Path) -> Result<usize, String> {
    let mut binaries: Vec<CorpusBinary> = Vec::new();
    let mut files: BTreeSet<String> = BTreeSet::new();
    for binary in corpus.manifest.binaries.iter().filter(|binary| roles.contains(&binary.split)) {
        let mut entry = binary.clone();
        files.insert(entry.stripped.clone());
        if truth {
            files.insert(entry.twin.clone());
            files.extend(entry.program_object.iter().cloned());
            files.extend(entry.library_object.iter().cloned());
        } else {
            entry.twin = entry.stripped.clone();
            entry.twin_sha256 = entry.stripped_sha256.clone();
            entry.program_object = None;
            entry.program_object_sha256 = None;
            entry.library_object = None;
            entry.program_names = Vec::new();
        }
        binaries.push(entry);
    }
    if binaries.is_empty() {
        return Err(format!("the corpus has no binary in {roles:?}"));
    }
    std::fs::create_dir_all(view).map_err(|error| format!("{}: {error}", view.display()))?;
    for relative in &files {
        let (from, to) = (corpus.path(relative), view.join(relative));
        if let Some(parent) = to.parent() {
            std::fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
        }
        if !to.is_file() {
            std::fs::copy(&from, &to).map_err(|error| format!("{} -> {}: {error}", from.display(), to.display()))?;
        }
    }
    let count = binaries.len();
    let manifest = CorpusManifest { binaries, ..corpus.manifest.clone() };
    let text = serde_json::to_string_pretty(&manifest).map_err(|error| error.to_string())?;
    let path = view.join(rampage_api::flywheel::MANIFEST);
    std::fs::write(&path, text).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(count)
}

/// The in-session gate client: submits a request into the spool the harness watches and waits for its answer.
pub fn gate_client(spool: &Path) -> String {
    let spool = spool.to_string_lossy().replace('\'', "'\\''");
    format!(
        r#"#!/bin/sh
# flywheel-gate: gate this worktree's change (build, rampage-signatures tests, training, negatives, dev verdict,
# slices, time). Prints the gate's JSON answer; exits 0 when every stage passes, 1 when one fails, 3 when it is still
# running after FLYWHEEL_GATE_WAIT seconds (then run `flywheel-gate --wait ID`).
set -eu
spool='{spool}'
if [ "${{1:-}}" = "--wait" ]; then
  id="${{2:?usage: flywheel-gate --wait ID}}"
else
  id="$(date +%s)-$$"
  printf '{{"id":"%s"}}\n' "$id" > "$spool/requests/.$id.tmp"
  mv "$spool/requests/.$id.tmp" "$spool/requests/$id.json"
  echo "gate request $id submitted; a gate takes several minutes" >&2
fi
waited=0
limit="${{FLYWHEEL_GATE_WAIT:-1500}}"
while [ ! -f "$spool/responses/$id.status" ]; do
  if [ "$waited" -ge "$limit" ]; then
    echo "gate $id is still running; run: flywheel-gate --wait $id" >&2
    exit 3
  fi
  sleep 5
  waited=$((waited + 5))
done
cat "$spool/responses/$id.json"
[ "$(cat "$spool/responses/$id.status")" = "pass" ]
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_allowlist_admits_the_matcher_modules_and_nothing_beside_them() {
        let list = LIBID_ALLOWLIST;
        for path in [
            "crates/rampage-signatures/src/callgraph.rs",
            "crates/rampage-signatures/src/lib.rs",
            "crates/rampage-signatures/src/heuristics/wrappers.rs",
            "crates/rampage-signatures/tests/cross_program.rs",
            "crates/rampage-signatures/tests/new_test.rs",
        ] {
            assert!(allowed(path, list), "{path}");
        }
        for path in [
            "crates/rampage-signatures/Cargo.toml",
            "crates/rampage-signatures/build.rs",
            "crates/rampage-signatures/data/callgraph.json.gz",
            "crates/rampage-signatures/src/bundled.rs",
            "crates/rampage-signatures/src/lib.rs.orig",
            "crates/rampage-signatures/src/heuristics",
            "crates/rampage-signatures/src/heuristics/",
            "crates/rampage-signatures/src/heuristics/../bundled.rs",
            "crates/rampage-api/src/flywheel/engine.rs",
            "crates/rampage-eval/src/flywheel_code.rs",
            "tools/agent-bench/claude-runner.py",
            "notes.md",
            "/crates/rampage-signatures/src/lib.rs",
            "",
        ] {
            assert!(!allowed(path, list), "{path}");
        }
    }

    fn diff(patch: &str) -> Diff {
        let mut paths = Vec::new();
        for line in patch.lines() {
            if let Some((_, after)) = line.strip_prefix("diff --git a/").and_then(|rest| rest.split_once(" b/")) {
                paths.push(after.to_owned());
            }
        }
        Diff { patch: patch.to_owned(), paths }
    }

    #[test]
    fn a_change_outside_the_allowlist_fails_and_one_inside_passes() {
        let inside = diff(
            "diff --git a/crates/rampage-signatures/src/callgraph.rs b/crates/rampage-signatures/src/callgraph.rs\n\
             index 1..2 100644\n--- a/x\n+++ b/x\n@@ -1 +1,2 @@\n fn a() {}\n+fn b() -> usize { 1 }\n",
        );
        assert_eq!(policy_violations(&inside, LIBID_ALLOWLIST), Vec::<String>::new());
        let outside = diff(
            "diff --git a/crates/rampage-signatures/src/callgraph.rs b/crates/rampage-signatures/src/callgraph.rs\n\
             +fn b() {}\n\
             diff --git a/crates/rampage-api/src/flywheel/evaluation.rs b/crates/rampage-api/src/flywheel/evaluation.rs\n\
             +// make the gate lenient\n",
        );
        let violations = policy_violations(&outside, LIBID_ALLOWLIST);
        assert_eq!(violations, ["crates/rampage-api/src/flywheel/evaluation.rs: outside the allowlist"]);
    }

    #[test]
    fn added_io_symlinks_modes_and_binaries_are_refused() {
        let file = "diff --git a/crates/rampage-signatures/src/lib.rs b/crates/rampage-signatures/src/lib.rs\n";
        for line in [
            "+    let t = std::fs::read_to_string(\"/x\");",
            "+use std::{collections::BTreeMap, fs};",
            "+    let v = env::var(\"HOME\");",
            "+const T: &str = include_str!(\"/truth.json\");",
            "+#[path = \"/elsewhere.rs\"]",
            "+    unsafe { core::ptr::read(p) }",
            "+    let _ = process::Command::new(\"cat\");",
        ] {
            let violations = policy_violations(&diff(&format!("{file}{line}\n")), LIBID_ALLOWLIST);
            assert_eq!(violations.len(), 1, "{line}: {violations:?}");
        }
        for line in [
            "+    let fsize = names.len();",
            "+    // the environment of a call site",
            "+use std::collections::BTreeMap;",
        ] {
            assert!(policy_violations(&diff(&format!("{file}{line}\n")), LIBID_ALLOWLIST).is_empty(), "{line}");
        }
        // A removed line may mention anything.
        assert!(policy_violations(&diff(&format!("{file}-use std::fs;\n")), LIBID_ALLOWLIST).is_empty());
        for header in ["new file mode 120000", "old mode 100644\nnew mode 100755", "GIT binary patch"] {
            let violations = policy_violations(&diff(&format!("{file}{header}\n")), LIBID_ALLOWLIST);
            assert!(!violations.is_empty(), "{header}");
        }
        assert!(policy_violations(&diff(&format!("{file}new file mode 100644\n")), LIBID_ALLOWLIST).is_empty());
    }

    #[test]
    fn the_sandbox_profile_denies_then_carves_back_in_order() {
        let sandbox = Sandbox {
            deny: vec![PathBuf::from("/data/flywheel")],
            protect: vec![PathBuf::from("/repo")],
            allow: vec![PathBuf::from("/data/flywheel/code-runs/x/views/train"), PathBuf::from("/odd\"path")],
        };
        let profile = sandbox.profile();
        let deny = profile.find("(deny file-read* file-write* (subpath \"/data/flywheel\"))").unwrap();
        let protect = profile.find("(deny file-write* (subpath \"/repo\"))").unwrap();
        let allow = profile.find("(allow file-read* file-write* (subpath \"/data/flywheel/code-runs/x/views/train\"))");
        assert!(deny < protect && protect < allow.unwrap(), "{profile}");
        assert!(profile.contains("\"/odd\\\"path\""), "{profile}");
        assert!(profile.starts_with("(version 1)\n(allow default)\n"));
    }

    /// The isolation itself: a scripted stand-in for the session, run inside the sandbox the harness builds, cannot
    /// read a final-split file or list its directory, nor write the protected checkout, while it can read its
    /// training view and write its worktree.
    #[test]
    #[cfg(target_os = "macos")]
    fn a_scripted_session_cannot_read_final_files() {
        let root = canonical(&std::env::temp_dir()).join(format!("rampage-code-sandbox-{}", std::process::id()));
        let corpus = root.join("flywheel/corpus/libid-test");
        let train = root.join("session/flywheel/corpus/libid-test-train");
        let worktree = root.join("session/worktree");
        let checkout = root.join("checkout");
        for directory in [&corpus.join("bin"), &train.join("bin"), &worktree, &checkout] {
            std::fs::create_dir_all(directory).unwrap();
        }
        std::fs::write(corpus.join("bin/zlib-1.2.12-final.twin.elf"), "final truth").unwrap();
        std::fs::write(corpus.join("final-ledger.jsonl"), "{}\n").unwrap();
        std::fs::write(train.join("bin/zlib-1.2.13-train.twin.elf"), "training truth").unwrap();
        std::fs::write(checkout.join("README.md"), "checkout").unwrap();
        let sandbox = Sandbox {
            deny: vec![root.join("flywheel")],
            protect: vec![checkout.clone()],
            allow: vec![root.join("session")],
        };
        let script = format!(
            "cat {final_file} && echo READ-FINAL; ls {final_dir} && echo LISTED-FINAL; \
             cat {ledger} && echo READ-LEDGER; echo x >> {readme} && echo WROTE-CHECKOUT; \
             cat {train_file} && echo READ-TRAIN; echo change > {worktree}/lib.rs && echo WROTE-WORKTREE",
            final_file = corpus.join("bin/zlib-1.2.12-final.twin.elf").display(),
            final_dir = corpus.join("bin").display(),
            ledger = corpus.join("final-ledger.jsonl").display(),
            readme = checkout.join("README.md").display(),
            train_file = train.join("bin/zlib-1.2.13-train.twin.elf").display(),
            worktree = worktree.display(),
        );
        let out = sandbox
            .command(&root.join("session.sb"), Path::new("/bin/sh"))
            .unwrap()
            .arg("-c")
            .arg(&script)
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(!stdout.contains("final truth") && !stdout.contains("READ-FINAL"), "{stdout}{stderr}");
        assert!(!stdout.contains("LISTED-FINAL") && !stdout.contains("READ-LEDGER"), "{stdout}{stderr}");
        assert!(!stdout.contains("WROTE-CHECKOUT"), "{stdout}{stderr}");
        assert!(stderr.contains("Operation not permitted"), "{stderr}");
        assert!(stdout.contains("training truth") && stdout.contains("READ-TRAIN"), "{stdout}{stderr}");
        assert!(stdout.contains("WROTE-WORKTREE"), "{stdout}{stderr}");
        assert_eq!(std::fs::read_to_string(checkout.join("README.md")).unwrap(), "checkout");
        // The sandbox cannot be replaced from inside: a nested sandbox-exec is refused.
        let nested = sandbox
            .command(&root.join("session.sb"), Path::new(SANDBOX_EXEC))
            .unwrap()
            .args(["-p", "(version 1)(allow default)", "/bin/cat"])
            .arg(corpus.join("bin/zlib-1.2.12-final.twin.elf"))
            .output()
            .unwrap();
        assert!(!nested.status.success() && !String::from_utf8_lossy(&nested.stdout).contains("final truth"));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn the_gate_client_quotes_its_spool_and_waits_for_a_status() {
        let client = gate_client(Path::new("/tmp/it's here/gate"));
        assert!(client.contains("spool='/tmp/it'\\''s here/gate'"), "{client}");
        assert!(client.contains("responses/$id.status") && client.contains("--wait"));
    }

    #[test]
    #[cfg(unix)]
    fn diffs_are_captured_with_untracked_files_and_applied_to_a_clean_copy() {
        let root = canonical(&std::env::temp_dir()).join(format!("rampage-code-diff-{}", std::process::id()));
        let repository = root.join("repo");
        std::fs::create_dir_all(repository.join("src")).unwrap();
        std::fs::write(repository.join("src/lib.rs"), "fn a() {}\n").unwrap();
        std::fs::write(repository.join(".gitignore"), "ignored/\n").unwrap();
        let run = |args: &[&str]| {
            output(git(&repository).args(["-c", "user.name=t", "-c", "user.email=t@t"]).args(args)).unwrap()
        };
        run(&["init", "-q"]);
        run(&["add", "-A"]);
        run(&["commit", "-qm", "base"]);
        let base = resolve_commit(&repository, "HEAD").unwrap();
        let (agent, gate) = (root.join("agent"), root.join("gate"));
        add_worktree(&repository, &agent, &base).unwrap();
        add_worktree(&repository, &gate, &base).unwrap();
        let empty = capture_diff(&agent, &base, &root.join("index")).unwrap();
        assert!(empty.is_empty() && empty.patch.is_empty());
        std::fs::write(agent.join("src/lib.rs"), "fn a() {}\nfn b() {}\n").unwrap();
        std::fs::write(agent.join("src/new.rs"), "fn c() {}\n").unwrap();
        std::fs::create_dir_all(agent.join("ignored")).unwrap();
        std::fs::write(agent.join("ignored/build.log"), "x").unwrap();
        // Committing in the session's worktree changes nothing: the diff is always against the base.
        output(git(&agent).args(["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "agent"])).unwrap();
        let diff = capture_diff(&agent, &base, &root.join("index")).unwrap();
        assert_eq!(diff.paths, ["src/lib.rs", "src/new.rs"]);
        assert_eq!(diff.line_counts(), (2, 0));
        std::fs::write(gate.join("stale.txt"), "left over").unwrap();
        apply_diff(&gate, &base, &diff, &root.join("change.patch")).unwrap();
        assert_eq!(std::fs::read_to_string(gate.join("src/new.rs")).unwrap(), "fn c() {}\n");
        assert!(!gate.join("stale.txt").exists());
        apply_diff(&gate, &base, &Diff::default(), &root.join("change.patch")).unwrap();
        assert!(!gate.join("src/new.rs").exists());
        remove_worktree(&repository, &agent).unwrap();
        remove_worktree(&repository, &gate).unwrap();
        assert!(!agent.exists() && !gate.exists());
        std::fs::remove_dir_all(&root).unwrap();
    }
}
