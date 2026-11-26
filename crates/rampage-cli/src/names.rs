//! MCP tool names typed at the CLI. Agents that know the MCP tools type `rampage binary_info FILE`; every MCP tool
//! with one CLI command is a hidden alias for it, read from [`MCP_ROUTES`] alone. An unknown subcommand gets an error
//! that names the right one: the CLI path of an MCP tool name, or the nearest commands by edit distance.

use std::ffi::OsString;

/// An MCP tool and the CLI command that does the same thing.
pub(crate) struct McpRoute {
    pub(crate) tool: &'static str,
    /// The subcommand path below `rampage`.
    pub(crate) path: &'static [&'static str],
    /// Flags the CLI command needs to act as the tool does. A route with flags is suggested, never aliased: the
    /// command without them does something else.
    pub(crate) flags: &'static str,
}

const fn route(tool: &'static str, path: &'static [&'static str]) -> McpRoute {
    McpRoute { tool, path, flags: "" }
}

/// Every MCP tool with a one-to-one CLI command. The only place these mappings are written.
pub(crate) const MCP_ROUTES: &[McpRoute] = &[
    route("binary_info", &["binary", "inspect"]),
    route("triage", &["binary", "triage"]),
    route("inspect_sleigh", &["binary", "inspect-sleigh"]),
    route("patch_bytes", &["binary", "patch-bytes"]),
    route("revert_patch", &["binary", "revert-patch"]),
    route("list_patches", &["binary", "list-patches"]),
    route("export_patched", &["binary", "export-patched"]),
    route("assemble", &["binary", "assemble"]),
    route("search", &["binary", "search"]),
    route("inspect_data", &["binary", "inspect-data"]),
    route("inspect_raw_code", &["binary", "inspect-raw"]),
    route("decode_file_range", &["binary", "decode"]),
    McpRoute { tool: "write_decoded_range", path: &["binary", "decode"], flags: "--output <PATH>" },
    route("file_layout", &["binary", "layout"]),
    route("probe_compression", &["binary", "probe-compression"]),
    route("pe_resources", &["binary", "pe-resources"]),
    route("pe_load_config", &["binary", "pe-load-config"]),
    route("detect_tools", &["binary", "detect"]),
    route("capabilities", &["binary", "capabilities"]),
    route("peripheral_map", &["binary", "peripheral-map"]),
    route("build_info", &["binary", "build-info"]),
    route("analysis_diagnostics", &["binary", "audit"]),
    route("carve", &["binary", "carve"]),
    route("archive_inventory", &["binary", "archive-inventory"]),
    route("pyinstaller_archive", &["binary", "pyinstaller-archive"]),
    route("wasm_module", &["binary", "wasm-module"]),
    route("list_imports", &["binary", "list-imports"]),
    route("list_exports", &["binary", "list-exports"]),
    route("yara_scan", &["binary", "scan-yara"]),
    route("capa_detect", &["binary", "scan-capa"]),
    route("list_functions", &["function", "list"]),
    route("disassemble", &["function", "disassemble"]),
    route("decompile", &["function", "decompile"]),
    route("function_summary", &["function", "summarize"]),
    route("function_graph", &["function", "graph"]),
    route("batch", &["function", "batch"]),
    route("xrefs", &["function", "xrefs"]),
    route("identify_functions", &["function", "identify"]),
    route("build_signatures", &["function", "build-signatures"]),
    route("inspect_jump_table", &["function", "inspect-table"]),
    route("evaluate_function", &["function", "evaluate"]),
    route("list_strings", &["string", "list"]),
    route("language_metadata", &["language", "inspect"]),
    route("objc_sends", &["language", "objc-sends"]),
    route("dotnet_metadata", &["managed", "inspect"]),
    route("dotnet_il", &["managed", "disassemble"]),
    route("list_annotations", &["annotation", "list"]),
    route("rename", &["annotation", "rename"]),
    route("set_comment", &["annotation", "comment"]),
    route("annotate_batch", &["annotation", "apply-batch"]),
    route("check_names", &["annotation", "check-names"]),
    route("record_finding", &["annotation", "record-finding"]),
    route("list_findings", &["annotation", "list-findings"]),
    route("transfer_annotations", &["annotation", "transfer"]),
    route("import_debug_signatures", &["type", "import-debug"]),
    route("import_debug_layouts", &["type", "import-debug-layouts"]),
    route("import_pdb_names", &["type", "import-pdb-names"]),
    route("observe_pointer", &["runtime", "pointer", "observe"]),
    route("compare_pointer_observations", &["runtime", "pointer", "compare"]),
    route("observe_indirect_branch", &["runtime", "branch", "inspect"]),
    route("compare_runtime_bytes", &["runtime", "bytes", "compare"]),
    route("query_debugger", &["runtime", "debugger", "query"]),
    route("list_packs", &["pack", "list"]),
];

/// The route of an MCP tool name, also written with dashes (`binary-info`), for suggestions.
fn mcp_route(token: &str) -> Option<&'static McpRoute> {
    let name = token.replace('-', "_");
    MCP_ROUTES.iter().find(|route| route.tool == name)
}

/// Where the subcommand tokens of `args` (with the program name first) start and which command each names: the
/// index of the first token that is not a subcommand of the command before it, and that command's path. Options
/// and their values are skipped.
fn walk<'a>(root: &'a clap::Command, args: &[OsString]) -> (Vec<&'a clap::Command>, Option<usize>) {
    let mut path = vec![root];
    let mut index = 1;
    while index < args.len() {
        let current = *path.last().unwrap();
        let Some(token) = args[index].to_str() else { return (path, None) };
        if token == "--" {
            return (path, None);
        }
        if let Some(option) = token.strip_prefix('-') {
            index += 1 + usize::from(takes_value(root, current, option));
            continue;
        }
        if !current.has_subcommands() {
            return (path, None);
        }
        match current.find_subcommand(token) {
            Some(next) => path.push(next),
            None => return (path, Some(index)),
        }
        index += 1;
    }
    (path, None)
}

/// Whether the option `option` (written without its first dash) of `command` or a global of `root` takes its value
/// from the next token.
fn takes_value(root: &clap::Command, command: &clap::Command, option: &str) -> bool {
    let takes = |argument: &clap::Arg| argument.get_action().takes_values();
    if let Some(long) = option.strip_prefix('-') {
        if long.contains('=') {
            return false;
        }
        let named = |argument: &&clap::Arg| {
            argument.get_long() == Some(long)
                || argument.get_all_aliases().is_some_and(|aliases| aliases.contains(&long))
        };
        return command.get_arguments().chain(root.get_arguments()).find(named).is_some_and(takes);
    }
    // A short option: the value is the next token only when nothing follows the letter.
    let mut letters = option.chars();
    match (letters.next(), letters.next()) {
        (Some(short), None) => command
            .get_arguments()
            .chain(root.get_arguments())
            .find(|argument| {
                argument.get_short() == Some(short)
                    || argument.get_all_short_aliases().is_some_and(|aliases| aliases.contains(&short))
            })
            .is_some_and(takes),
        _ => false,
    }
}

/// The names of `path`'s commands below the root, without a leading `help` (`rampage help binary inspect`).
fn names(path: &[&clap::Command]) -> Vec<String> {
    let mut names: Vec<String> = path.iter().skip(1).map(|command| command.get_name().to_owned()).collect();
    if names.first().is_some_and(|name| name == "help") {
        names.remove(0);
    }
    names
}

/// `args` with an MCP tool name in place of a subcommand replaced by its CLI path, when the route needs no flags
/// and continues the path typed so far (`rampage binary_info`, `rampage binary binary_info`, `rampage help
/// binary_info`).
pub(crate) fn rewrite(root: &clap::Command, mut args: Vec<OsString>) -> Vec<OsString> {
    let (path, Some(index)) = walk(root, &args) else { return args };
    let typed = names(&path);
    // Only the exact tool name: a dashed spelling such as `archive-inventory` is a retired flat command, which stays
    // refused with the route named.
    let Some(route) = args[index].to_str().and_then(|token| MCP_ROUTES.iter().find(|route| route.tool == token)) else {
        return args;
    };
    if !route.flags.is_empty() || !route.path.starts_with(&typed.iter().map(String::as_str).collect::<Vec<_>>()) {
        return args;
    }
    let rest = route.path[typed.len()..].iter().map(OsString::from);
    args.splice(index..=index, rest);
    args
}

/// The error for an unknown subcommand in `args`, naming the command meant; `None` when `args` has none.
pub(crate) fn unknown_subcommand(root: &clap::Command, args: &[OsString], mcp_tools: &[&str]) -> Option<String> {
    let (path, Some(index)) = walk(root, args) else { return None };
    let token = args[index].to_str()?;
    let typed = names(&path);
    let shown = |words: &[&str]| format!("rampage {}", words.join(" "));
    let mut message = format!("unrecognized subcommand '{token}'");
    if let Some(route) = mcp_route(token) {
        let flags = if route.flags.is_empty() { String::new() } else { format!(" {}", route.flags) };
        message.push_str(&format!(
            "\n\n  '{}' is an MCP tool; the CLI command is `{}{flags}`",
            route.tool,
            shown(route.path)
        ));
    } else if mcp_tools.iter().any(|tool| *tool == token.replace('-', "_")) {
        message.push_str(&format!(
            "\n\n  '{token}' is an MCP tool with no CLI command; call it through `rampage server serve`"
        ));
    } else {
        let nearest = nearest(root, &typed, token);
        if !nearest.is_empty() {
            let list: Vec<String> = nearest.iter().map(|words| format!("`rampage {}`", words.join(" "))).collect();
            message.push_str(&format!("\n\n  did you mean {}?", list.join(" or ")));
        }
    }
    let usage =
        if typed.is_empty() { "rampage --help".to_owned() } else { format!("rampage {} --help", typed.join(" ")) };
    message.push_str(&format!("\n\nFor the commands, try '{usage}'."));
    Some(message)
}

/// The visible commands and groups (and MCP routes without flags) nearest `token` by edit distance; only those in
/// the group typed so far when any is close. At most three.
fn nearest(root: &clap::Command, typed: &[String], token: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    collect(root, &mut Vec::new(), &mut commands);
    let mut scored: Vec<(usize, bool, Vec<String>)> = commands
        .into_iter()
        .map(|words| {
            let below = words.len() == typed.len() + 1 && words.starts_with(typed);
            (score(token, words.last().unwrap()), below, words)
        })
        .collect();
    let tool = token.replace('-', "_");
    for route in MCP_ROUTES.iter().filter(|route| route.flags.is_empty()) {
        let words = route.path.iter().map(|word| (*word).to_owned()).collect();
        scored.push((score(&tool, route.tool), false, words));
    }
    let limit = (token.chars().count() / 3).max(2);
    scored.retain(|(distance, ..)| *distance <= limit);
    // A close command in the group typed so far is the one meant.
    if scored.iter().any(|(_, below, _)| *below) {
        scored.retain(|(_, below, _)| *below);
    }
    let Some(best) = scored.iter().map(|(distance, ..)| *distance).min() else { return Vec::new() };
    scored.retain(|(distance, ..)| *distance == best);
    scored.sort_by(|a, b| a.2.cmp(&b.2));
    let mut nearest: Vec<Vec<String>> = Vec::new();
    for (_, _, words) in scored {
        if !nearest.contains(&words) {
            nearest.push(words);
        }
    }
    nearest.truncate(3);
    nearest
}

/// Every visible command and group below `command`, as its path of names.
fn collect(command: &clap::Command, prefix: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
    for sub in command.get_subcommands().filter(|sub| !sub.is_hide_set() && sub.get_name() != "help") {
        prefix.push(sub.get_name().to_owned());
        out.push(prefix.clone());
        collect(sub, prefix, out);
        prefix.pop();
    }
}

/// How far `token` is from the name `name`: zero when it is a prefix of at least three characters (`decomp` for
/// `decompile`), otherwise the edit distance.
fn score(token: &str, name: &str) -> usize {
    if token.chars().count() >= 3 && name.starts_with(token) { 0 } else { distance(token, name) }
}

/// The Levenshtein distance between `a` and `b`, by characters.
fn distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut previous = row[0];
        row[0] = i + 1;
        for (j, &cb) in b.iter().enumerate() {
            let substitution = previous + usize::from(ca != cb);
            previous = row[j + 1];
            row[j + 1] = substitution.min(row[j] + 1).min(previous + 1);
        }
    }
    row[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn root() -> clap::Command {
        let mut root = crate::hierarchy::with_pack_arguments(crate::Cli::command());
        root.build();
        root
    }

    fn args(words: &[&str]) -> Vec<OsString> {
        std::iter::once("rampage").chain(words.iter().copied()).map(OsString::from).collect()
    }

    fn mcp_tools() -> Vec<&'static str> {
        rampage_mcp::all_tool_names()
    }

    fn rampage_words(args: &[OsString]) -> Vec<&str> {
        args.iter().map(|arg| arg.to_str().unwrap()).collect()
    }

    /// The argument IDs of the command at `path` below `root`.
    fn argument_ids(root: &clap::Command, path: &[&str]) -> Vec<String> {
        let mut command = root;
        for word in path {
            command = command.find_subcommand(word).unwrap();
        }
        let mut ids: Vec<String> = command.get_arguments().map(|argument| argument.get_id().to_string()).collect();
        ids.sort();
        ids
    }

    #[test]
    fn every_route_names_a_real_cli_command_and_a_real_mcp_tool() {
        let root = root();
        let tools = mcp_tools();
        for route in MCP_ROUTES {
            let mut command = &root;
            for word in route.path {
                command = command
                    .find_subcommand(word)
                    .unwrap_or_else(|| panic!("{}: no CLI command {:?}", route.tool, route.path));
            }
            assert!(!command.has_subcommands(), "{}: {:?} is a group, not a command", route.tool, route.path);
            assert!(!command.is_hide_set(), "{}: {:?} is hidden", route.tool, route.path);
            assert!(tools.contains(&route.tool), "{} is not an MCP tool", route.tool);
            assert_eq!(MCP_ROUTES.iter().filter(|other| other.tool == route.tool).count(), 1, "{}", route.tool);
        }
    }

    #[test]
    fn the_cli_reference_lists_every_route() {
        let reference = include_str!("../../../docs/cli-reference.md");
        let section = &reference[reference.find("## MCP tool names").expect("section")..];
        let rows: Vec<&str> = section.lines().filter(|line| line.starts_with("| `")).collect();
        assert_eq!(rows.len(), MCP_ROUTES.len());
        for route in MCP_ROUTES {
            let flags = if route.flags.is_empty() { String::new() } else { format!(" {}", route.flags) };
            let row = format!("| `{}` | `{}{flags}`", route.tool, route.path.join(" "));
            assert!(rows.iter().any(|line| line.starts_with(&row)), "docs/cli-reference.md lacks {row}");
        }
    }

    #[test]
    fn every_alias_parses_as_its_command() {
        let root = root();
        for route in MCP_ROUTES.iter().filter(|route| route.flags.is_empty()) {
            let rewritten = rewrite(&root, args(&[route.tool, "--help"]));
            let expected = args(&route.path.iter().copied().chain(["--help"]).collect::<Vec<_>>());
            let typed = rampage_words(&rewritten);
            // A tool whose name is also a hidden top-level spelling (decompile, xrefs) is parsed by clap directly.
            if typed == ["rampage", route.tool, "--help"] {
                assert!(root.find_subcommand(route.tool).is_some(), "{}", route.tool);
                assert_eq!(argument_ids(&root, &[route.tool]), argument_ids(&root, route.path), "{}", route.tool);
            } else {
                assert_eq!(rewritten, expected, "{}", route.tool);
            }
            if route.tool.contains('_') {
                let dashed = route.tool.replace('_', "-");
                let untouched = args(&[&dashed, "--help"]);
                assert_eq!(rewrite(&root, untouched.clone()), untouched, "{dashed}");
            }
        }
    }

    #[test]
    fn rewrite_skips_global_options_and_continues_a_typed_group() {
        let root = root();
        let rewritten = rewrite(&root, args(&["--json", "--arch", "arm", "binary_info", "file"]));
        assert_eq!(rampage_words(&rewritten), ["rampage", "--json", "--arch", "arm", "binary", "inspect", "file"]);
        let rewritten = rewrite(&root, args(&["binary", "binary_info", "file"]));
        assert_eq!(rampage_words(&rewritten), ["rampage", "binary", "inspect", "file"]);
        let rewritten = rewrite(&root, args(&["runtime", "observe_pointer", "file"]));
        assert_eq!(rampage_words(&rewritten), ["rampage", "runtime", "pointer", "observe", "file"]);
        // A tool name under another group, or a file argument that happens to be a tool name, is left alone.
        let untouched = args(&["function", "binary_info", "file"]);
        assert_eq!(rewrite(&root, untouched.clone()), untouched);
        let untouched = args(&["binary", "inspect", "binary_info"]);
        assert_eq!(rewrite(&root, untouched.clone()), untouched);
        let rewritten = rewrite(&root, args(&["help", "binary_info"]));
        assert_eq!(rampage_words(&rewritten), ["rampage", "help", "binary", "inspect"]);
        // A route that needs flags is never an alias.
        let untouched = args(&["write_decoded_range", "file"]);
        assert_eq!(rewrite(&root, untouched.clone()), untouched);
    }

    #[test]
    fn unknown_subcommands_name_the_command_meant() {
        let root = root();
        let tools = mcp_tools();
        let message = |words: &[&str]| unknown_subcommand(&root, &args(words), &tools).unwrap();
        assert!(message(&["write_decoded_range", "f"]).contains("`rampage binary decode --output <PATH>`"));
        assert!(message(&["function", "binary_info"]).contains("`rampage binary inspect`"));
        assert!(message(&["enable_tools"]).contains("no CLI command"));
        let typo = message(&["binary", "inspct"]);
        assert!(typo.contains("`rampage binary inspect`") && !typo.contains("language"), "{typo}");
        assert!(message(&["fuction"]).contains("`rampage function"), "{}", message(&["fuction"]));
        assert!(message(&["binary_inf"]).contains("`rampage binary inspect`"), "{}", message(&["binary_inf"]));
        assert!(message(&["binary", "decompile"]).contains("`rampage function decompile`"));
        assert!(!message(&["zzzzzzzzzzzz"]).contains("did you mean"));
        let prefix = message(&["function", "decomp"]);
        assert!(prefix.contains("did you mean `rampage function decompile`?"), "{prefix}");
        let help = message(&["help", "binary", "inspct"]);
        assert!(help.contains("`rampage binary inspect`") && help.contains("try 'rampage binary --help'"), "{help}");
        assert!(unknown_subcommand(&root, &args(&["binary", "inspect", "file"]), &tools).is_none());
    }

    #[test]
    fn distance_counts_edits() {
        assert_eq!(distance("inspect", "inspect"), 0);
        assert_eq!(distance("inspct", "inspect"), 1);
        assert_eq!(distance("", "abc"), 3);
        assert_eq!(distance("kitten", "sitting"), 3);
    }
}
