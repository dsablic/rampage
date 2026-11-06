//! The CLI's command routes and flags (docs/stability.md) pinned against `tests/contract/cli-commands.json`. Every
//! route is listed, hidden compatibility spellings included, with each flag's long and short names, whether it
//! takes a value, repeats or is required, and the positional arguments by position. `tests/contract/support.rs`
//! classifies the differences and says how to update the snapshot.

use std::collections::BTreeMap;

use clap::{ArgAction, CommandFactory};
use serde_json::{Value, json};

#[path = "../../../tests/contract/support.rs"]
mod support;

/// The arguments of `command`, keyed by how a user writes them: `--long`, `-s` and `<N>` for the N-th positional.
fn arguments(command: &clap::Command) -> BTreeMap<String, Value> {
    let mut arguments = BTreeMap::new();
    for argument in command.get_arguments() {
        if matches!(argument.get_action(), ArgAction::Help | ArgAction::HelpShort | ArgAction::HelpLong) {
            continue;
        }
        let action = argument.get_action();
        let summary = json!({
            "type": if action.takes_values() { "value" } else { "flag" },
            "repeated": matches!(action, ArgAction::Append | ArgAction::Count),
            "required": argument.is_required_set(),
        });
        if argument.is_positional() {
            let index = argument.get_index().unwrap_or_default();
            arguments.insert(format!("<{index}>"), summary);
            continue;
        }
        let longs = argument.get_long().into_iter().chain(argument.get_all_aliases().into_iter().flatten());
        for long in longs {
            arguments.insert(format!("--{long}"), summary.clone());
        }
        let shorts = argument.get_short().into_iter().chain(argument.get_all_short_aliases().into_iter().flatten());
        for short in shorts {
            arguments.insert(format!("-{short}"), summary.clone());
        }
    }
    arguments
}

/// Every route under `command` (its own name and aliases included), with its arguments.
fn routes(command: &clap::Command, prefix: &str, out: &mut BTreeMap<String, Value>) {
    let names = std::iter::once(command.get_name()).chain(command.get_all_aliases());
    for name in names {
        let route = if prefix.is_empty() { name.to_owned() } else { format!("{prefix} {name}") };
        let has_subcommands = command.has_subcommands();
        out.insert(
            route.clone(),
            json!({
                "arguments": arguments(command),
                "subcommand_required": has_subcommands && command.is_subcommand_required_set(),
            }),
        );
        for subcommand in command.get_subcommands() {
            if subcommand.get_name() == "help" {
                continue;
            }
            routes(subcommand, &route, out);
        }
    }
}

/// Compares route snapshots `{"routes": {route: {"arguments": {...}}}}`.
fn compare(old: &Value, new: &Value) -> Vec<support::Change> {
    let (old, new) = (old["routes"].as_object().cloned().unwrap_or_default(), new["routes"].clone());
    let mut changes = Vec::new();
    for (route, old_route) in &old {
        match new.get(route) {
            None => changes.push(support::Change::breaking(format!("command `{route}` was removed or renamed"))),
            Some(new_route) => changes.extend(support::compare_arguments(
                &format!("command `{route}`"),
                &old_route["arguments"],
                &new_route["arguments"],
            )),
        }
    }
    for route in new.as_object().into_iter().flatten().map(|(route, _)| route) {
        if !old.contains_key(route) {
            changes.push(support::Change::additive(format!("command `{route}` was added")));
        }
    }
    changes
}

#[test]
fn contract_cli_commands_and_flags() {
    let mut command = crate::hierarchy::with_pack_arguments(crate::Cli::command());
    command.build();
    let mut all = BTreeMap::new();
    routes(&command, "", &mut all);
    support::check("cli-commands.json", &json!({ "routes": all }), compare);
}
