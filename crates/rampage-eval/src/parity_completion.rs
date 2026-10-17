use std::collections::BTreeSet;

use serde_json::{Value, json};

pub(super) fn assess(report: &Value) -> Value {
    let mut checks = Vec::new();
    let mut check = |name: &str, met: bool| checks.push(json!({"criterion":name,"met":met}));
    let workloads = report["workloads"].as_array().cloned().unwrap_or_default();
    let hashes: BTreeSet<_> =
        workloads.iter().filter(|row| usable_workload(row)).filter_map(|row| row["sha256"].as_str()).collect();
    let mut inventories = Vec::new();
    flatten_inventory(&report["corpus_inventory"], &mut inventories);
    let profiles: Vec<_> = inventories
        .iter()
        .flat_map(|inventory| inventory["entries"].as_array().into_iter().flatten())
        .filter(|entry| {
            entry["status"] == "available" && workloads.iter().any(|workload| profile_matches(entry, workload))
        })
        .collect();
    let scored_hashes: BTreeSet<_> =
        profiles.iter().filter_map(|entry| entry.pointer("/pair/stripped_sha256").and_then(Value::as_str)).collect();
    let has_format = |format: &str, arch: &str, endian: &str| {
        workloads.iter().any(|workload| {
            workload["sha256"].as_str().is_some_and(|hash| scored_hashes.contains(hash))
                && workload.pointer("/metadata/static_function_symbols").and_then(Value::as_u64) == Some(0)
                && workload.pointer("/metadata/debug_sections").and_then(Value::as_array).is_some_and(Vec::is_empty)
                && workload.pointer("/metadata/format").and_then(Value::as_str) == Some(format)
                && workload.pointer("/metadata/arch").and_then(Value::as_str) == Some(arch)
                && workload.pointer("/metadata/endianness").and_then(Value::as_str) == Some(endian)
        })
    };
    let compiler_profile = |compiler: &str, optimization: &str| {
        profiles.iter().any(|entry| {
            entry["compiler"] == compiler
                && entry["arch"] == "x86_64"
                && entry["format"] == "elf"
                && entry["flags"].as_array().is_some_and(|flags| flags.iter().any(|flag| flag == optimization))
        })
    };
    check("gcc_x64_elf_o0", compiler_profile("gcc", "-O0"));
    check("gcc_x64_elf_o2", compiler_profile("gcc", "-O2"));
    check("clang_x64_elf_o2", compiler_profile("clang", "-O2"));
    check("aarch64_elf", has_format("elf", "aarch64", "little"));
    check("aarch64_macho", has_format("macho", "aarch64", "little"));
    check("x64_pe", has_format("pe", "x86_64", "little"));
    check(
        "thumb_elf",
        profiles.iter().any(|entry| {
            entry["arch"] == "thumb"
                && entry["format"] == "elf"
                && entry.pointer("/observed/symbolized/thumb_ranges").and_then(Value::as_u64).is_some_and(|n| n > 0)
        }),
    );
    check("mips32_big_endian_elf", has_format("elf", "mips", "big"));
    check(
        "cpp_virtuals_and_exceptions",
        profiles.iter().any(|entry| {
            entry["source"].as_str().is_some_and(|source| source.ends_with("parity-classes.cpp"))
                && entry["flags"].as_array().is_some_and(|flags| flags.iter().any(|flag| flag == "-fexceptions"))
        }),
    );
    check("go_program", profiles.iter().any(|entry| entry["compiler"] == "go"));
    check("rust_program", profiles.iter().any(|entry| entry["compiler"] == "rustc"));
    check(
        "realistic_open_source_program",
        inventories.iter().any(|inventory| {
            inventory["kind"] == "parity_realistic_lua"
                && inventory["status"] == "available"
                && inventory["stripped_sha256"].as_str().is_some_and(|hash| hashes.contains(hash))
        }),
    );
    for metric in ["function_starts", "library_names", "parameter_counts", "return_classes", "parameter_classes"] {
        check(metric, report["static_metric_status"][metric] == "scored");
    }
    let graph_image = &report["graph_agreement"]["binding"]["rampage"]["image"];
    let graph_bound = workloads.iter().any(|workload| {
        usable_workload(workload)
            && workload["sha256"] == graph_image["image_sha256"]
            && workload["metadata"]["arch"] == graph_image["architecture"]
    });
    check(
        "cfg_and_call_graph_reference",
        graph_bound
            && report.pointer("/graph_agreement/functions/common").and_then(Value::as_u64).is_some_and(|n| n > 0)
            && report.pointer("/graph_agreement/edges/ghidra").and_then(Value::as_u64).is_some_and(|n| n > 0)
            && report.pointer("/graph_agreement/call_graph/ghidra").and_then(Value::as_u64).is_some_and(|n| n > 0),
    );
    check(
        "decompiler_health",
        report.pointer("/decompiler_health/attempted").and_then(Value::as_u64).is_some_and(|n| n > 0),
    );
    check(
        "health_coverage_for_scored_workloads",
        !workloads.is_empty()
            && workloads.iter().filter(|workload| usable_workload(workload)).all(|workload| {
                workload["path"].is_string()
                    && report.pointer("/decompiler_health/targets").and_then(Value::as_array).is_some_and(|targets| {
                        targets.iter().any(|target| {
                            target["target"] == workload["path"] && target["attempted"].as_u64().is_some_and(|n| n > 0)
                        })
                    })
            }),
    );
    let tasks = report.pointer("/agent_tasks/tasks").and_then(Value::as_array).cloned().unwrap_or_default();
    let requested = report.pointer("/agent_tasks/requested_model").and_then(Value::as_str);
    let required = report["required_task_definitions"].as_object();
    let task_ids: BTreeSet<_> = tasks.iter().filter_map(|task| task["task_id"].as_str()).collect();
    let required_set = task_ids.len() == tasks.len()
        && required.is_some_and(|required| {
            required.len() >= 20
                && required.len() == tasks.len()
                && tasks.iter().all(|task| {
                    task["task_id"].as_str().is_some_and(|id| {
                        required
                            .get(id)
                            .is_some_and(|digest| digest.is_string() && digest == &task["definition_sha256"])
                    })
                })
        });
    let all_measured = required_set
        && requested.is_some()
        && tasks.iter().all(|task| {
            task["fixture_status"] == "matches"
                && task["run_kind"] == "mcp_model"
                && task.pointer("/agent_run/model_source") == Some(&json!("provider"))
                && task.pointer("/agent_run/catalog_requests").and_then(Value::as_u64).is_some_and(|n| n > 0)
                && task.pointer("/agent_run/catalog_tool_count").and_then(Value::as_u64).is_some_and(|n| n > 0)
                && task.pointer("/agent_run/turns").and_then(Value::as_array).is_some_and(|turns| {
                    !turns.is_empty()
                        && turns
                            .iter()
                            .all(|turn| turn["error"].is_null() && turn["returned_model"].as_str() == requested)
                })
                && task.pointer("/check/outcome").and_then(Value::as_str).is_some_and(|outcome| outcome != "unmeasured")
        });
    check("complete_fixed_model_mcp_task_run", all_measured);
    check(
        "provider_usage_and_timing",
        all_measured
            && tasks.iter().all(|task| {
                ["input_tokens", "output_tokens", "wall_time_ms", "mcp_tool_calls"]
                    .iter()
                    .all(|field| task[*field].as_u64().is_some())
            }),
    );
    let complete = checks.iter().all(|check| check["met"] == true);
    json!({"complete":complete,"checks":checks,
        "meaning":"Baseline evidence completeness, not parity accuracy or a requirement that every task succeeds.",
        "limits":"Corpus receipts are operator-supplied provenance bound to observed target hashes, \
            not authentication. \
            Optional unscored profiles and absent Ghidra MCP comparison remain explicit limitations."})
}

fn usable_workload(workload: &Value) -> bool {
    workload["nonempty_metric_slices"].as_array().is_some_and(|slices| !slices.is_empty())
        && workload.pointer("/metadata/static_function_symbols").and_then(Value::as_u64) == Some(0)
        && workload.pointer("/metadata/debug_sections").and_then(Value::as_array).is_some_and(Vec::is_empty)
}

fn profile_matches(profile: &Value, workload: &Value) -> bool {
    if !usable_workload(workload) {
        return false;
    }
    let arch = if profile["arch"] == "thumb" { "arm" } else { profile["arch"].as_str().unwrap_or("") };
    profile.pointer("/pair/stripped_sha256").and_then(Value::as_str).is_some()
        && profile["pair"]["stripped_sha256"] == workload["sha256"]
        && profile["format"] == workload["metadata"]["format"]
        && workload["metadata"]["arch"].as_str() == Some(arch)
        && profile["endianness"] == workload["metadata"]["endianness"]
}

fn flatten_inventory<'a>(value: &'a Value, output: &mut Vec<&'a Value>) {
    if let Some(inventories) = value["inventories"].as_array() {
        for inventory in inventories {
            flatten_inventory(inventory, output);
        }
    } else if value.is_object() {
        output.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn absent_or_unmeasured_evidence_never_completes_a_baseline() {
        let report = json!({"phase0_complete":true,"agent_tasks":{"status":"attempted"}});
        let result = assess(&report);
        assert_eq!(result["complete"], false);
        assert!(
            result["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|check| { check["criterion"] == "complete_fixed_model_mcp_task_run" && check["met"] == false })
        );
    }

    fn simulated_report() -> Value {
        let definitions = [
            ("gcc", "-O0", "x86_64", "elf", "little", "types.c"),
            ("gcc", "-O2", "x86_64", "elf", "little", "types.c"),
            ("clang", "-O2", "x86_64", "elf", "little", "types.c"),
            ("zig", "-O2", "aarch64", "elf", "little", "types.c"),
            ("zig", "-O2", "x86_64", "pe", "little", "core.c"),
            ("zig", "-O2", "thumb", "elf", "little", "core.c"),
            ("zig", "-O2", "mips", "elf", "big", "core.c"),
            ("clang++", "-fexceptions", "aarch64", "macho", "little", "parity-classes.cpp"),
            ("go", "", "x86_64", "elf", "little", "program.go"),
            ("rustc", "", "aarch64", "macho", "little", "program.rs"),
        ];
        let mut profiles = Vec::new();
        let mut workloads = Vec::new();
        for (index, (compiler, flag, arch, format, endian, source)) in definitions.into_iter().enumerate() {
            let hash = format!("{index:064x}");
            profiles.push(json!({"status":"available","compiler":compiler,"flags":[flag],"arch":arch,
                "format":format,"endianness":endian,"source":source,"pair":{"stripped_sha256":hash},
                "observed":{"symbolized":{"thumb_ranges":1}}}));
            workloads.push(json!({"path":format!("/synthetic/{index}"),"sha256":hash,
                "nonempty_metric_slices":["synthetic"],
                "metadata":{"format":format,"arch":if arch=="thumb" {"arm"} else {arch},"endianness":endian,
                "static_function_symbols":0,"debug_sections":[]}}));
        }
        let tasks: Vec<_> = (0..20)
            .map(|index| {
                json!({
                    "task_id":format!("task-{index}"),"definition_sha256":format!("{index:064x}"),
                    "fixture_status":"matches","run_kind":"mcp_model",
                    "agent_run":{"model_source":"provider","catalog_requests":1,"catalog_tool_count":1,
                        "turns":[{"error":null,"returned_model":"test/fixed"}]},
                    "check":{"outcome":if index==0 {"answer_mismatch"} else {"answer_matches"}},
                    "input_tokens":100,"output_tokens":10,"mcp_tool_calls":1,"wall_time_ms":20
                })
            })
            .collect();
        let required: BTreeMap<_, _> =
            (0..20).map(|index| (format!("task-{index}"), format!("{index:064x}"))).collect();
        let health: Vec<_> =
            (0..definitions.len()).map(|index| json!({"target":format!("/synthetic/{index}"),"attempted":1})).collect();
        json!({"workloads":workloads,"corpus_inventory":{"inventories":[{"entries":profiles},
            {"kind":"parity_realistic_lua","status":"available","stripped_sha256":format!("{:064x}",3)}]},
            "static_metric_status":{"function_starts":"scored","library_names":"scored",
                "parameter_counts":"scored","return_classes":"scored","parameter_classes":"scored"},
            "required_task_definitions":required,
            "graph_agreement":{"binding":{"rampage":{"image":{"image_sha256":format!("{:064x}",3),
                "architecture":"aarch64"}}},"functions":{"common":1},"edges":{"ghidra":1},"call_graph":{"ghidra":1}},
            "decompiler_health":{"attempted":10,"targets":health},
            "agent_tasks":{"requested_model":"test/fixed","tasks":tasks}})
    }

    #[test]
    fn recorded_wrong_answers_are_baseline_results_not_incomplete_measurements() {
        assert_eq!(assess(&simulated_report())["complete"], true);
    }

    #[test]
    fn missing_metering_wrong_models_or_unbound_corpus_receipts_keep_the_gate_open() {
        for pointer in [
            "/agent_tasks/tasks/0/input_tokens",
            "/agent_tasks/tasks/0/agent_run/turns/0/returned_model",
            "/corpus_inventory/inventories/0/entries/0/pair/stripped_sha256",
            "/workloads/0/nonempty_metric_slices",
            "/agent_tasks/tasks/0/definition_sha256",
            "/agent_tasks/tasks/0/agent_run/catalog_tool_count",
            "/graph_agreement/binding/rampage/image/image_sha256",
            "/workloads/0/metadata/arch",
            "/workloads/0/metadata/static_function_symbols",
        ] {
            let mut report = simulated_report();
            *report.pointer_mut(pointer).unwrap() = Value::Null;
            assert_eq!(assess(&report)["complete"], false, "{pointer}");
        }
    }

    #[test]
    fn arm_macho_cannot_substitute_for_required_thumb_elf() {
        let mut report = simulated_report();
        report["workloads"][5]["metadata"]["format"] = json!("macho");
        report["corpus_inventory"]["inventories"][0]["entries"][5]["format"] = json!("macho");
        let assessment = assess(&report);
        assert_eq!(assessment["complete"], false);
        assert!(
            assessment["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|check| { check["criterion"] == "thumb_elf" && check["met"] == false })
        );
    }
}
