# Owned-corpus publication view: no model answers, reasoning, opaque provider state or absolute paths.
def total($rows; $field): [$rows[] | .[$field]] | if any(. == null) then null else add end;
def target_name: split("/") | .[-2];

.agent_tasks.tasks as $tasks |
{
  schema_version: 1,
  measured_at_utc: (.run_unix_ms / 1000 | strftime("%Y-%m-%dT%H:%M:%SZ")),
  source_report_sha256: $source_sha256,
  evaluator: (.evaluator | {sha256, repository_revision, worktree_dirty}),
  phase0_complete,
  acceptance,
  requested_model: .agent_tasks.requested_model,
  requested_provider: .agent_tasks.requested_provider,
  observed_models: ([$tasks[].returned_models[]?] | unique),
  observed_variants: ([$tasks[].agent_run.turns[].response.text | fromjson? |
    .adapter.returned_variant // empty] | unique),
  required_task_definitions,
  static_evaluation,
  workloads: [.workloads[] | {id: (.path | target_name), sha256, metadata, nonempty_metric_slices}],
  graph_agreement: (.graph_agreement | {
    semantics, reference_is_truth, functions, blocks, edges, chains, chain_edges, calls, call_graph,
    identical_block_functions, disagreeing_functions,
    disagreements: (.disagreements | {total, omitted, publication_details_omitted: (.items | length)}),
    ghidra_computed_calls: (.ghidra_computed_calls | {total, omitted,
      publication_details_omitted: (.items | length)}),
    raw_call_disagreements: (.raw_call_disagreements | {only_rampage, only_ghidra,
      detail_count: .details.total}),
    image_sha256: .binding.rampage.image.image_sha256,
    rampage_export_sha256: .binding.rampage.export_sha256,
    ghidra_export_sha256: .binding.ghidra.export_sha256,
    ghidra_version: .binding.ghidra.version
  }),
  decompiler_health: (.decompiler_health | {status, attempted, limits,
    targets: [.targets[] | {id: (.target | target_name), sample_kind, attempted, returned_exact_entry,
      errors, address_mismatches, with_warnings, diagnostics_unavailable, bad_data, unimplemented,
      timing_boundary, functions}]}),
  agent_tasks: {
    measured_analysis_tasks: .agent_tasks.measured_analysis_tasks,
    analysis_answer_matches: .agent_tasks.analysis_answer_matches,
    provider_tasks_started: .agent_tasks.provider_tasks_started,
    totals: {
      input_tokens: total($tasks; "input_tokens"), output_tokens: total($tasks; "output_tokens"),
      reasoning_tokens: total($tasks; "reasoning_tokens"), mcp_tool_calls: total($tasks; "mcp_tool_calls"),
      tool_errors: ([$tasks[].agent_run.tool_errors] | add),
      model_errors: ([$tasks[].agent_run.model_errors] | add),
      task_wall_time_ms: total($tasks; "wall_time_ms")
    },
    tasks: [$tasks[] | {task_id, kind, fixture_id, expected_sha256, actual_sha256, definition_sha256,
      check: (.check | {task_id, kind, outcome}), returned_models,
      input_tokens, output_tokens, reasoning_tokens, cache_tokens, mcp_tool_calls, wall_time_ms,
      tool_errors: .agent_run.tool_errors, model_errors: .agent_run.model_errors,
      timing_boundary: .agent_run.timing_boundary}]
  },
  unmeasured,
  scorecard_wall_time_ms,
  limits: (.limits + ["Publication view omits detailed disagreements, model answers and transcripts; " +
    "the private source report is hash-bound. Usage totals cover this run, not setup probes."])
}
| .static_evaluation.slices |= with_entries(.value |=
    (.publication_disagreements_omitted = (.disagreements | length) | del(.disagreements)))
