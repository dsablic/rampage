"""Stream-parsing and isolation-check tests for claude-runner.py; they never start `claude`."""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SPECIFICATION = importlib.util.spec_from_file_location("claude_runner", HERE / "claude-runner.py")
assert SPECIFICATION is not None and SPECIFICATION.loader is not None
runner = importlib.util.module_from_spec(SPECIFICATION)
SPECIFICATION.loader.exec_module(runner)

# Recorded from a real `claude -p` run against `rampage mcp`, trimmed and scrubbed (tool outputs replaced).
SAMPLE = HERE / "testdata" / "stream-rampage.jsonl"
MODEL = "claude-sonnet-5-5"


def sample_lines(step: float = 0.5) -> list[tuple[float, str]]:
    return [(index * step, line) for index, line in enumerate(SAMPLE.read_text().splitlines())]


def sample_init() -> dict[str, Any]:
    for _, line in sample_lines():
        event = json.loads(line)
        if event.get("subtype") == "init":
            return event
    raise AssertionError("sample has no init event")


def replace_result(lines: list[tuple[float, str]], **fields: Any) -> list[tuple[float, str]]:
    output = []
    for arrival, line in lines:
        event = json.loads(line)
        if event.get("type") == "result":
            event.update(fields)
            line = json.dumps(event)
        output.append((arrival, line))
    return output


def normalized(parsed: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    arguments = {
        "server": "rampage",
        "requested_model": MODEL,
        "isolation": "setting-sources-none",
        "duration_ms": 1000,
        "timed_out": False,
        "leak": [],
        "process_error": None,
    }
    arguments.update(overrides)
    return runner.normalize(parsed, **arguments)


class ParseStreamTest(unittest.TestCase):
    def test_recorded_stream_normalizes_answer_calls_turns_and_usage(self) -> None:
        parsed = runner.parse_stream(sample_lines(), "rampage")
        result = normalized(parsed)
        self.assertEqual(result["exit"], "ok")
        self.assertIsNone(result["error"])
        self.assertEqual(json.loads(result["answer"]), {"return_value": 22})
        self.assertEqual(
            [call["name"] for call in result["tool_calls"]],
            [
                "mcp__rampage__disassemble",
                "mcp__rampage__list_exports",
                "mcp__rampage__list_functions",
                "mcp__rampage__disassemble",
            ],
        )
        for call in result["tool_calls"]:
            self.assertFalse(call["is_error"])
            self.assertEqual(call["output_bytes"], 100)
            self.assertGreater(call["input_bytes"], 0)
            self.assertGreaterEqual(call["duration_ms"], 0)
        self.assertEqual(result["turns"], 5)
        self.assertEqual(
            result["usage"], {"input": 8, "output": 497, "cache_read": 108920, "cache_write": 37295}
        )
        self.assertEqual(result["usage_source"], "result_event")
        self.assertAlmostEqual(result["cost_usd"], 0.165058)
        self.assertEqual(
            result["runner"],
            {"name": "claude-code", "version": "2.1.318", "model": MODEL, "isolation": "setting-sources-none"},
        )
        self.assertEqual(result["isolation_evidence"]["tool_count"], 4)

    def test_without_a_result_event_usage_is_summed_per_message_and_the_run_fails(self) -> None:
        lines = [(arrival, line) for arrival, line in sample_lines() if '"type":"result"' not in line]
        parsed = runner.parse_stream(lines, "rampage")
        self.assertEqual(parsed["usage_source"], "assistant_messages")
        self.assertGreater(parsed["usage"]["cache_read"], 0)
        self.assertEqual(parsed["exit"], "error")
        self.assertIn("without a result", parsed["error"])
        self.assertEqual(json.loads(parsed["answer"]), {"return_value": 22})

    def test_result_subtypes_map_to_exit_kinds(self) -> None:
        cases = [
            ({"subtype": "error_max_turns", "is_error": True}, "max_turns"),
            ({"subtype": "error_during_execution", "is_error": True}, "error"),
            ({"subtype": "success", "is_error": True}, "error"),
        ]
        for fields, expected in cases:
            parsed = runner.parse_stream(replace_result(sample_lines(), **fields), "rampage")
            self.assertEqual(normalized(parsed)["exit"], expected, fields)
        timed_out = normalized(runner.parse_stream(sample_lines(), "rampage"), timed_out=True)
        self.assertEqual(timed_out["exit"], "timeout")

    def test_unanswered_tool_calls_count_as_errors(self) -> None:
        lines = [(arrival, line) for arrival, line in sample_lines() if '"type":"user"' not in line]
        calls = runner.parse_stream(lines, "rampage")["tool_calls"]
        self.assertTrue(all(call["is_error"] and call["unanswered"] for call in calls))

    def test_malformed_lines_are_counted_not_fatal(self) -> None:
        parsed = runner.parse_stream([(0.0, "not json"), *sample_lines()], "rampage")
        self.assertEqual(parsed["malformed_lines"], 1)
        self.assertEqual(parsed["exit"], "ok")


class IsolationTest(unittest.TestCase):
    def test_recorded_init_is_clean(self) -> None:
        self.assertEqual(runner.check_init(sample_init(), "rampage"), [])

    def test_anything_beyond_the_one_server_and_built_ins_is_a_leak(self) -> None:
        mutations = [
            lambda event: event["tools"].append("Bash"),
            lambda event: event["tools"].append("mcp__other__read"),
            lambda event: event["mcp_servers"].append({"name": "other", "status": "connected"}),
            lambda event: event["mcp_servers"][0].update(status="failed"),
            lambda event: event["plugins"].append({"name": "x", "path": "/home/user/x", "source": "x@market"}),
            lambda event: event["plugins"].append({"name": "x", "path": "builtin", "source": "x@builtin"}),
            lambda event: event["tools"].append("Read"),
            lambda event: event.update(tools=["ToolSearch"]),
            lambda event: event["slash_commands"].append("review"),
            lambda event: event["agents"].append("my-agent"),
            lambda event: event.update(skills=["deploy"]),
            lambda event: event.update(additional_directories=["/home/user"]),
            lambda event: event.update(tools=[]),
        ]
        for mutate in mutations:
            event = copy.deepcopy(sample_init())
            mutate(event)
            self.assertNotEqual(runner.check_init(event, "rampage"), [], event)

    def test_tool_search_is_the_only_allowed_built_in(self) -> None:
        event = sample_init()
        event["tools"].append("ToolSearch")
        self.assertEqual(runner.check_init(event, "rampage"), [])
        self.assertTrue(runner.init_evidence(event)["deferred_tool_loading"])

    def test_a_non_empty_memory_directory_is_a_leak(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            event = sample_init()
            event["memory_paths"] = {"auto": directory}
            self.assertEqual(runner.check_init(event, "rampage"), [])
            (Path(directory) / "MEMORY.md").write_text("remember")
            self.assertIn("memory directory is not empty", runner.check_init(event, "rampage")[0])

    def test_normalize_checks_the_init_event_itself(self) -> None:
        lines = []
        for arrival, line in sample_lines():
            event = json.loads(line)
            if event.get("subtype") == "init":
                event["tools"].append("Bash")
                line = json.dumps(event)
            lines.append((arrival, line))
        result = normalized(runner.parse_stream(lines, "rampage"))
        self.assertEqual(result["exit"], "error")
        self.assertIn("tools outside", result["error"])

    def test_server_prompts_may_appear_as_slash_commands(self) -> None:
        event = sample_init()
        event["slash_commands"] = ["mcp__rampage__triage"]
        self.assertEqual(runner.check_init(event, "rampage"), [])

    def test_hooks_stray_tools_and_other_models_fail_the_run(self) -> None:
        hook = json.dumps({"type": "system", "subtype": "hook_started", "hook_name": "SessionStart"})
        parsed = runner.parse_stream([*sample_lines(), (9.0, hook)], "rampage")
        self.assertIn("hook events", normalized(parsed)["error"])
        stray = runner.parse_stream(sample_lines(), "rea")
        result = normalized(stray, server="rea")
        self.assertEqual(result["exit"], "error")
        self.assertIn("outside the server", result["error"])
        other = normalized(runner.parse_stream(sample_lines(), "rampage"), requested_model="claude-other")
        self.assertIn("model differs", other["error"])
        leaked = normalized(runner.parse_stream(sample_lines(), "rampage"), leak=["tools outside"])
        self.assertTrue(leaked["error"].startswith("isolation: tools outside"))


def with_outside_call(
    lines: list[tuple[float, str]],
    text: str = "<tool_use_error>Error: No such tool available: enable_tools</tool_use_error>",
    name: str = "enable_tools",
) -> list[tuple[float, str]]:
    """Add a model call to a tool outside the server, answered with an error carrying `text`."""
    call = {"type": "assistant", "message": {"model": MODEL, "id": "msg_rejected", "role": "assistant",
            "content": [{"type": "tool_use", "id": "toolu_rejected", "name": name, "input": {}}]}}
    answer = {"type": "user", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "toolu_rejected", "is_error": True,
         "content": text}]}}
    return [lines[0], (0.1, json.dumps(call)), (0.2, json.dumps(answer)), *lines[1:]]


class RejectedCallTest(unittest.TestCase):
    def test_a_rejected_call_to_a_missing_tool_is_a_model_error_not_a_leak(self) -> None:
        parsed = runner.parse_stream(with_outside_call(sample_lines()), "rampage")
        result = normalized(parsed)
        self.assertEqual(result["exit"], "ok")
        self.assertEqual(result["rejected_outside_calls"], ["enable_tools"])
        self.assertEqual(len(result["tool_calls"]), 5)
        self.assertTrue(result["tool_calls"][0]["is_error"])
        self.assertTrue(result["tool_calls"][0]["rejected"])

    def test_an_outside_call_that_ran_and_failed_is_a_leak(self) -> None:
        lines = with_outside_call(sample_lines(), "Exit code 1: cat: no such file", "Bash")
        result = normalized(runner.parse_stream(lines, "rampage"))
        self.assertEqual(result["exit"], "error")
        self.assertIn("outside the server: ['Bash']", result["error"])

    def test_truncated_results_are_counted(self) -> None:
        lines = with_outside_call(
            sample_lines(), "<persisted-output>\nOutput too large (63.7KB). Full output saved to: x", "mcp__rampage__x"
        )
        parsed = runner.parse_stream(lines, "rampage")
        self.assertEqual(parsed["truncated_results"], 1)
        self.assertTrue(parsed["tool_calls"][0]["truncated"])
        self.assertGreater(parsed["first_request_tokens"], 0)

    def test_renormalize_recomputes_from_the_transcript_and_keeps_timings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transcript = root / "transcript.jsonl"
            lines = with_outside_call(sample_lines())
            transcript.write_text("\n".join(line for _, line in lines) + "\n")
            previous = normalized(runner.parse_stream(lines, "rampage"), duration_ms=4321)
            previous["exit"], previous["error"] = "error", "isolation: calls to tools outside the server"
            out = root / "result.json"
            out.write_text(json.dumps(previous))
            arguments = runner.parser().parse_args(
                [
                    "--mcp-config", str(root / "mcp.json"), "--server-name", "rampage", "--prompt-file", "p",
                    "--model", MODEL, "--max-turns", "7", "--timeout-s", "60", "--workdir", directory,
                    "--out", str(out), "--transcript", str(transcript), "--renormalize",
                ]
            )
            result = runner.renormalize(arguments)
            self.assertEqual(result["exit"], "ok")
            self.assertEqual(result["duration_ms"], 4321)
            self.assertTrue(result["renormalized"])
            self.assertEqual(
                [call.get("duration_ms") for call in result["tool_calls"]],
                [call.get("duration_ms") for call in previous["tool_calls"]],
            )


class CommandTest(unittest.TestCase):
    def arguments(self, directory: Path) -> argparse.Namespace:
        return runner.parser().parse_args(
            [
                "--mcp-config", str(directory / "mcp.json"), "--server-name", "rea", "--prompt-file", "p",
                "--model", MODEL, "--max-turns", "7", "--timeout-s", "60", "--workdir", str(directory),
                "--out", "o.json", "--transcript", "t.jsonl", "--claude-bin", "claude",
            ]
        )

    def test_command_allows_only_the_server_and_denies_built_ins(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            arguments = self.arguments(Path(directory))
            command = runner.claude_command(arguments, "system text", "setting-sources-none")
            self.assertIn("--strict-mcp-config", command)
            self.assertIn("--allowedTools=mcp__rea__*,ToolSearch", command)
            denied = next(part for part in command if part.startswith("--disallowedTools="))
            for tool in ("Bash", "Read", "Write", "Edit", "Glob", "Grep", "WebFetch", "WebSearch", "Agent",
                         "Task", "NotebookEdit", "TodoWrite", "Skill"):
                self.assertIn(tool, denied.split("=", 1)[1].split(","))
            self.assertEqual(command[command.index("--tools") + 1], "ToolSearch")
            self.assertNotIn("ToolSearch", denied)
            self.assertEqual(command[command.index("--setting-sources") + 1], "")
            self.assertEqual(command[command.index("--permission-mode") + 1], "dontAsk")
            self.assertEqual(command[command.index("--system-prompt") + 1], "system text")
            self.assertIn("--no-session-persistence", command)
            self.assertNotIn("--bare", command)
            bare = runner.claude_command(arguments, None, "bare")
            self.assertIn("--bare", bare)
            self.assertNotIn("--setting-sources", bare)
            self.assertNotIn("--system-prompt", bare)
            self.assertNotIn("--max-budget-usd", bare)

    def test_a_budget_caps_the_session(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            arguments = self.arguments(Path(directory))
            arguments.max_budget_usd = 0.75
            command = runner.claude_command(arguments, None, "bare")
            self.assertEqual(command[command.index("--max-budget-usd") + 1], "0.7500")

    def test_isolation_mode_and_child_environment(self) -> None:
        self.assertEqual(runner.isolation_mode({"ANTHROPIC_API_KEY": "k"}), "bare")
        self.assertEqual(runner.isolation_mode({}), "setting-sources-none")
        environment = runner.child_environment(
            {"PATH": "/bin", "HOME": "/home/u", "CLAUDE_EFFORT": "max", "CLAUDECODE": "1", "CLAUDE_CODE_X": "y"}
        )
        self.assertEqual(environment, {"PATH": "/bin", "HOME": "/home/u"})
        limited = runner.child_environment({"PATH": "/bin", "MAX_MCP_OUTPUT_TOKENS": "9"}, 200000)
        self.assertEqual(limited["MAX_MCP_OUTPUT_TOKENS"], "200000")
        self.assertEqual(
            runner.client_project_dir(Path("/home/u"), Path("/private/var/tmp/agent-bench-1-0")),
            Path("/home/u/.claude/projects/-private-var-tmp-agent-bench-1-0"),
        )

    def test_mcp_config_must_hold_exactly_the_named_server(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mcp.json"
            path.write_text(json.dumps({"mcpServers": {"rea": {"command": "node"}}}))
            runner.read_mcp_config(path, "rea")
            with self.assertRaises(ValueError):
                runner.read_mcp_config(path, "rampage")
            path.write_text(json.dumps({"mcpServers": {"rea": {}, "other": {}}}))
            with self.assertRaises(ValueError):
                runner.read_mcp_config(path, "rea")


class ReapTest(unittest.TestCase):
    def test_a_grandchild_in_its_own_session_is_found_and_stopped_after_its_parent_exits(self) -> None:
        script = (
            "import subprocess, sys, time\n"
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)\n"
            "time.sleep(1)\n"
        )
        parent = subprocess.Popen([sys.executable, "-c", script])
        time.sleep(0.5)
        found = runner.descendants(parent.pid)
        parent.wait()
        self.assertTrue(found)
        runner.reap(found)
        for pid in found:
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)


if __name__ == "__main__":
    unittest.main()
