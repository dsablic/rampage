"""Run one benchmark task through `claude -p` against exactly one MCP server and normalize the result.

This is the swap point between the benchmark harness and an agent CLI. The harness never sees Claude Code's
stream format: it reads the normalized result JSON this script writes, and a runner for another agent CLI only
has to emit the same JSON. The script decides nothing about scoring.

Isolation: built-in tools are removed and denied except ToolSearch, which Claude Code uses to load deferred MCP
tool schemas on demand; only `mcp__<server>__*` tools and ToolSearch are allowed, no setting sources (or `--bare`
when ANTHROPIC_API_KEY is set) are loaded, and the stream's `system`/`init` event is checked. Anything beyond the
one server's tools, ToolSearch and Claude Code's built-in plugins and agents fails the run, as does a non-empty
memory directory or a call outside the server that ran.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any, BinaryIO

RUNNER_NAME = "claude-code"

# Every built-in tool name seen in `claude --help`, the init event of an unrestricted session, or the task spec.
BUILTIN_TOOLS = (
    "Agent",
    "AskUserQuestion",
    "Bash",
    "BashOutput",
    "CronCreate",
    "CronDelete",
    "CronList",
    "DesignSync",
    "Edit",
    "EnterPlanMode",
    "EnterWorktree",
    "ExitPlanMode",
    "ExitWorktree",
    "Glob",
    "Grep",
    "KillShell",
    "LSP",
    "ListAgents",
    "ListMcpResourcesTool",
    "Monitor",
    "MultiEdit",
    "NotebookEdit",
    "PowerShell",
    "PublishPlugin",
    "PushNotification",
    "Read",
    "ReadMcpResourceTool",
    "RemoteTrigger",
    "ReportFindings",
    "ScheduleWakeup",
    "SendMessage",
    "ShareOnboardingGuide",
    "Skill",
    "SlashCommand",
    "Task",
    "TaskOutput",
    "TaskStop",
    "TodoWrite",
    "WebFetch",
    "WebSearch",
    "Workflow",
    "Write",
)

# The only built-in tool a run may use: it loads deferred MCP tool schemas and touches no file or network.
ALLOWED_BUILTINS = ("ToolSearch",)

# Claude Code's built-in plugins as of 2.1.318; any other plugin came from user configuration.
BUILTIN_PLUGINS = frozenset(
    {
        "cc-plugin-agents-md",
        "cc-plugin-plugin-authoring",
        "cc-plugin-privacy",
        "cc-plugin-sec-default",
        "cc-plugin-telemetry",
    }
)

# Claude Code's answer to a call it refused to run: an unknown tool, or one the permission mode denied.
REJECTION = re.compile(
    r"No such tool available|haven't granted it yet|Permission to use \S+ (?:has been|was) denied"
)

# Claude Code's replacements for a tool result too large to show inline.
TRUNCATION = re.compile(r"<persisted-output>|Output too large|exceeds maximum allowed tokens|<truncated-output>")

# Default MAX_MCP_OUTPUT_TOKENS, the same for every server; Claude Code's own default is 25,000.
DEFAULT_MAX_MCP_OUTPUT_TOKENS = 200_000

# Claude Code's own agents. Without the Agent tool none of them can run; anything else came from user config.
BUILTIN_AGENTS = frozenset(
    {"claude", "claude-code-guide", "Explore", "general-purpose", "Plan", "statusline-setup", "web-fetch"}
)

# Environment passed to `claude`. Everything else (CLAUDE_EFFORT, a parent session's CLAUDE_CODE_* and the
# like) would change the child's behavior.
ENVIRONMENT_ALLOWLIST = (
    "ANTHROPIC_API_KEY",
    "HOME",
    "LANG",
    "LC_ALL",
    "LOGNAME",
    "MAX_MCP_OUTPUT_TOKENS",
    "PATH",
    "SHELL",
    "TERM",
    "TMPDIR",
    "USER",
)

MAX_ERROR_TEXT = 2000


class IsolationError(Exception):
    pass


def isolation_mode(environment: dict[str, str]) -> str:
    return "bare" if environment.get("ANTHROPIC_API_KEY") else "setting-sources-none"


def child_environment(environment: dict[str, str], max_mcp_output_tokens: int | None = None) -> dict[str, str]:
    child = {name: environment[name] for name in ENVIRONMENT_ALLOWLIST if name in environment}
    if max_mcp_output_tokens is not None:
        child["MAX_MCP_OUTPUT_TOKENS"] = str(max_mcp_output_tokens)
    return child


def client_project_dir(home: Path, workdir: Path) -> Path:
    """Where Claude Code keeps a session's per-project files (spilled tool results, memory) for this cwd."""
    return home / ".claude" / "projects" / re.sub(r"[^A-Za-z0-9]", "-", str(workdir))


def read_mcp_config(path: Path, server: str) -> dict[str, Any]:
    config = json.loads(path.read_text(encoding="utf-8"))
    servers = config.get("mcpServers") if isinstance(config, dict) else None
    if not isinstance(servers, dict) or list(servers) != [server]:
        raise ValueError(f"{path} must hold exactly one MCP server named {server!r}")
    return config


def claude_command(arguments: argparse.Namespace, system_prompt: str | None, isolation: str) -> list[str]:
    command = [
        arguments.claude_bin,
        "-p",
        "--output-format",
        "stream-json",
        "--verbose",
        "--include-hook-events",
        "--mcp-config",
        str(arguments.mcp_config),
        "--strict-mcp-config",
        "--tools",
        ",".join(ALLOWED_BUILTINS),
        f"--allowedTools=mcp__{arguments.server_name}__*," + ",".join(ALLOWED_BUILTINS),
        "--disallowedTools=" + ",".join(BUILTIN_TOOLS),
        "--permission-mode",
        "dontAsk",
        "--disable-slash-commands",
        "--model",
        arguments.model,
        "--max-turns",
        str(arguments.max_turns),
        "--no-session-persistence",
    ]
    if isolation == "bare":
        command.append("--bare")
    else:
        command += ["--setting-sources", ""]
    if system_prompt is not None:
        command += ["--system-prompt", system_prompt]
    return command


def check_init(event: dict[str, Any], server: str) -> list[str]:
    """Problems with an init event; empty when exactly the one server's tools and nothing user-defined loaded."""
    prefix = f"mcp__{server}__"
    problems = []
    tools = event.get("tools")
    if not isinstance(tools, list) or not tools:
        problems.append("init event lists no tools")
        tools = []
    extra_tools = [tool for tool in tools if not str(tool).startswith(prefix) and tool not in ALLOWED_BUILTINS]
    if not any(str(tool).startswith(prefix) for tool in tools):
        problems.append(f"no {prefix}* tools")
    if extra_tools:
        problems.append(f"tools outside {prefix}*: {extra_tools}")
    servers = event.get("mcp_servers")
    if not isinstance(servers, list) or [entry.get("name") for entry in servers] != [server]:
        problems.append(f"MCP servers are not exactly [{server!r}]: {servers}")
    else:
        status = servers[0].get("status")
        if status != "connected":
            problems.append(f"MCP server {server!r} status is {status!r}, not connected")
    plugins = event.get("plugins") or []
    extra_plugins = [
        plugin
        for plugin in plugins
        if not (
            isinstance(plugin, dict)
            and plugin.get("path") == "builtin"
            and plugin.get("name") in BUILTIN_PLUGINS
            and plugin.get("source") == f"{plugin.get('name')}@builtin"
        )
    ]
    if extra_plugins:
        problems.append(f"non-built-in plugins: {extra_plugins}")
    extra_commands = [command for command in event.get("slash_commands") or [] if not str(command).startswith(prefix)]
    if extra_commands:
        problems.append(f"slash commands outside {prefix}*: {extra_commands}")
    extra_agents = [agent for agent in event.get("agents") or [] if agent not in BUILTIN_AGENTS]
    if extra_agents:
        problems.append(f"non-built-in agents: {extra_agents}")
    if event.get("skills"):
        problems.append(f"skills loaded: {event.get('skills')}")
    if event.get("additional_directories"):
        problems.append(f"additional directories: {event.get('additional_directories')}")
    for kind, directory in (event.get("memory_paths") or {}).items():
        try:
            if Path(directory).is_dir() and any(Path(directory).iterdir()):
                problems.append(f"{kind} memory directory is not empty: {directory}")
        except OSError as error:
            problems.append(f"{kind} memory directory unreadable: {error}")
    return problems


def init_evidence(event: dict[str, Any]) -> dict[str, Any]:
    tools = event.get("tools") or []
    return {
        "tool_count": len(tools),
        "deferred_tool_loading": any(tool in ALLOWED_BUILTINS for tool in tools),
        "mcp_servers": event.get("mcp_servers"),
        "plugins": [plugin.get("source") for plugin in event.get("plugins") or [] if isinstance(plugin, dict)],
        "slash_commands": event.get("slash_commands"),
        "agents": event.get("agents"),
        "skills": event.get("skills"),
        "permission_mode": event.get("permissionMode"),
        "api_key_source": event.get("apiKeySource"),
        "memory_paths": event.get("memory_paths"),
    }


def content_bytes(content: Any) -> int:
    if content is None:
        return 0
    if isinstance(content, str):
        return len(content.encode("utf-8"))
    if isinstance(content, list):
        total = 0
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                total += len(str(block.get("text", "")).encode("utf-8"))
            else:
                total += len(json.dumps(block, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
        return total
    return len(json.dumps(content, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(str(block.get("text", "")) for block in content if isinstance(block, dict))
    return ""


def parse_stream(lines: list[tuple[float, str]], server: str) -> dict[str, Any]:
    """Normalize a recorded stream of (arrival seconds, JSON line) pairs. Pure: no process or clock access."""
    init: dict[str, Any] | None = None
    result: dict[str, Any] | None = None
    usage_by_message: dict[str, dict[str, Any]] = {}
    message_order: list[str] = []
    calls: list[dict[str, Any]] = []
    result_texts: list[str] = []
    first_request_tokens: int | None = None
    call_index: dict[str, int] = {}
    started: dict[str, float] = {}
    last_text = ""
    models: set[str] = set()
    hook_events: list[str] = []
    malformed = 0
    for arrival, line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            malformed += 1
            continue
        if not isinstance(event, dict):
            malformed += 1
            continue
        kind = event.get("type")
        subtype = str(event.get("subtype") or "")
        if kind == "system" and subtype == "init" and init is None:
            init = event
        elif kind == "system" and subtype.startswith("hook"):
            hook_events.append(subtype)
        elif kind == "assistant":
            message = event.get("message") or {}
            identity = str(message.get("id") or f"anonymous-{len(message_order)}")
            if identity not in usage_by_message:
                message_order.append(identity)
            if isinstance(message.get("usage"), dict):
                usage_by_message[identity] = message["usage"]
                if first_request_tokens is None:
                    first = message["usage"]
                    first_request_tokens = sum(
                        int(first.get(key) or 0)
                        for key in ("input_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
                    )
            else:
                usage_by_message.setdefault(identity, {})
            if message.get("model"):
                models.add(str(message["model"]))
            texts = []
            for block in message.get("content") or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text":
                    texts.append(str(block.get("text", "")))
                elif block.get("type") == "tool_use":
                    identifier = str(block.get("id", ""))
                    call_index[identifier] = len(calls)
                    started[identifier] = arrival
                    result_texts.append("")
                    calls.append(
                        {
                            "name": str(block.get("name", "")),
                            "input_bytes": content_bytes(block.get("input", {})),
                            "output_bytes": 0,
                            "is_error": None,
                        }
                    )
            if texts:
                last_text = "".join(texts)
        elif kind == "user":
            message = event.get("message") or {}
            content = message.get("content")
            for block in content if isinstance(content, list) else []:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                identifier = str(block.get("tool_use_id", ""))
                index = call_index.get(identifier)
                if index is None:
                    continue
                calls[index]["output_bytes"] = content_bytes(block.get("content"))
                calls[index]["is_error"] = bool(block.get("is_error", False))
                result_texts[index] = content_text(block.get("content"))
                calls[index]["truncated"] = bool(TRUNCATION.search(result_texts[index][:4096]))
                if identifier in started:
                    calls[index]["duration_ms"] = round((arrival - started[identifier]) * 1000)
        elif kind == "result":
            result = event
    usage = {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0}
    for identity in message_order:
        entry = usage_by_message.get(identity) or {}
        usage["input"] += int(entry.get("input_tokens") or 0)
        usage["output"] += int(entry.get("output_tokens") or 0)
        usage["cache_read"] += int(entry.get("cache_read_input_tokens") or 0)
        usage["cache_write"] += int(entry.get("cache_creation_input_tokens") or 0)
    usage_source = "assistant_messages"
    reported = result.get("usage") if result else None
    if isinstance(reported, dict) and "output_tokens" in reported:
        # Streamed assistant events carry partial output counts; the result event holds the session totals.
        usage = {
            "input": int(reported.get("input_tokens") or 0),
            "output": int(reported.get("output_tokens") or 0),
            "cache_read": int(reported.get("cache_read_input_tokens") or 0),
            "cache_write": int(reported.get("cache_creation_input_tokens") or 0),
        }
        usage_source = "result_event"
    for call in calls:
        if call["is_error"] is None:
            call["is_error"] = True
            call["unanswered"] = True
    answer = last_text
    exit_kind, error = "error", "stream ended without a result event"
    if result is not None:
        if isinstance(result.get("result"), str):
            answer = result["result"]
        subtype = str(result.get("subtype") or "")
        if subtype == "success" and not result.get("is_error"):
            exit_kind, error = "ok", None
        elif subtype == "error_max_turns":
            exit_kind, error = "max_turns", "maximum turns reached"
        else:
            exit_kind = "error"
            error = f"result {subtype or 'unknown'}: {str(result.get('result') or '')[:MAX_ERROR_TEXT]}"
    prefix = f"mcp__{server}__"
    # A call outside the server that Claude Code refused (no such tool, or permission denied) ran nothing: it is
    # a model error inside the run. Any other outside call, successful or failed, reached something else.
    stray: set[str] = set()
    rejected: set[str] = set()
    for call, text in zip(calls, result_texts):
        if call["name"].startswith(prefix) or call["name"] in ALLOWED_BUILTINS:
            continue
        if call["is_error"] and not call.get("unanswered") and REJECTION.search(text):
            call["rejected"] = True
            rejected.add(call["name"])
        else:
            stray.add(call["name"])
    return {
        "init": init,
        "answer": answer,
        "tool_calls": calls,
        "turns": int(result["num_turns"]) if result and isinstance(result.get("num_turns"), int) else len(message_order),
        "usage": usage,
        "usage_source": usage_source,
        "cost_usd": result.get("total_cost_usd") if result else None,
        "exit": exit_kind,
        "error": error,
        "models": sorted(models),
        "hook_events": hook_events,
        "stray_tools": sorted(stray),
        "rejected_outside_calls": sorted(rejected),
        "truncated_results": sum(1 for call in calls if call.get("truncated")),
        "first_request_tokens": first_request_tokens,
        "malformed_lines": malformed,
    }


def normalize(
    parsed: dict[str, Any],
    *,
    server: str,
    requested_model: str,
    isolation: str,
    duration_ms: int,
    timed_out: bool,
    leak: list[str],
    process_error: str | None,
) -> dict[str, Any]:
    init = parsed["init"] or {}
    exit_kind, error = parsed["exit"], parsed["error"]
    problems = list(leak)
    if parsed["init"] is None:
        problems.append("no init event")
    else:
        problems += [problem for problem in check_init(init, server) if problem not in problems]
    if parsed["hook_events"]:
        problems.append(f"hook events ran: {parsed['hook_events']}")
    if parsed["stray_tools"]:
        problems.append(f"calls to tools outside the server: {parsed['stray_tools']}")
    wrong_models = [model for model in parsed["models"] if model != requested_model]
    if init.get("model") not in (None, requested_model):
        wrong_models.append(str(init.get("model")))
    if timed_out:
        exit_kind, error = "timeout", "runner timeout elapsed"
    elif problems:
        exit_kind, error = "error", "isolation: " + "; ".join(problems)
    elif wrong_models:
        exit_kind, error = "error", f"model differs from {requested_model}: {sorted(set(wrong_models))}"
    elif exit_kind == "error" and process_error:
        error = f"{error}; {process_error}"
    return {
        "answer": parsed["answer"],
        "tool_calls": parsed["tool_calls"],
        "turns": parsed["turns"],
        "usage": parsed["usage"],
        "usage_source": parsed["usage_source"],
        "cost_usd": parsed["cost_usd"],
        "duration_ms": duration_ms,
        "exit": exit_kind,
        "error": error,
        "runner": {
            "name": RUNNER_NAME,
            "version": init.get("claude_code_version"),
            "model": init.get("model"),
            "isolation": isolation,
        },
        "isolation_evidence": init_evidence(init) if parsed["init"] is not None else None,
        "rejected_outside_calls": parsed["rejected_outside_calls"],
        "truncated_results": parsed["truncated_results"],
        "first_request_tokens": parsed["first_request_tokens"],
        "server": server,
    }


def open_private(path: Path) -> BinaryIO:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.chmod(path, 0o600)
    return os.fdopen(descriptor, "wb")


def terminate(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    for sig, wait in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            return
        try:
            process.wait(timeout=wait)
            return
        except subprocess.TimeoutExpired:
            continue


def run(arguments: argparse.Namespace) -> dict[str, Any]:
    read_mcp_config(arguments.mcp_config, arguments.server_name)
    if not arguments.workdir.is_dir():
        raise ValueError(f"workdir {arguments.workdir} is not a directory")
    prompt = arguments.prompt_file.read_text(encoding="utf-8")
    system_prompt = arguments.system_file.read_text(encoding="utf-8") if arguments.system_file else None
    environment = child_environment(dict(os.environ), arguments.max_mcp_output_tokens)
    isolation = isolation_mode(environment)
    command = claude_command(arguments, system_prompt, isolation)
    lines: list[tuple[float, str]] = []
    leak: list[str] = []
    started = time.monotonic()
    stderr_path = arguments.transcript.with_suffix(arguments.transcript.suffix + ".stderr")
    with open_private(arguments.transcript) as transcript, open_private(stderr_path) as stderr:
        process = subprocess.Popen(
            command,
            cwd=arguments.workdir,
            env=environment,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            start_new_session=True,
        )
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(prompt.encode("utf-8"))
        process.stdin.close()
        expired = threading.Event()

        def expire() -> None:
            expired.set()
            terminate(process)

        deadline = threading.Timer(arguments.timeout_s, expire)
        deadline.start()
        try:
            for raw in process.stdout:
                arrival = time.monotonic() - started
                transcript.write(raw)
                text = raw.decode("utf-8", errors="replace")
                lines.append((arrival, text))
                if not leak and '"subtype":"init"' in text.replace(" ", ""):
                    try:
                        event = json.loads(text)
                    except json.JSONDecodeError:
                        event = {}
                    if event.get("type") == "system" and event.get("subtype") == "init":
                        leak = check_init(event, arguments.server_name)
                        if leak:
                            terminate(process)
                            break
            process.wait()
        finally:
            deadline.cancel()
            terminate(process)
    timed_out = expired.is_set()
    duration_ms = round((time.monotonic() - started) * 1000)
    process_error = None
    if process.returncode not in (0, None):
        tail = stderr_path.read_text(encoding="utf-8", errors="replace")[-MAX_ERROR_TEXT:].strip()
        process_error = f"claude exited {process.returncode}" + (f": {tail}" if tail else "")
    parsed = parse_stream(lines, arguments.server_name)
    result = normalize(
        parsed,
        server=arguments.server_name,
        requested_model=arguments.model,
        isolation=isolation,
        duration_ms=duration_ms,
        timed_out=timed_out,
        leak=leak,
        process_error=process_error,
    )
    result["client_settings"] = {"MAX_MCP_OUTPUT_TOKENS": environment.get("MAX_MCP_OUTPUT_TOKENS")}
    result["client_project_dir_removed"] = remove_client_project_dir(environment, arguments.workdir)
    return result


def remove_client_project_dir(environment: dict[str, str], workdir: Path) -> bool:
    """Delete the per-project directory Claude Code made for this run's workdir (spilled results, memory)."""
    home = environment.get("HOME")
    if not home:
        return False
    directory = client_project_dir(Path(home), workdir.resolve())
    if not directory.is_dir():
        return False
    shutil.rmtree(directory)
    return True


def renormalize(arguments: argparse.Namespace) -> dict[str, Any]:
    """Recompute a result from its recorded transcript and earlier result, without starting `claude`.

    Arrival times are not in the transcript, so wall time, per-call durations and the timeout verdict come
    from the earlier result.
    """
    previous = json.loads(arguments.out.read_text(encoding="utf-8"))
    lines = [(0.0, line) for line in arguments.transcript.read_text(encoding="utf-8").splitlines()]
    parsed = parse_stream(lines, arguments.server_name)
    old_calls = previous.get("tool_calls") or []
    for index, call in enumerate(parsed["tool_calls"]):
        call.pop("duration_ms", None)
        if index < len(old_calls) and old_calls[index].get("name") == call["name"]:
            if "duration_ms" in old_calls[index]:
                call["duration_ms"] = old_calls[index]["duration_ms"]
    leak = check_init(parsed["init"], arguments.server_name) if parsed["init"] else []
    process_error = None
    old_error = str(previous.get("error") or "")
    if "claude exited" in old_error:
        process_error = old_error[old_error.index("claude exited") :]
    result = normalize(
        parsed,
        server=arguments.server_name,
        requested_model=arguments.model,
        isolation=(previous.get("runner") or {}).get("isolation") or isolation_mode(dict(os.environ)),
        duration_ms=int(previous.get("duration_ms") or 0),
        timed_out=previous.get("exit") == "timeout",
        leak=leak,
        process_error=process_error,
    )
    result["renormalized"] = True
    return result


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    result.add_argument("--mcp-config", type=Path, required=True, help="JSON file holding exactly one server")
    result.add_argument("--server-name", required=True)
    result.add_argument("--prompt-file", type=Path, required=True)
    result.add_argument("--system-file", type=Path, help="replaces Claude Code's default system prompt")
    result.add_argument("--model", required=True)
    result.add_argument("--max-turns", type=int, required=True)
    result.add_argument("--timeout-s", type=float, required=True)
    result.add_argument("--workdir", type=Path, required=True, help="the session's working directory")
    result.add_argument("--out", type=Path, required=True, help="normalized result JSON")
    result.add_argument("--transcript", type=Path, required=True, help="raw stream, written 0600")
    result.add_argument("--claude-bin", default=os.environ.get("CLAUDE_BIN") or shutil.which("claude") or "claude")
    result.add_argument(
        "--max-mcp-output-tokens",
        type=int,
        default=DEFAULT_MAX_MCP_OUTPUT_TOKENS,
        help="MAX_MCP_OUTPUT_TOKENS for the session, the same for every server",
    )
    result.add_argument(
        "--renormalize",
        action="store_true",
        help="recompute --out from --transcript and the existing --out instead of running claude",
    )
    return result


def main() -> int:
    arguments = parser().parse_args()
    try:
        result = renormalize(arguments) if arguments.renormalize else run(arguments)
    except (OSError, ValueError) as error:
        result = {
            "answer": "",
            "tool_calls": [],
            "turns": 0,
            "usage": {"input": 0, "output": 0, "cache_read": 0, "cache_write": 0},
            "cost_usd": None,
            "duration_ms": 0,
            "exit": "error",
            "error": f"runner: {error}",
            "runner": {"name": RUNNER_NAME, "version": None, "model": None, "isolation": None},
            "server": arguments.server_name,
        }
    arguments.out.parent.mkdir(parents=True, exist_ok=True)
    arguments.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return 0 if result["exit"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
