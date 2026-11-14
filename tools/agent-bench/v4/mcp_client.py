"""A minimal stdio MCP client for validating suite-v4 truths against a server directly (no model involved)."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any


class McpError(Exception):
    pass


class Client:
    def __init__(self, command: list[str], env: dict[str, str] | None = None, cwd: Path | None = None) -> None:
        environment = dict(os.environ)
        environment.update(env or {})
        self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.DEVNULL, env=environment, cwd=cwd, text=True)
        self.next_id = 0
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "bench-v4-validate", "version": "1"}})
        self.notify("notifications/initialized", {})

    def notify(self, method: str, params: dict[str, Any]) -> None:
        assert self.process.stdin
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method, "params": params}) + "\n")
        self.process.stdin.flush()

    def request(self, method: str, params: dict[str, Any]) -> Any:
        assert self.process.stdin and self.process.stdout
        self.next_id += 1
        identity = self.next_id
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": identity, "method": method,
                                             "params": params}) + "\n")
        self.process.stdin.flush()
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise McpError(f"server closed during {method}")
            message = json.loads(line)
            if message.get("id") != identity:
                continue
            if "error" in message:
                raise McpError(f"{method}: {message['error']}")
            return message["result"]

    def tools(self) -> dict[str, Any]:
        return {tool["name"]: tool for tool in self.request("tools/list", {})["tools"]}

    def call(self, name: str, arguments: dict[str, Any]) -> Any:
        """A tool's structured result (or its text parsed as JSON); raises on a tool error."""
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        text = "".join(block.get("text", "") for block in result.get("content", []) if block.get("type") == "text")
        if result.get("isError"):
            raise McpError(f"{name}: {text[:2000]}")
        if "structuredContent" in result:
            return result["structuredContent"]
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text

    def close(self) -> None:
        if self.process.stdin:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
