from __future__ import annotations

import json
import os
from dataclasses import dataclass


@dataclass
class ToolCall:
    tool: str
    paths: list[str]
    ok: bool
    output: str


_PATH_KEYS = ("filePath", "file_path", "path", "notebook_path")
_PATTERN_TOOLS = ("glob",)
_OWN_TOOL_PREFIXES = ("iacgod_", "mcp__iacgod__")


def _paths(tool: str, inp: dict) -> list[str]:
    out = [inp[k] for k in _PATH_KEYS if isinstance(inp.get(k), str) and inp[k]]
    if tool.lower() in _PATTERN_TOOLS and isinstance(inp.get("pattern"), str) and inp["pattern"].startswith("/"):
        out.append(inp["pattern"])
    return out


def _opencode_calls(events: list[dict]) -> list[ToolCall]:
    calls = []
    for ev in events:
        if ev.get("type") != "tool_use":
            continue
        part = ev.get("part", {})
        tool = part.get("tool", "")
        if tool.startswith(_OWN_TOOL_PREFIXES):
            continue
        state = part.get("state") or {}
        calls.append(ToolCall(
            tool=tool,
            paths=_paths(tool, state.get("input") or {}),
            ok=state.get("status") == "completed",
            output=str(state.get("output") or state.get("error") or ""),
        ))
    return calls


def _claude_calls(events: list[dict]) -> list[ToolCall]:
    pending: dict[str, ToolCall] = {}
    calls: list[ToolCall] = []
    for ev in events:
        message = ev.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if ev.get("type") == "assistant" and block.get("type") == "tool_use":
                tool = block.get("name", "")
                if tool.startswith(_OWN_TOOL_PREFIXES):
                    continue
                call = ToolCall(tool=tool, paths=_paths(tool, block.get("input") or {}), ok=False, output="")
                pending[block.get("id", "")] = call
                calls.append(call)
            elif ev.get("type") == "user" and block.get("type") == "tool_result":
                call = pending.get(block.get("tool_use_id", ""))
                if call is not None:
                    body = block.get("content")
                    call.output = body if isinstance(body, str) else json.dumps(body)
                    call.ok = not block.get("is_error")
    return calls


def tool_calls(stream_text: str, harness: str) -> list[ToolCall]:
    events = []
    for line in stream_text.splitlines():
        line = line.strip()
        if line:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return _claude_calls(events) if harness == "claude_code" else _opencode_calls(events)


def is_inside(path: str, workspace: str) -> bool:
    full = path if os.path.isabs(path) else os.path.join(workspace, path)
    resolved = os.path.realpath(full)
    root = os.path.realpath(workspace)
    return resolved == root or resolved.startswith(root + os.sep)


def workspace_escapes(calls: list[ToolCall], workspace: str) -> list[ToolCall]:
    return [c for c in calls if c.ok and any(not is_inside(p, workspace) for p in c.paths)]


def describe(calls: list[ToolCall], workspace: str) -> list[str]:
    return [
        f"{c.tool}:{p}" for c in calls for p in c.paths if not is_inside(p, workspace)
    ]
