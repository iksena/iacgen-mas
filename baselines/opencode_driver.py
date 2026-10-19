from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from benchmark_common import _safe_int

if TYPE_CHECKING:
    from baselines.evaluation import ScenarioConfig
    from baselines.opencode_baseline import BaselineConfig

REPO_ROOT = Path(__file__).resolve().parent.parent

AGENT_NAME = "iacgod"
MCP_SERVER_NAME = "iacgod"

_PATH_KEYS = ("filePath", "file_path", "path", "notebook_path")
_PATTERN_TOOLS = ("glob",)
_OWN_TOOL_PREFIX = f"{MCP_SERVER_NAME}_"


def _empty_tokens() -> dict[str, int]:
    return {
        "input_tokens": 0,
        "output_tokens": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "all_tokens": 0,
    }


def _events(stdout: str) -> list[dict[str, Any]]:
    events = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return events


def config_path_for(state_dir: Path) -> Path:
    return (state_dir.parent / "opencode.json").resolve()


def _confine_workspace(workdir: Path) -> None:
    workdir = workdir.resolve()
    if not (workdir / ".git").exists():
        result = subprocess.run(
            ["git", "init", "-q"], cwd=workdir, capture_output=True, text=True
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Could not git-init the workspace {workdir}, so it cannot be isolated "
                f"from the repository: {result.stderr.strip()}"
            )
    top = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"], cwd=workdir, capture_output=True, text=True
    )
    if top.returncode != 0 or Path(top.stdout.strip()).resolve() != workdir:
        raise RuntimeError(
            f"Workspace {workdir} is not its own git root (got {top.stdout.strip()!r}); "
            "refusing to run opencode with the enclosing repository inside its project."
        )


def _is_inside(path: str, workspace: str) -> bool:
    full = path if os.path.isabs(path) else os.path.join(workspace, path)
    resolved = os.path.realpath(full)
    root = os.path.realpath(workspace)
    return resolved == root or resolved.startswith(root + os.sep)


def _tool_paths(tool: str, inp: dict[str, Any]) -> list[str]:
    out = [inp[k] for k in _PATH_KEYS if isinstance(inp.get(k), str) and inp[k]]
    pattern = inp.get("pattern")
    if tool.lower() in _PATTERN_TOOLS and isinstance(pattern, str) and pattern.startswith("/"):
        out.append(pattern)
    return out


def workspace_escapes(stdout: str, workdir: Path) -> list[str]:
    workspace = str(workdir.resolve())
    found = []
    for event in _events(stdout):
        if event.get("type") != "tool_use":
            continue
        part = event.get("part") or {}
        tool = part.get("tool", "")
        state = part.get("state") or {}
        if tool.startswith(_OWN_TOOL_PREFIX) or state.get("status") != "completed":
            continue
        for path in _tool_paths(tool, state.get("input") or {}):
            if not _is_inside(path, workspace):
                found.append(f"{tool}:{path}")
    return found


class OpenCodeDriver:
    name = "opencode"

    def _write_config(
        self,
        *,
        scenario: "ScenarioConfig",
        config: "BaselineConfig",
        system_prompt_path: Path,
        state_dir: Path,
    ) -> None:
        base = config.base_url.rstrip("/")
        base_url = base if base.endswith("/v1") else f"{base}/v1"

        cfg: dict[str, Any] = {
            "$schema": "https://opencode.ai/config.json",
            "mcp": {
                MCP_SERVER_NAME: {
                    "type": "local",
                    "command": [sys.executable, str(REPO_ROOT / "baselines" / "mcp_server.py")],
                    "environment": {**scenario.to_env(), "PYTHONPATH": str(REPO_ROOT)},
                    "timeout": config.scenario_timeout * 1000,
                }
            },
            "agent": {
                AGENT_NAME: {
                    "description": "IaCGOD harness-baseline scenario agent",
                    "mode": "primary",
                    "prompt": f"{{file:{system_prompt_path}}}",
                    "permission": {
                        "*": "deny",
                        "read": "allow",
                        "write": "allow",
                        "edit": "allow",
                        "glob": "deny",
                        "grep": "deny",
                        "list": "deny",
                        "external_directory": {"*": "deny"},
                        f"{MCP_SERVER_NAME}_validate_iac": "allow",
                        f"{MCP_SERVER_NAME}_deploy_iac": "allow",
                        f"{MCP_SERVER_NAME}_submit_template": "allow",
                    },
                }
            },
            "small_model": f"{config.provider_name}/{config.model}",
            "provider": {
                config.provider_name: {
                    "npm": "@ai-sdk/openai-compatible",
                    "name": config.provider_name,
                    "options": {
                        "baseURL": base_url,
                        "apiKey": f"{{env:{config.api_key_env}}}",
                    },
                    "models": {config.model: {"name": config.model}},
                }
            },
        }
        config_path_for(state_dir).write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    def build_command(
        self,
        *,
        config: "BaselineConfig",
        scenario: "ScenarioConfig",
        prompt: str,
        workdir: Path,
        system_prompt: str,
        state_dir: Path,
    ) -> list[str]:
        _confine_workspace(workdir)
        system_prompt_path = (state_dir.parent / "SYSTEM_PROMPT.md").resolve()
        system_prompt_path.write_text(system_prompt, encoding="utf-8")
        self._write_config(
            scenario=scenario,
            config=config,
            system_prompt_path=system_prompt_path,
            state_dir=state_dir,
        )
        return [
            "opencode",
            "run",
            prompt,
            "--model",
            f"{config.provider_name}/{config.model}",
            "--agent",
            AGENT_NAME,
            "--format",
            "json",
            "--auto",
        ]

    def build_env(self, config: "BaselineConfig", state_dir: Path) -> dict[str, str]:
        data_dir = state_dir / "data"
        config_dir = state_dir / "config"
        xdg_state = state_dir / "state"
        for d in (data_dir, config_dir, xdg_state):
            d.mkdir(parents=True, exist_ok=True)

        if not os.environ.get(config.api_key_env):
            raise RuntimeError(f"{config.api_key_env} is not set. Export it or add it to .env.")

        env = dict(os.environ)
        env.update(
            {
                "XDG_DATA_HOME": str(data_dir),
                "XDG_CONFIG_HOME": str(config_dir),
                "XDG_STATE_HOME": str(xdg_state),
                "OPENCODE_CONFIG": str(config_path_for(state_dir)),
            }
        )
        return env

    def parse_stream(
        self, stdout: str, *, returncode: int, timed_out: bool, duration: float
    ) -> dict[str, Any]:
        llm_calls: list[dict[str, Any]] = []
        thinking_tokens_total = 0
        total_input = total_output = 0
        any_real_content = False
        last_reason: str | None = None
        seen_error = False

        for event in _events(stdout):
            etype = event.get("type")
            part = event.get("part") or {}

            if etype == "text" and (part.get("text") or "").strip():
                any_real_content = True
            elif etype == "tool_use":
                state = part.get("state") or {}
                if state.get("status") == "completed":
                    any_real_content = True
                elif state.get("status") == "error":
                    seen_error = True
            elif etype == "step_finish":
                tokens = part.get("tokens") or {}
                last_reason = part.get("reason")
                total_input += _safe_int(tokens.get("input"))
                total_output += _safe_int(tokens.get("output"))
                thinking_tokens_total += _safe_int(tokens.get("reasoning"))
                cache = tokens.get("cache") or {}
                llm_calls.append(
                    {
                        "agent": "harness",
                        "iteration": None,
                        "model": None,
                        "message_id": part.get("messageID") or f"anon-{len(llm_calls)}",
                        "prompt": "",
                        "response": "",
                        "timestamp": datetime.now().isoformat(),
                        "token_usage": {
                            "input_tokens": _safe_int(tokens.get("input")),
                            "output_tokens": _safe_int(tokens.get("output")),
                            "cache_read_input_tokens": _safe_int(cache.get("read")),
                            "cache_creation_input_tokens": _safe_int(cache.get("write")),
                        },
                    }
                )
            elif isinstance(etype, str) and "error" in etype.lower():
                seen_error = True

        token_usage = _empty_tokens()
        token_usage["input_tokens"] = total_input
        token_usage["output_tokens"] = total_output
        token_usage["all_tokens"] = total_input + total_output

        return {
            "llm_call_log": llm_calls,
            "token_usage": token_usage,
            "token_usage_source": "per_call",
            "num_turns": len(llm_calls),
            "thinking_tokens_total": thinking_tokens_total,
            "is_error": (returncode != 0) or (seen_error and not any_real_content),
            "stalled": len(llm_calls) > 0 and not any_real_content,
            "stop_reason": last_reason,
            "subtype": "success" if returncode == 0 else "error",
            "returncode": returncode,
            "timed_out": timed_out,
            "duration_seconds": duration,
        }

    def write_debug_transcripts(
        self,
        stdout: str,
        *,
        run_id: str,
        system_prompt: str,
        user_prompt: str,
        model: str,
        state_dir: Path,
        debug_log_path: Path,
        transcript_path: Path,
        tool_calls_path: Path,
    ) -> None:
        rule = "=" * 78
        transcript_lines: list[str] = [
            f"{rule}\nHarness Transcript\nRun ID        : {run_id}\n"
            f"Model         : {model}\n{rule}\n\n"
            f"[SYSTEM PROMPT]\n{system_prompt.strip()}\n\n"
            f"[USER] (initial prompt)\n{user_prompt.strip()}\n\n"
        ]
        tool_call_lines: list[str] = [f"{rule}\nTool Calls - Run {run_id}\n{rule}\n\n"]
        tool_call_index = 0
        last_result_text = ""

        for event in _events(stdout):
            etype = event.get("type")
            part = event.get("part") or {}

            if etype == "text":
                text = (part.get("text") or "").strip()
                if text:
                    transcript_lines.append(f"[ASSISTANT - text]\n{text}\n\n")
                    last_result_text = text
            elif etype == "tool_use":
                tool_call_index += 1
                name = part.get("tool", "?")
                state = part.get("state") or {}
                args = [f"    {k}: {v}" for k, v in (state.get("input") or {}).items()]
                entry = (
                    f"[ASSISTANT - tool_use #{tool_call_index}: {name}]\n"
                    + ("\n".join(args) + "\n" if args else "  (no arguments)\n")
                    + "\n"
                )
                transcript_lines.append(entry)
                tool_call_lines.append(entry)

                result_text = state.get("error") or state.get("output") or ""
                if result_text:
                    result_entry = f"[TOOL RESULT]\n{str(result_text).strip()}\n\n"
                    transcript_lines.append(result_entry)
                    tool_call_lines.append(result_entry)
            elif etype == "step_finish":
                transcript_lines.append(
                    f"  [step finished: reason={part.get('reason')} "
                    f"tokens={part.get('tokens') or {}} cost={part.get('cost')}]\n\n"
                )

        final_summary = f"{rule}\nSession Result\n  final text  : {last_result_text!r}\n{rule}\n"
        transcript_lines.append(final_summary)
        tool_call_lines.append(f"\n{final_summary}")
        if tool_call_index == 0:
            tool_call_lines.insert(1, "(no tool calls were made in this session)\n\n")

        transcript_path.write_text("".join(transcript_lines), encoding="utf-8")
        tool_calls_path.write_text("".join(tool_call_lines), encoding="utf-8")

        source_log = state_dir / "data" / "opencode" / "log" / "opencode.log"
        if source_log.exists():
            debug_log_path.write_text(
                source_log.read_text(encoding="utf-8", errors="replace"), encoding="utf-8"
            )
