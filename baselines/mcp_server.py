from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path
from typing import Any

_PROTOCOL_OUT = sys.stdout
sys.stdout = sys.stderr

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from baselines.evaluation import ScenarioConfig, ScenarioLedger, template_filename

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "iacgod-eval", "version": "1.0.0"}


def _tool_definitions(iac_type: str) -> list[dict[str, Any]]:
    fname = template_filename(iac_type)
    lang = "Terraform HCL" if iac_type == "terraform" else "CloudFormation YAML"
    path_schema = {
        "type": "object",
        "properties": {
            "file_path": {
                "type": "string",
                "description": f"Absolute path to the {fname} file.",
            }
        },
        "required": ["file_path"],
    }
    return [
        {
            "name": "validate_iac",
            "description": (
                f"Run static validation on a {lang} file and return every error found. "
                "Each call counts as one iteration against this scenario's budget. "
                "Call this after every edit until it reports PASSED."
            ),
            "inputSchema": path_schema,
        },
        {
            "name": "deploy_iac",
            "description": (
                "Deploy the template to verify it actually provisions. Only available "
                "once validate_iac has passed for the template's current contents; "
                "does not count as an extra iteration."
            ),
            "inputSchema": path_schema,
        },
        {
            "name": "submit_template",
            "description": (
                "Submit the final template and end work on this scenario. Call this "
                "once validation and deployment pass, or immediately if told the "
                "iteration cap has been reached."
            ),
            "inputSchema": path_schema,
        },
    ]


def _send(payload: dict[str, Any]) -> None:
    _PROTOCOL_OUT.write(json.dumps(payload) + "\n")
    _PROTOCOL_OUT.flush()


def _result(rid: Any, result: dict[str, Any]) -> None:
    _send({"jsonrpc": "2.0", "id": rid, "result": result})


def _error(rid: Any, code: int, message: str) -> None:
    _send({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": message}})


def _text_result(text: str, is_error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


_PATH_ARG_NAMES = ("file_path", "filePath", "filepath", "path", "file")


def _path_arg(args: dict[str, Any]) -> str | None:
    for key in _PATH_ARG_NAMES:
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _dispatch_tool(ledger: ScenarioLedger, name: str, args: dict[str, Any]) -> dict[str, Any]:
    file_path = _path_arg(args)
    if not file_path:
        example = ledger.config.workdir / template_filename(ledger.config.iac_type)
        return _text_result(
            f"No file path found in the arguments you sent (keys received: {sorted(args)}). "
            f'Call this tool again with the path as `file_path`, for example '
            f'{{"file_path": "{example}"}}.',
            is_error=True,
        )

    if name == "validate_iac":
        outcome = ledger.validate(file_path)
    elif name == "deploy_iac":
        outcome = ledger.deploy(file_path)
    elif name == "submit_template":
        outcome = ledger.submit(file_path)
    else:
        return _text_result(f"Unknown tool: {name}", is_error=True)

    return _text_result(outcome.text, is_error=False)


def main() -> int:
    try:
        config = ScenarioConfig.from_env()
    except Exception as exc:
        print(f"[mcp_server] fatal: {exc}", file=sys.stderr)
        return 1

    ledger: ScenarioLedger | None = None
    tools = _tool_definitions(config.iac_type)

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = request.get("method")
        rid = request.get("id")
        is_notification = rid is None

        try:
            if method == "initialize":
                requested = (request.get("params") or {}).get("protocolVersion")
                _result(
                    rid,
                    {
                        "protocolVersion": requested or PROTOCOL_VERSION,
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": SERVER_INFO,
                    },
                )
            elif method == "notifications/initialized":
                if ledger is None:
                    ledger = ScenarioLedger(config=config)
            elif method == "ping":
                _result(rid, {})
            elif method == "tools/list":
                _result(rid, {"tools": tools})
            elif method == "tools/call":
                if ledger is None:
                    ledger = ScenarioLedger(config=config)
                params = request.get("params") or {}
                _result(
                    rid,
                    _dispatch_tool(
                        ledger,
                        params.get("name", ""),
                        params.get("arguments") or {},
                    ),
                )
            elif is_notification:
                continue
            else:
                _error(rid, -32601, f"Method not found: {method}")
        except Exception as exc:
            print(
                f"[mcp_server] error handling {method}: {exc}\n{traceback.format_exc()}",
                file=sys.stderr,
            )
            if not is_notification:
                _error(rid, -32603, f"Internal error: {exc}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
