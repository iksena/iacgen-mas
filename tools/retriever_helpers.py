from __future__ import annotations

import json
import re

_CFN_DEPLOY_ERROR_KEYWORDS = (
    "FAILED",
    "ERROR",
    "timed out",
    "does not exist",
    "InvalidAMI",
)

_TF_CONTEXT_LINES = 5

_TF_TAIL_LINES = 5


def get_latest_stage_result(validation_results: list[dict], stage: str) -> dict | None:
    for result in reversed(validation_results):
        if result.get("stage") == stage:
            return result
    return None


def format_cfn_lint_errors(errors: list[str]) -> str:
    return "\n".join(f"  - {e.strip()}" for e in errors)


def format_tflint_errors(tflint_errors: list[str], tf_validate_errors: list[str]) -> str:
    parts: list[str] = []

    if tflint_errors:
        parts.append("**tflint (HCL lint):**")
        parts.extend(f"  - {e.strip()}" for e in tflint_errors)

    if tf_validate_errors:
        parts.append("**terraform-validate (provider schema):**")
        parts.extend(f"  - {e.strip()}" for e in tf_validate_errors)

    return "\n".join(parts) if parts else "No Terraform structural errors."


def _extract_tf_error_context(deploy_logs: list[str]) -> list[str]:
    if not deploy_logs:
        return []

    error_line_re = re.compile(r'^(\u2502\s*)?Error:', re.IGNORECASE)
    error_indices: list[int] = [
        i for i, line in enumerate(deploy_logs)
        if error_line_re.match(line.strip())
    ]

    result_lines: list[str] = []
    covered: set[int] = set()

    if error_indices:
        result_lines.append("**Terraform error context (±5 lines per error block):**")
        for idx in error_indices:
            lo = max(0, idx - _TF_CONTEXT_LINES)
            hi = min(len(deploy_logs), idx + _TF_CONTEXT_LINES + 1)
            window = range(lo, hi)
            if covered and lo > max(covered) + 1:
                result_lines.append("  ---")
            for line_idx in window:
                if line_idx not in covered:
                    result_lines.append(f"  {deploy_logs[line_idx]}")
                    covered.add(line_idx)

    tail = deploy_logs[-_TF_TAIL_LINES:]
    tail_start = len(deploy_logs) - len(tail)
    uncovered_tail = [
        line for i, line in enumerate(tail, start=tail_start)
        if i not in covered
    ]
    if uncovered_tail:
        if result_lines:
            result_lines.append("  ---")
        result_lines.append(f"**Last {_TF_TAIL_LINES} log lines:**")
        result_lines.extend(f"  {line}" for line in uncovered_tail)

    return result_lines


def format_deploy_errors(deploy_result: dict) -> str:
    target = deploy_result.get("target", "unknown").upper()
    lines: list[str] = [f"**Target:** {target}"]

    failed = deploy_result.get("failed_resources", [])
    if failed:
        lines.append("**Failed resources:**")
        for fr in failed:
            name   = fr.get("logical_name") or "unknown"
            reason = fr.get("status_reason") or "no reason provided"
            lines.append(f"  - `{name}`: {reason}")
    elif deploy_result.get("error_message"):
        lines.append(f"**Error:** {deploy_result['error_message']}")

    completed = deploy_result.get("completed_resources", [])
    if completed:
        lines.append(
            "**Completed successfully:** "
            + ", ".join(f"`{r}`" for r in completed)
        )

    deploy_logs = deploy_result.get("deployment_logs", [])

    explicit_iac_type: str = deploy_result.get("iac_type", "")
    if explicit_iac_type == "terraform":
        is_terraform = True
    elif explicit_iac_type == "cloudformation":
        is_terraform = False
    else:
        is_terraform = any(
            "." in (fr.get("logical_name") or "")
            and "::" not in (fr.get("logical_name") or "")
            for fr in failed
        )

    if is_terraform:
        tf_log_lines = _extract_tf_error_context(deploy_logs)
        lines.extend(tf_log_lines)
    else:
        actionable = [
            log_line for log_line in deploy_logs
            if any(kw in str(log_line) for kw in _CFN_DEPLOY_ERROR_KEYWORDS)
        ]
        if actionable:
            lines.append("**Deployment event log (errors only):**")
            for log_line in actionable:
                lines.append(f"  - {log_line}")
        elif not failed and deploy_logs:
            lines.append("**Last deployment events:**")
            for log_line in deploy_logs[-5:]:
                lines.append(f"  - {log_line}")

    if len(lines) == 1:
        lines.append("Deployment failed with no structured error details.")

    return "\n".join(lines)


def extract_errors(
    validation_results: list[dict],
    deploy_validation_result: dict | None,
) -> list[str]:
    errors: list[str] = []

    for result in validation_results:
        stage = str(result.get("stage") or "").strip().lower()
        if not result.get("passed"):
            for err in result.get("errors", []):
                if str(err).strip():
                    errors.append(str(err))

    if (
        deploy_validation_result
        and not deploy_validation_result.get("passed")
        and deploy_validation_result.get("target") != "skipped"
    ):
        errors.append(format_deploy_errors(deploy_validation_result))

    return errors


def parse_query_response(raw: str, max_queries: int = 8) -> dict[str, list[str]]:
    cleaned = re.sub(r"```(?:json)?\s*", "", raw).strip().removesuffix("```").strip()

    try:
        parsed = json.loads(cleaned)
    except json.JSONDecodeError as e:
        print(f"[RAG Tool] Query parse error (JSONDecodeError): {e}. Raw: {cleaned[:200]}")
        return {"schema_queries": [], "security_queries": []}

    schema_queries = []
    security_queries = []

    if isinstance(parsed, dict):
        schema_queries = parsed.get("schema_queries", [])
        security_queries = parsed.get("security_queries", [])
        if not schema_queries and not security_queries:
             queries = parsed.get("queries") or parsed.get("query") or []
             schema_queries = queries
    elif isinstance(parsed, list):
        schema_queries = parsed
    else:
        print(f"[RAG Tool] Unexpected query response type: {type(parsed)}")
        return {"schema_queries": [], "security_queries": []}

    if not isinstance(schema_queries, list):
        schema_queries = []
    if not isinstance(security_queries, list):
        security_queries = []

    schema_result = [str(q).strip() for q in schema_queries if str(q).strip()][:max_queries]
    security_result = [str(q).strip() for q in security_queries if str(q).strip()][:max_queries]

    print(f"[RAG Tool] Parsed {len(schema_result)} schema queries and {len(security_result)} security queries from LLM response.")
    return {"schema_queries": schema_result, "security_queries": security_result}
