from __future__ import annotations

import os
import re
from collections import OrderedDict
from contextlib import contextmanager
from typing import Any

from neo4j import GraphDatabase

NEO4J_URI      = os.getenv("NEO4J_URI",      "bolt://localhost:7687")
NEO4J_USER     = os.getenv("NEO4J_USER",     "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

_SEVERITY_RANK: dict[str, int] = {
    "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4
}

_SECURITY_CHAR_BUDGET: int = int(os.getenv("SECURITY_CHAR_BUDGET", "12000"))

_FRAMEWORK_FILTERS: dict[str, list[str]] = {
    "cloudformation": ["cfn", "cloudformation"],
    "terraform":      ["terraform", "tf"],
}

_AVD_ID_RE  = re.compile(r"\b(?:AVD-)?AWS-\d{4}\b", re.IGNORECASE)
_BRACKET_RE = re.compile(r"\[([A-Z0-9_-]+)\]")
_HTML_CMNT  = re.compile(r"<!--.*?-->", re.DOTALL)


def _clean_html_comments(text: str | None) -> str:
    if not text:
        return ""
    return _HTML_CMNT.sub("", text).strip()


def extract_trivy_check_ids(finding_texts: list[str]) -> list[str]:
    seen: set[str] = set()
    ids: list[str] = []
    for text in finding_texts:
        for match in _BRACKET_RE.findall(text):
            cid = match.strip().upper()
            if re.fullmatch(r"(?:AVD-)?AWS-\d{4}", cid) and cid not in seen:
                seen.add(cid)
                ids.append(cid)
        for match in _AVD_ID_RE.findall(text):
            cid = match.strip().upper()
            if cid not in seen:
                seen.add(cid)
                ids.append(cid)
    return ids


def _id_variants(check_id: str) -> list[str]:
    base = check_id.strip().upper()
    if re.fullmatch(r"AWS-\d{4}", base):
        return [base, f"AVD-{base}"]
    if re.fullmatch(r"AVD-AWS-\d{4}", base):
        return [base, base.removeprefix("AVD-")]
    return [base]


@contextmanager
def _neo4j_driver():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        yield driver
    finally:
        driver.close()


_SECURITY_CYPHER = """
MATCH (s:SecurityCheck {check_id: $check_id})

OPTIONAL MATCH (s)-[:HAS_IMPACT]->(imp:Impact)
OPTIONAL MATCH (s)-[:HAS_REMEDIATION]->(rem:Remediation)
    WHERE rem.framework IN $frameworks
OPTIONAL MATCH (s)-[:HAS_GOOD_EXAMPLE]->(ex:GoodExample)
    WHERE ex.framework  IN $frameworks
OPTIONAL MATCH (s)-[:ENFORCED_BY]->(rp:RegoPolicy)

RETURN s.check_id    AS check_id,
       s.check_name  AS check_name,
       s.severity    AS severity,
       s.description AS description,
       imp.text      AS impact,
       collect(DISTINCT rem.instruction) AS iac_remediations,
       collect(DISTINCT ex.code)         AS iac_examples,
       rp.code                           AS rego_code
"""


def _query_security_check(
    driver,
    check_id: str,
    frameworks: list[str],
) -> dict[str, Any] | None:
    with driver.session() as session:
        for variant in _id_variants(check_id):
            row = session.run(
                _SECURITY_CYPHER,
                check_id=variant,
                frameworks=frameworks,
            ).single()
            if row:
                return {
                    "check_id":         row["check_id"],
                    "check_name":       row["check_name"],
                    "severity":         row["severity"],
                    "description":      row["description"],
                    "impact":           row["impact"],
                    "iac_remediations": [r for r in (row["iac_remediations"] or []) if r],
                    "iac_examples":     [e for e in (row["iac_examples"] or []) if e],
                    "rego_code":        row["rego_code"],
                }
    return None


def _security_graph_lookup(
    check_ids: list[str],
    iac_type: str = "cloudformation",
) -> list[dict[str, Any]]:
    results: list[dict] = []
    if not check_ids:
        return results

    frameworks = _FRAMEWORK_FILTERS.get(iac_type, _FRAMEWORK_FILTERS["cloudformation"])
    print(
        f"[SecurityRAG] Graph lookup: querying Neo4j for {len(check_ids)} check(s) "
        f"(iac_type={iac_type}, frameworks={frameworks})..."
    )
    try:
        with _neo4j_driver() as driver:
            seen: set[str] = set()
            for cid in check_ids:
                norm = cid.strip().upper()
                if norm in seen:
                    continue
                seen.add(norm)
                row = _query_security_check(driver, norm, frameworks)
                if row:
                    results.append(row)
    except Exception as exc:
        print(f"[SecurityRAG] Graph lookup warning: Neo4j unavailable. {exc}")
    print(
        f"[SecurityRAG] Graph lookup: {len(results)}/{len(check_ids)} "
        f"check(s) resolved from Neo4j."
    )
    return results


def _format_one_check(chk: dict[str, Any], iac_type: str = "cloudformation") -> str:
    fw_label = "Terraform" if iac_type == "terraform" else "CloudFormation"
    code_fence = "hcl" if iac_type == "terraform" else "yaml"

    lines: list[str] = []
    severity = (chk.get("severity") or "UNKNOWN").upper()
    name     = chk.get("check_name") or chk.get("check_id", "")
    lines.append(f"### [{chk['check_id']}] {name} (Severity: {severity})")

    desc = (chk.get("description") or "").strip()
    if desc:
        lines.append(f"Description: {desc}")

    impact = _clean_html_comments(chk.get("impact"))
    if impact:
        lines.append(f"Impact: {impact}")

    for rem in chk.get("iac_remediations") or []:
        rem = rem.strip()
        if rem:
            lines.append(f"Remediation ({fw_label}): {rem}")

    for code in chk.get("iac_examples") or []:
        code = code.strip()
        if code:
            lines.append(f"{fw_label} Good Example:\n```{code_fence}\n{code}\n```")
            break

    rego = (chk.get("rego_code") or "").strip()
    if rego:
        lines.append(f"Policy (Rego):\n```rego\n{rego}\n```")

    return "\n".join(lines)


def _assemble_security_context(
    checks: list[dict[str, Any]],
    iac_type: str = "cloudformation",
    char_budget: int = _SECURITY_CHAR_BUDGET,
) -> str:
    if not checks:
        return ""

    sorted_checks = sorted(
        checks,
        key=lambda c: _SEVERITY_RANK.get((c.get("severity") or "UNKNOWN").upper(), 4),
    )

    included_blocks: list[str] = []
    total_chars = 0
    skipped_unknown = 0

    for chk in sorted_checks:
        block = _format_one_check(chk, iac_type)
        severity = (chk.get("severity") or "UNKNOWN").upper()
        if total_chars + len(block) > char_budget:
            if severity == "UNKNOWN":
                skipped_unknown += 1
                continue
            print(
                f"[SecurityRAG] Budget exceeded at {chk['check_id']} "
                f"(severity={severity}). Truncating."
            )
            break
        included_blocks.append(block)
        total_chars += len(block)

    if skipped_unknown:
        print(
            f"[SecurityRAG] Dropped {skipped_unknown} UNKNOWN-severity check(s) "
            f"(char budget). Included {len(included_blocks)}/{len(checks)} check(s)."
        )
    else:
        print(f"[SecurityRAG] Included {len(included_blocks)}/{len(checks)} check(s).")

    return "\n\n".join(included_blocks)


def execute_security_retrieval(
    raw_errors: list[str],
    iac_type: str = "cloudformation",
) -> str:
    check_ids = extract_trivy_check_ids(raw_errors)

    if not check_ids:
        print(
            "[SecurityRAG] No AVD/Trivy IDs found in raw errors. "
            "Returning empty security context."
        )
        return ""

    print(
        f"[SecurityRAG] Extracted {len(check_ids)} unique ID(s) from "
        f"{len(raw_errors)} raw error string(s): {check_ids}"
    )

    checks = _security_graph_lookup(check_ids, iac_type)
    if not checks:
        print(
            f"[SecurityRAG] 0/{len(check_ids)} IDs resolved from Neo4j. "
            "Ensure 04_import_security_to_neo4j.py has been run."
        )
        return ""

    context = _assemble_security_context(checks, iac_type)
    print(f"[SecurityRAG] Context assembled: {len(context)} char(s).")
    return context
