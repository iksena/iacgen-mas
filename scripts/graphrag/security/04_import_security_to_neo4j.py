#!/usr/bin/env python3

import json
import os
import sys
from pathlib import Path

try:
    from neo4j import GraphDatabase
except ImportError:
    print("ERROR: Install neo4j driver: pip install neo4j", file=sys.stderr)
    sys.exit(1)

NEO4J_URI      = os.getenv("NEO4J_URI",      "bolt://localhost:7687")
NEO4J_USER     = os.getenv("NEO4J_USER",     "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

REPO_ROOT   = Path(__file__).resolve().parents[3]
CHECKS_JSON = REPO_ROOT / "data" / "security_checks.json"

CODE_MAX_CHARS = 4000
TEXT_MAX_CHARS = 2000

_LEGACY_INDEXES = [
    "security_check_id",
    "aws_service_name",
    "remediation_id",
    "good_example_id",
]


def create_schema(session) -> None:
    print("Creating indexes and constraints...")

    for index_name in _LEGACY_INDEXES:
        try:
            session.run(f"DROP INDEX {index_name} IF EXISTS")
        except Exception as exc:
            print(f"  WARNING: could not drop legacy index '{index_name}': {exc}")

    constraints = [
        ("SecurityCheck", "check_id"),
        ("AwsService",    "name"),
        ("Impact",        "id"),
        ("Remediation",   "id"),
        ("GoodExample",   "id"),
        ("RegoPolicy",    "id"),
    ]
    for label, prop in constraints:
        session.run(
            f"CREATE CONSTRAINT {label.lower()}_{prop}_unique IF NOT EXISTS "
            f"FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE"
        )

    session.run(
        "CREATE INDEX security_check_severity_service IF NOT EXISTS "
        "FOR (s:SecurityCheck) ON (s.severity, s.service)"
    )
    session.run(
        "CREATE INDEX remediation_framework IF NOT EXISTS "
        "FOR (r:Remediation) ON (r.framework)"
    )
    session.run(
        "CREATE INDEX good_example_framework IF NOT EXISTS "
        "FOR (g:GoodExample) ON (g.framework)"
    )
    print("  Schema ready.")


_IMPORT_CHECK_CYPHER = """
// ── 1. SecurityCheck node ────────────────────────────────────────────
MERGE (sc:SecurityCheck {check_id: $check_id})
SET sc.check_name      = $check_name,
    sc.severity        = $severity,
    sc.short_code      = $short_code,
    sc.description     = $description,
    sc.service         = $service,
    sc.framework       = $framework,
    sc.source_file_url = $source_file_url

// ── 2. AwsService ─────────────────────────────────────────────────
WITH sc
FOREACH (svc IN CASE WHEN $service <> '' THEN [$service] ELSE [] END |
    MERGE (a:AwsService {name: svc})
    MERGE (sc)-[:AFFECTS_SERVICE]->(a)
)

// ── 3. Impact ─────────────────────────────────────────────────────
WITH sc
FOREACH (txt IN CASE WHEN $impact <> '' THEN [$impact] ELSE [] END |
    MERGE (imp:Impact {id: $impact_id})
    SET imp.text = txt
    MERGE (sc)-[:HAS_IMPACT]->(imp)
)

// ── 4. GoodExample (CloudFormation) ─────────────────────────────────
WITH sc
FOREACH (code IN CASE WHEN $cfn_example <> '' THEN [$cfn_example] ELSE [] END |
    MERGE (ge:GoodExample {id: $cfn_example_id})
    SET ge.framework = 'cloudformation',
        ge.code      = code
    MERGE (sc)-[:HAS_GOOD_EXAMPLE]->(ge)
)

// ── 5. GoodExample (Terraform) ──────────────────────────────────────
WITH sc
FOREACH (code IN CASE WHEN $tf_example <> '' THEN [$tf_example] ELSE [] END |
    MERGE (ge:GoodExample {id: $tf_example_id})
    SET ge.framework = 'terraform',
        ge.code      = code
    MERGE (sc)-[:HAS_GOOD_EXAMPLE]->(ge)
)

// ── 6. RegoPolicy ────────────────────────────────────────────────────
WITH sc
FOREACH (code IN CASE WHEN $rego_code <> '' THEN [$rego_code] ELSE [] END |
    MERGE (rp:RegoPolicy {id: $rego_id})
    SET rp.code            = code,
        rp.source_file_url = $source_file_url
    MERGE (sc)-[:ENFORCED_BY]->(rp)
)

RETURN sc.check_id AS check_id
"""

_IMPORT_REMEDIATION_CYPHER = """
MATCH (sc:SecurityCheck {check_id: $check_id})
MERGE (r:Remediation {id: $rem_id})
SET r.framework   = $framework,
    r.instruction = $instruction
MERGE (sc)-[:HAS_REMEDIATION]->(r)
"""

_CROSS_GRAPH_CYPHER = """
MATCH (sc:SecurityCheck {check_id: $check_id})
MATCH (res:Resource)
WHERE res.name STARTS WITH $cfn_prefix
MERGE (sc)-[:APPLIES_TO_RESOURCE]->(res)
"""


def _import_one_check(session, check_id: str, check: dict) -> bool:
    service    = check.get("service", "").strip().lower()
    cfn_prefix = check.get("cfn_resource_prefix", "").strip()

    impact_text  = (check.get("impact",            "") or "").strip()[:TEXT_MAX_CHARS]
    cfn_example  = (check.get("cfn_good_example",  "") or "").strip()[:CODE_MAX_CHARS]
    tf_example   = (check.get("tf_good_example",   "") or "").strip()[:CODE_MAX_CHARS]
    rego_code    = (check.get("source_code",        "") or "").strip()[:CODE_MAX_CHARS]
    source_url   = (check.get("source_file_url",    "") or "").strip()
    description  = (check.get("description",        "") or "").strip()[:TEXT_MAX_CHARS]

    try:
        session.run(
            _IMPORT_CHECK_CYPHER,
            check_id       = check_id,
            check_name     = check.get("check_name", ""),
            severity       = check.get("severity", ""),
            short_code     = check.get("short_code", ""),
            description    = description,
            service        = service,
            framework      = check.get("framework", ""),
            source_file_url= source_url,
            impact         = impact_text,
            impact_id      = f"{check_id}_impact",
            cfn_example    = cfn_example,
            cfn_example_id = f"{check_id}_ex_cfn",
            tf_example     = tf_example,
            tf_example_id  = f"{check_id}_ex_tf",
            rego_code      = rego_code,
            rego_id        = f"{check_id}_rego",
        )

        cfn_remediations = check.get("remediation_cfn", [])
        if isinstance(cfn_remediations, str):
            cfn_remediations = [cfn_remediations] if cfn_remediations.strip() else []
        for j, instruction in enumerate(cfn_remediations):
            instruction = instruction.strip()[:TEXT_MAX_CHARS]
            if not instruction:
                continue
            session.run(
                _IMPORT_REMEDIATION_CYPHER,
                check_id    = check_id,
                rem_id      = f"{check_id}_rem_cfn_{j}",
                framework   = "cloudformation",
                instruction = instruction,
            )

        tf_remediations = check.get("remediation_tf", [])
        if isinstance(tf_remediations, str):
            tf_remediations = [tf_remediations] if tf_remediations.strip() else []
        for j, instruction in enumerate(tf_remediations):
            instruction = instruction.strip()[:TEXT_MAX_CHARS]
            if not instruction:
                continue
            session.run(
                _IMPORT_REMEDIATION_CYPHER,
                check_id    = check_id,
                rem_id      = f"{check_id}_rem_tf_{j}",
                framework   = "terraform",
                instruction = instruction,
            )

        if cfn_prefix:
            result = session.run(
                _CROSS_GRAPH_CYPHER,
                check_id   = check_id,
                cfn_prefix = cfn_prefix,
            )
            result.consume()

        return True

    except Exception as exc:
        print(f"  ERROR importing {check_id}: {exc}", file=sys.stderr)
        return False


def verify_import(session, expected: int) -> None:
    print("\nVerifying import...")
    counts = {}
    for label in ("SecurityCheck", "AwsService", "Impact", "Remediation",
                  "GoodExample", "RegoPolicy"):
        result = session.run(f"MATCH (n:{label}) RETURN count(n) AS c")
        counts[label] = result.single()["c"]

    for label, fw in (("Remediation", "cloudformation"), ("Remediation", "terraform"),
                      ("GoodExample", "cloudformation"), ("GoodExample", "terraform")):
        result = session.run(
            f"MATCH (n:{label} {{framework: $fw}}) RETURN count(n) AS c", fw=fw
        )
        counts[f"{label}[{fw}]"] = result.single()["c"]

    edge_counts = {}
    for rel in ("AFFECTS_SERVICE", "HAS_IMPACT", "HAS_REMEDIATION",
                "HAS_GOOD_EXAMPLE", "ENFORCED_BY", "APPLIES_TO_RESOURCE"):
        result = session.run(f"MATCH ()-[r:{rel}]->() RETURN count(r) AS c")
        edge_counts[rel] = result.single()["c"]

    print("  Node counts:")
    for label, count in counts.items():
        status = "✓" if (label != "SecurityCheck" or count == expected) else "✗"
        print(f"    {status} {label:<35} {count:>6}")

    print("  Edge counts:")
    for rel, count in edge_counts.items():
        indicator = "✓" if count > 0 else "⚠ (0 — may be expected if nodes are missing)"
        print(f"    {indicator} {rel:<30} {count:>6}")

    cross = edge_counts.get("APPLIES_TO_RESOURCE", 0)
    sc    = counts.get("SecurityCheck", 0)
    if sc > 0:
        pct = 100.0 * cross / sc
        print(f"\n  Cross-graph coverage: {cross}/{sc} checks linked to IaC resources ({pct:.1f}%)")
        if pct < 50:
            print(
                "  ⚠  Less than 50% of checks are linked to IaC resources.\n"
                "     Run 01_load_trivy_csv.py and check the service→CFN prefix mapping.\n"
                "     Also ensure 04_import_cfn_to_neo4j.py has been run first."
            )


def main() -> None:
    print(f"Loading security checks from: {CHECKS_JSON}")
    if not CHECKS_JSON.exists():
        print(
            "ERROR: security_checks.json not found. "
            "Run scripts/graphrag/security/01_load_trivy_csv.py first.",
            file=sys.stderr,
        )
        sys.exit(1)

    with CHECKS_JSON.open(encoding="utf-8") as fh:
        checks: dict = json.load(fh)

    total = len(checks)
    print(f"Loaded {total} security checks.")

    print(f"Connecting to Neo4j at {NEO4J_URI} as '{NEO4J_USER}'...")
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    succeeded = failed = 0

    with driver.session() as session:
        create_schema(session)

        print(f"\nImporting {total} checks (one transaction per check)...")
        for i, (check_id, check) in enumerate(checks.items(), 1):
            if i % 50 == 0 or i == total:
                print(f"  [{i}/{total}] ... (ok={succeeded} err={failed})")

            ok = _import_one_check(session, check_id, check)
            if ok:
                succeeded += 1
            else:
                failed += 1

        verify_import(session, total)

    driver.close()

    print(f"\n{'\u2713' if failed == 0 else '\u2717'} Import complete: {succeeded} ok, {failed} errors.")
    if failed:
        print(f"  {failed} checks failed — review ERROR lines above.", file=sys.stderr)
        sys.exit(1)

    print("\nNode labels written:")
    print("  SecurityCheck, AwsService, Impact, Remediation, GoodExample, RegoPolicy")
    print("\nEdge types written:")
    print("  AFFECTS_SERVICE, HAS_IMPACT,")
    print("  HAS_REMEDIATION (framework: cloudformation + terraform),")
    print("  HAS_GOOD_EXAMPLE (framework: cloudformation + terraform),")
    print("  ENFORCED_BY, APPLIES_TO_RESOURCE")
    print("\nNext steps:")
    print("  3. Run scripts/graphrag/security/03_build_security_chromadb.py")
    print("  4. Run scripts/graphrag/security/05_execute_security_g_retrieval.py")


if __name__ == "__main__":
    main()
