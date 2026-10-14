#!/usr/bin/env python3

import re
from pathlib import Path

import pandas as pd

REPO_ROOT = Path(__file__).resolve().parent.parent
PARQUET_PATH = REPO_ROOT / "iac_benchmark" / "iac_eval_hf" / "data" / "train.parquet"
BENCHMARK_CSV = REPO_ROOT.parent / "data" / "iac_eval_benchmark.csv"
AUDIT_OUT = REPO_ROOT / "iac_benchmark" / "dataset" / "iac_eval_satisfiability_audit.csv"
FILTERED_OUT = REPO_ROOT.parent / "data" / "iac_eval_benchmark_filtered.csv"

LABEL_DEPENDENCY_PATTERN = re.compile(
    r'\.(references\[\d+\]|depends_on\[\d+\]|provider_config_key)\s*==\s*"([^"]+)"'
)

RULE_NAME_PATTERN = re.compile(r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\([^)]*\))?\s*(?:if\s*)?\{', re.MULTILINE)
_SKIP_RULE_NAMES = {"package", "default", "import", "is_configuration_valid"}


def _rule_name_at_offset(rego_text: str, offset: int) -> str | None:
    best_name = None
    best_pos = -1
    for m in RULE_NAME_PATTERN.finditer(rego_text):
        if m.start() <= offset and m.start() > best_pos and m.group(1) not in _SKIP_RULE_NAMES:
            best_pos = m.start()
            best_name = m.group(1)
    return best_name


def classify_row(rego_text: str) -> dict:
    if not rego_text:
        return {"is_label_dependent": False, "n_matches": 0, "matched_literals": "", "matched_rule_names": ""}

    matches = list(LABEL_DEPENDENCY_PATTERN.finditer(rego_text))
    literals = []
    rule_names = []
    for m in matches:
        literals.append(m.group(2))
        rn = _rule_name_at_offset(rego_text, m.start())
        if rn:
            rule_names.append(rn)

    return {
        "is_label_dependent": len(matches) > 0,
        "n_matches": len(matches),
        "matched_literals": ";".join(dict.fromkeys(literals)),
        "matched_rule_names": ";".join(dict.fromkeys(rule_names)),
    }


def main() -> None:
    if not PARQUET_PATH.exists():
        raise SystemExit(f"[ERROR] Benchmark parquet not found: {PARQUET_PATH}")
    if not BENCHMARK_CSV.exists():
        raise SystemExit(f"[ERROR] Benchmark CSV not found: {BENCHMARK_CSV}")

    bench_df = pd.read_parquet(PARQUET_PATH)
    eval_df = pd.read_csv(BENCHMARK_CSV)

    if len(bench_df) != len(eval_df):
        print(f"[WARN] parquet has {len(bench_df)} rows but {BENCHMARK_CSV.name} has "
              f"{len(eval_df)} -- row_number is assumed to equal the parquet's 0-based "
              f"index; verify this still holds before trusting the result.")

    audit_rows = []
    for row_number in eval_df["row_number"]:
        rego_text = bench_df.iloc[int(row_number)]["Rego intent"]
        result = classify_row(rego_text)
        audit_rows.append({"row_number": int(row_number), **result})

    audit_df = pd.DataFrame(audit_rows)
    audit_df = audit_df.merge(eval_df[["row_number", "difficulty"]], on="row_number", how="left")
    audit_df = audit_df[["row_number", "difficulty", "is_label_dependent", "n_matches",
                          "matched_literals", "matched_rule_names"]]
    audit_df.to_csv(AUDIT_OUT, index=False)

    n_excluded = int(audit_df["is_label_dependent"].sum())
    n_total = len(audit_df)
    print(f"[INFO] {n_excluded}/{n_total} rows ({100*n_excluded/n_total:.1f}%) are label-dependent "
          f"(structurally unsatisfiable regardless of correctness) -- excluded from the filtered benchmark.")
    print(f"[INFO] Full audit trail written to {AUDIT_OUT}")

    by_diff = audit_df.groupby("difficulty")["is_label_dependent"].agg(["sum", "count"])
    print("\n[INFO] Excluded rows by difficulty level:")
    for diff, r in by_diff.iterrows():
        print(f"    L{int(diff)}: {int(r['sum'])}/{int(r['count'])} excluded")

    filtered_df = eval_df[eval_df["row_number"].isin(
        audit_df.loc[~audit_df["is_label_dependent"], "row_number"]
    )].copy()
    filtered_df.to_csv(FILTERED_OUT, index=False)
    print(f"\n[INFO] Filtered benchmark ({len(filtered_df)} rows) written to {FILTERED_OUT}")
    print("[INFO] row_number is preserved from the original benchmark (not renumbered) -- "
          "existing result/intent CSVs can be filtered by row_number set-membership directly, "
          "no re-run required.")


if __name__ == "__main__":
    main()
