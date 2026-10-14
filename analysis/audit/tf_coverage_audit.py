#!/usr/bin/env python3

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

try:
    import pandas as pd
except ImportError:
    sys.exit("[ERROR] pandas not installed. Run: pip install pandas")

_field_size_limit = sys.maxsize
while True:
    try:
        csv.field_size_limit(_field_size_limit)
        break
    except OverflowError:
        _field_size_limit //= 2


def extract_tf_blocks(template_str: str) -> dict:
    template_str = template_str.strip() if template_str else ""
    
    resources = re.findall(r'^\s*resource\s+"([^"]+)"', template_str, re.MULTILINE)
    
    data_sources = re.findall(r'^\s*data\s+"([^"]+)"', template_str, re.MULTILINE)
    
    variables = re.findall(r'^\s*variable\s+"([^"]+)"', template_str, re.MULTILINE)
    
    outputs = re.findall(r'^\s*output\s+"([^"]+)"', template_str, re.MULTILINE)
    
    return {
        "resource": resources,
        "data": data_sources,
        "variable": variables,
        "output": outputs
    }

def load_ground_truth_blocks(folder_path: str) -> dict:
    p = Path(folder_path)
    combined_content = ""
    
    norm = Path(folder_path.replace("\\", "/"))
    for candidate in [p, norm, Path("iac_benchmark") / norm]:
        if candidate.exists() and candidate.is_dir():
            for tf_file in candidate.glob("*.tf"):
                try:
                    combined_content += tf_file.read_text(encoding="utf-8", errors="ignore") + "\n"
                except Exception:
                    pass
            break
        if candidate.exists() and candidate.is_file():
            try:
                combined_content = candidate.read_text(encoding="utf-8", errors="ignore") + "\n"
            except Exception:
                pass
            break
            
    return extract_tf_blocks(combined_content)


def analyze_block_coverage(required_blocks: list[str], generated_blocks: list[str]) -> dict:
    required_counts  = Counter(required_blocks)
    generated_counts = Counter(generated_blocks)

    all_items = set(required_counts) | set(generated_counts)
    correct: list[str]  = []
    missing: list[str]  = []
    extra:   list[str]  = []

    for item in all_items:
        req = required_counts.get(item, 0)
        gen = generated_counts.get(item, 0)
        correct.extend([item] * min(req, gen))
        if req > gen:
            missing.extend([item] * (req - gen))
        elif gen > req:
            extra.extend([item] * (gen - req))

    n_req = len(required_blocks)
    n_gen = len(generated_blocks)
    n_cor = len(correct)

    return {
        "required": n_req,
        "generated": n_gen,
        "correct": n_cor,
        "missing": len(missing),
        "extra": len(extra),
        "coverage_pct": round(n_cor / n_req * 100, 2) if n_req else (100.0 if n_gen == 0 else 0.0),
        "accuracy_pct": round(n_cor / n_gen * 100, 2) if n_gen else (100.0 if n_req == 0 else 0.0),
        "details": {
            "correct": correct,
            "missing": missing,
            "extra": extra,
        },
    }


def aggregate_metrics(rows: list[dict], block_types: list[str]) -> dict:
    matched = [r for r in rows if r.get("matched")]
    
    agg = {
        "total_rows_in_input": len(rows),
        "rows_matched_to_benchmark": len(matched),
        "rows_unmatched_skipped": sum(1 for r in rows if not r.get("matched")),
        "rows_with_empty_template": sum(1 for r in rows if r.get("template_empty")),
    }
    
    for btype in block_types:
        req_total = sum(r[btype]["required"] for r in matched)
        gen_total = sum(r[btype]["generated"] for r in matched)
        cor_total = sum(r[btype]["correct"] for r in matched)
        
        agg[f"{btype}_micro_coverage_pct"] = round(cor_total / req_total * 100, 4) if req_total else None
        agg[f"{btype}_micro_accuracy_pct"] = round(cor_total / gen_total * 100, 4) if gen_total else None
        
        cov_vals = [r[btype]["coverage_pct"] for r in matched if r[btype]["required"] > 0]
        acc_vals = [r[btype]["accuracy_pct"] for r in matched if r[btype]["generated"] > 0]
        
        agg[f"{btype}_mean_coverage_pct"] = round(sum(cov_vals) / len(cov_vals), 4) if cov_vals else None
        agg[f"{btype}_mean_accuracy_pct"] = round(sum(acc_vals) / len(acc_vals), 4) if acc_vals else None

    return agg


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Measure coverage and accuracy of LLM-generated TF templates."
    )
    p.add_argument("--input", "-i", required=True, metavar="CSV",
                   help="Input CSV with generated code (looks for 'final_template' or 'tf_code').")
    p.add_argument("--benchmark", "-b", required=True, metavar="CSV",
                   help="Benchmark CSV (e.g., tf_benchmark.csv).")
    p.add_argument("--output", "-o", metavar="JSON", default=None,
                   help="Write per-row + aggregate results to JSON.")
    p.add_argument("--output-csv", metavar="CSV_OUT", default=None,
                   help="Write flat per-row summary to CSV.")
    return p

def main() -> None:
    args = build_parser().parse_args()

    bench_path = Path(args.benchmark)
    if not bench_path.exists():
        sys.exit(f"[ERROR] Benchmark file not found: {bench_path}")

    bench_df = pd.read_csv(bench_path, dtype=str)
    
    if "ground_truth_path" not in bench_df.columns:
        sys.exit("[ERROR] Benchmark CSV missing `ground_truth_path` column.")

    benchmark: dict[str, dict] = {
        str(row["ground_truth_path"]).strip(): row.to_dict()
        for _, row in bench_df.iterrows()
    }

    print(f"[INFO] Benchmark loaded : {bench_path}  ({len(benchmark)} entries)")

    input_path = Path(args.input)
    if not input_path.exists():
        sys.exit(f"[ERROR] Input file not found: {input_path}")

    with input_path.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        fieldnames = reader.fieldnames or []
        
        code_col = "final_template" if "final_template" in fieldnames else ("tf_code" if "tf_code" in fieldnames else None)
        if not code_col:
            sys.exit(f"[ERROR] CSV missing code column (checked for 'final_template', 'tf_code'). Found: {fieldnames}")
            
        if "ground_truth_path" not in fieldnames:
            sys.exit(f"[ERROR] CSV missing `ground_truth_path` column. Found: {fieldnames}")
            
        input_rows = list(reader)

    print(f"[INFO] Input CSV loaded : {input_path}  ({len(input_rows)} rows)")
    print()

    SEP = "─" * 75
    row_results: list[dict] = []
    block_types = ["resource", "data", "variable", "output"]

    for i, row in enumerate(input_rows):
        gt_path   = str(row.get("ground_truth_path", "")).strip()
        template  = str(row.get(code_col, "")).strip()

        result: dict = {
            "row_index": i,
            "ground_truth_path": gt_path,
            "matched": False,
            "template_empty": not bool(template),
        }

        bench_row = benchmark.get(gt_path)
        if bench_row is None:
            result["matched"] = False
            row_results.append(result)
            continue

        result["matched"] = True
        result["difficulty"] = bench_row.get("difficulty", "")

        for btype in block_types:
            result[btype] = {}

        if not template:
            for btype in block_types:
                result[btype] = analyze_block_coverage([], [])
            row_results.append(result)
            continue

        gen_blocks = extract_tf_blocks(template)
        gt_blocks = load_ground_truth_blocks(gt_path)

        for btype in block_types:
            result[btype] = analyze_block_coverage(gt_blocks[btype], gen_blocks[btype])

        cov_res = result["resource"]["coverage_pct"]
        acc_res = result["resource"]["accuracy_pct"]
        req_res = result["resource"]["required"]
        gen_res = result["resource"]["generated"]
        
        print(
            f"  [{i:>4}] {gt_path[-30:]:>30} | "
            f"RES cov={cov_res:>5.1f}% acc={acc_res:>5.1f}% [req={req_res:<2} gen={gen_res:<2}] | "
            f"VAR cov={result['variable']['coverage_pct']:>5.1f}%"
        )
        
        row_results.append(result)

    agg = aggregate_metrics(row_results, block_types)

    print("\n" + SEP)
    print("AGGREGATE SUMMARY (Matched Scenarios Only)")
    print(SEP)
    print(f"  Input Rows Processed : {agg['total_rows_in_input']}")
    print(f"  Matched to Benchmark : {agg['rows_matched_to_benchmark']}")
    print(f"  Skipped (Non-AWS)    : {agg['rows_unmatched_skipped']}")
    print(f"  Empty Templates      : {agg['rows_with_empty_template']}\n")

    for btype in block_types:
        print(f"  --- {btype.upper()} METRICS ---")
        print(f"    Macro Avg Coverage (mean of %s) : {agg[f'{btype}_mean_coverage_pct']}")
        print(f"    Macro Avg Accuracy (mean of %s) : {agg[f'{btype}_mean_accuracy_pct']}")
        print(f"    Micro Avg Coverage (global pool): {agg[f'{btype}_micro_coverage_pct']}")
        print(f"    Micro Avg Accuracy (global pool): {agg[f'{btype}_micro_accuracy_pct']}\n")

    if args.output:
        Path(args.output).write_text(
            json.dumps({"aggregate": agg, "rows": row_results}, indent=2),
            encoding="utf-8",
        )
        print(f"[INFO] JSON written      : {args.output}")

    if args.output_csv:
        flat_cols = ["row_index", "ground_truth_path", "matched", "difficulty", "template_empty"]
        
        for btype in block_types:
            flat_cols.extend([
                f"{btype}_req", f"{btype}_gen", f"{btype}_cor", 
                f"{btype}_missing", f"{btype}_extra", 
                f"{btype}_cov_pct", f"{btype}_acc_pct",
                f"{btype}_missing_list", f"{btype}_extra_list"
            ])
            
        with open(args.output_csv, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=flat_cols, extrasaction="ignore")
            writer.writeheader()
            
            for r in row_results:
                if not r.get("matched"):
                    continue
                flat = {
                    "row_index": r["row_index"],
                    "ground_truth_path": r["ground_truth_path"],
                    "matched": r["matched"],
                    "difficulty": r.get("difficulty", ""),
                    "template_empty": r["template_empty"]
                }
                for btype in block_types:
                    bdata = r.get(btype, {})
                    if not bdata: continue
                    flat[f"{btype}_req"] = bdata.get("required")
                    flat[f"{btype}_gen"] = bdata.get("generated")
                    flat[f"{btype}_cor"] = bdata.get("correct")
                    flat[f"{btype}_missing"] = bdata.get("missing")
                    flat[f"{btype}_extra"] = bdata.get("extra")
                    flat[f"{btype}_cov_pct"] = bdata.get("coverage_pct")
                    flat[f"{btype}_acc_pct"] = bdata.get("accuracy_pct")
                    
                    details = bdata.get("details", {})
                    flat[f"{btype}_missing_list"] = ";".join(details.get("missing", []))
                    flat[f"{btype}_extra_list"]   = ";".join(details.get("extra", []))
                    
                writer.writerow(flat)
                
        print(f"[INFO] CSV written       : {args.output_csv}")

if __name__ == "__main__":
    main()
