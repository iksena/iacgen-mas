#!/usr/bin/env python3
import argparse, json, os, sys
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "analysis", "audit"))
import finalize_results as fr

ap = argparse.ArgumentParser()
ap.add_argument("--name", required=True)
ap.add_argument("--results", required=True)
ap.add_argument("--templates-root", required=True, help="dir that contains the paths in final_template_path (llm_generated_data/...)")
ap.add_argument("--dataset", required=True)
ap.add_argument("--error-history", default=None, help="IaCGen Code/result/error_tracking/.../*_error_history.csv: supplies the last error of every failed row")
ap.add_argument("--schema-from", default=os.path.join(ROOT, "results", "CFN_RealAWS_GLM53F", "results_final.csv"))
a = ap.parse_args()

res = pd.read_csv(a.results, low_memory=False)
res["row_number"] = res.row_number.astype(int)
ds = pd.read_csv(os.path.join(ROOT, a.dataset) if not os.path.isabs(a.dataset) else a.dataset)
ds["row_number"] = ds.row_number.astype(int)
cols = list(pd.read_csv(a.schema_from, nrows=1, low_memory=False).columns)

last_err = {}
if a.error_history and os.path.exists(a.error_history):
    eh = pd.read_csv(a.error_history, low_memory=False).sort_values("timestamp")
    last_err = {int(n): " | ".join(dict.fromkeys(str(m) for m in g[g.timestamp == g.timestamp.max()]["error_message"])) for n, g in eh.groupby("row_number")}

def template(p):
    f = os.path.join(a.templates_root, str(p))
    return open(f, encoding="utf-8", errors="replace").read() if os.path.exists(f) else ""

rows = []
for _, r in res.iterrows():
    ok = bool(r["success"])
    err = "" if ok else (last_err.get(int(r.row_number)) or str(r.get("error_message") if pd.notna(r.get("error_message")) else "") or str(r.get("failure_reason") if pd.notna(r.get("failure_reason")) else ""))
    env = (not ok) and bool(fr.ENV_RE.search(err))
    rows.append(dict(
        row_number=int(r.row_number), ground_truth_path=r.ground_truth_path, run_id=f"iacgen_{a.name}_row{int(r.row_number)}",
        status="ok", final_validation_passed=ok, iterations_used=int(r.total_iterations),
        error_message=err[:2000], final_template=template(r.final_template_path),
        deploy_target="aws", deploy_passed=ok, deploy_error_message=("" if ok else err[:2000]),
        validity="valid_pass" if ok else ("invalid_environment" if env else "valid_fail"),
        invalid_reason=("environment error: " + err[:160]) if env else "",
        highest_feedback_level=r.get("highest_feedback_level"), failed_at_stage=(None if ok else r.get("failed_at_stage")),
        coverage_percentage=r.get("coverage_percentage"), accuracy_percentage=r.get("accuracy_percentage"),
    ))
out = pd.DataFrame(rows)
out = out.merge(ds[["row_number", "ground_truth_path"]], on="row_number", how="left", suffixes=("_ig", ""))
out["ground_truth_path"] = out["ground_truth_path"].fillna(out["ground_truth_path_ig"]); out = out.drop(columns=["ground_truth_path_ig"])
missing = sorted(set(ds.row_number) - set(out.row_number))
assert not missing, f"dataset rows without an IaCGen result: {missing}"
extra = [c for c in out.columns if c not in cols]
full = out.reindex(columns=cols + extra).sort_values("row_number")

d = os.path.join(ROOT, "results", a.name); os.makedirs(d, exist_ok=True)
full.to_csv(os.path.join(d, "results_final.csv"), index=False)
full.to_csv(os.path.join(d, "attempts_all.csv"), index=False)
json.dump(dict(name=a.name, expected=len(ds), rows=len(full), valid_pass=int((full.validity == "valid_pass").sum()),
               valid_fail=int((full.validity == "valid_fail").sum()), invalid=int((full.validity == "invalid_environment").sum()),
               source=os.path.basename(a.results), note="imported from original IaCGen results (scripts/import_iacgen_results.py)"),
          open(os.path.join(d, "status.json"), "w"), indent=1)
print(a.name, "rows", len(full), "| pass", int((full.validity == "valid_pass").sum()), "| fail", int((full.validity == "valid_fail").sum()),
      "| invalid(env)", int((full.validity == "invalid_environment").sum()), "| templates found", int((full.final_template.fillna("").str.len() > 20).sum()))
