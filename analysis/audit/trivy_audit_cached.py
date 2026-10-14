#!/usr/bin/env python3
import argparse, glob, os, subprocess, sys, tempfile, csv
import pandas as pd
csv.field_size_limit(sys.maxsize)
ap = argparse.ArgumentParser()
ap.add_argument("--input", required=True); ap.add_argument("--type", required=True); ap.add_argument("--output-csv", required=True)
ap.add_argument("--cache", nargs="*", default=["result/iacgod/Trivy_*.csv", "result/final/Trivy_*.csv"])
a = ap.parse_args()
runs = pd.read_csv(a.input, engine="python")
cache = []
for g in a.cache:
    for p in glob.glob(g):
        if os.path.abspath(p) == os.path.abspath(a.output_csv) or ".bak" in p: continue
        try: c = pd.read_csv(p)
        except Exception: continue
        if {"run_id", "trivy_passed"} <= set(c.columns): cache.append(c)
cache = pd.concat(cache, ignore_index=True) if cache else pd.DataFrame(columns=["run_id"])
cache = cache[cache.error.isna()] if "error" in cache else cache
cache = cache.drop_duplicates("run_id", keep="last").set_index("run_id")
has_t = runs.final_template.fillna("").astype(str).str.strip() != ""
need = runs[~(runs.run_id.isin(cache.index) & has_t)]
print(f"[cache] {len(runs)-len(need)} reused, {len(need)} to scan")
new = pd.DataFrame()
if len(need):
    with tempfile.TemporaryDirectory() as t:
        src, dst = os.path.join(t, "in.csv"), os.path.join(t, "out.csv")
        need.to_csv(src, index=False)
        subprocess.run([sys.executable, "audit/trivy_audit.py", "--input", src, "--type", a.type, "--output-csv", dst], check=True)
        new = pd.read_csv(dst)
        new["run_id"] = new["run_id"].astype(str)
out = []
for i, r in enumerate(runs.itertuples()):
    rid = str(r.run_id)
    if rid in cache.index and has_t.iloc[i]:
        row = cache.loc[rid].to_dict(); row["run_id"] = rid
    else:
        m = new[new.run_id == rid] if len(new) else new
        if len(m): row = m.iloc[0].to_dict()
        else: row = {"run_id": rid, "trivy_passed": False, "error": "no template / not scanned"}
    row["row_index"] = i
    out.append(row)
canon = list(pd.read_csv("result/iacgod/Trivy_DSV4F_TFRealAWS.csv", nrows=0).columns)
df = pd.DataFrame(out)
for c in canon:
    if c not in df.columns: df[c] = None
df[canon].to_csv(a.output_csv, index=False)
print("[cache] wrote", a.output_csv)
