#!/usr/bin/env python3
import csv, glob, json, math, os, sys
import numpy as np, pandas as pd
csv.field_size_limit(sys.maxsize)
ROOT = ".."
EXPS = {"CFN": {"DeepSeek": "CFN_RealAWS_DSV4F", "GLM": "CFN_RealAWS_GLM53F", "Gemini": "CFN_RealAWS_Gemini38F"},
        "TF": {"DeepSeek": "TF_RealAWS_DSV4F", "GLM": "TF_RealAWS_GLM53F", "Gemini": "TF_RealAWS_Gemini38F"}}
idx = {}
for p in glob.glob(f"{ROOT}/runs/**/final_report.json", recursive=True):
    idx[os.path.basename(os.path.dirname(p))] = os.path.dirname(p)

def deploy_trace(run_dir):
    out = []
    for f in sorted(glob.glob(run_dir + "/iteration_*.json")):
        j = json.load(open(f)); dv = j.get("deploy_validation_result") or {}
        ran = dv.get("target") not in (None, "skipped")
        out.append((int(j["iteration"]), ran, bool(dv.get("passed")) if ran else None))
    return out

def episode(trace):
    fail = [i for i, (it, ran, ok) in enumerate(trace) if ran and not ok]
    if not fail: return None
    f0 = fail[0]; later = [i for i, (it, ran, ok) in enumerate(trace) if i > f0 and ran and ok]
    first_it = trace[f0][0]; last_it = trace[-1][0]
    return dict(first=first_it, remaining=last_it - first_it, latency=(trace[later[0]][0] - first_it) if later else np.nan)

def wilson(k, n, z=1.96):
    if n == 0: return (np.nan, np.nan)
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - h) / d, (c + h) / d)

def hazard(eps, kmax=8):
    rows = []
    for k in range(1, kmax + 1):
        res = int((eps.latency == k).sum())
        cens = int(((eps.remaining >= k) & (eps.latency.isna() | (eps.latency >= k))).sum())
        naive = int((eps.latency.isna() | (eps.latency >= k)).sum())
        lo, hi = wilson(res, cens)
        rows.append(dict(turn_k=k, open_censored=cens, open_naive=naive, resolved=res, hazard_censored=res / cens if cens else np.nan,
                         hazard_naive=res / naive if naive else np.nan, ci95_lo=lo, ci95_hi=hi))
    return pd.DataFrame(rows)

if __name__ == "__main__":
    allrows = []
    for lang, models in EXPS.items():
        pooled = []
        for name, e in models.items():
            ids = pd.read_csv(f"{ROOT}/results/{e}/results_final.csv", engine="python").run_id
            eps = []
            for rid in ids:
                d = idx.get(rid)
                if d is None: continue
                ep = episode(deploy_trace(d))
                if ep: eps.append(dict(model=name, run_id=rid, **ep))
            eps = pd.DataFrame(eps); pooled.append(eps)
            h = hazard(eps); h.insert(0, "scope", name); h.insert(0, "lang", lang); allrows.append(h)
            print(f"{lang} {name}: {len(eps)} deployment episodes in {len(ids)} runs, {int(eps.latency.isna().sum())} unresolved")
        P = pd.concat(pooled); h = hazard(P); h.insert(0, "scope", "pooled (3 models)"); h.insert(0, "lang", lang); allrows.append(h)
        print(f"\n{lang} pooled: {len(P)} episodes")
        print((h[["turn_k", "open_censored", "open_naive", "resolved", "hazard_censored", "hazard_naive", "ci95_lo", "ci95_hi"]]
               .assign(**{c: lambda d, c=c: (d[c] * 100).round(1) for c in ["hazard_censored", "hazard_naive", "ci95_lo", "ci95_hi"]})).head(6).to_string(index=False))
    R = pd.concat(allrows); R.to_csv(ROOT + "/results/repair_loop_tables/F2_hazard_check.csv", index=False)
    print("\nwrote F2_hazard_check.csv")
