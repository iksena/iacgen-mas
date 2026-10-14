#!/usr/bin/env python3
import json, os, re, sys, glob, collections
import pandas as pd, csv
csv.field_size_limit(sys.maxsize)
ROOT = ".."
OUT = ROOT + "/results/opencode_workspace_audit_"
SERVER = "/home/tianyi/iac-research/iac-god"
EXPS = ["CFN_RealAWS_OpenCode_DSV4F", "TF_RealAWS_OpenCode_DSV4F", "CFN_Ablation_OpenCodeRetriever", "TF_Ablation_OpenCodeRetriever"]
import argparse
_ap = argparse.ArgumentParser(); _ap.add_argument("--exp", nargs="*", help="experiments to audit (default: all four OpenCode ones)")
_ap.add_argument("--mark-invalid", action="store_true", help="write scripts/tainted_runs.csv (makes tainted attempts invalid in finalize_results)")
_args = _ap.parse_args()
if _args.exp: EXPS = _args.exp
idx = {}
for p in glob.glob(f"{ROOT}/runs/**/harness_stream.jsonl", recursive=True):
    idx.setdefault(os.path.basename(os.path.dirname(p)), os.path.dirname(p))
PATH_KEYS = ("filePath", "file_path", "path", "notebook_path", "dir", "directory", "cwd")
ABS = re.compile(r"(?:^|[\s\"'=(])((?:/[A-Za-z0-9_.@+-]+)+/?|~/[^\s\"']*|\.\./[^\s\"']*)")

def resolve(p, ws):
    base = SERVER if p.startswith(("runs/", "./runs/")) else ws
    full = p if os.path.isabs(p) else os.path.join(base, p)
    return os.path.normpath(full)

def inside(p, ws, rid=None):
    if p == ws or p.startswith(ws + "/"): return True
    return rid is not None and re.search(rf"/runs/(?:[^/]+/)?{rid}/workspace(/|$)", p) is not None

def category(p, rid):
    if re.search(rf"/runs/(?:[^/]+/)?{rid}(/|$)", p): return "own run folder"
    for k, c in (("/baselines/", "harness code"), ("/agents/", "pipeline code"), ("/tools/", "pipeline code"), ("config.py", "config/.env/nuke"), ("nuke-config", "config/.env/nuke"),
                 ("/.env", "config/.env/nuke"), ("/data/", "benchmark data"), ("/benchmark_runs/", "benchmark results"), ("/runs/", "other run folders"), ("/prompts/", "prompts"),
                 ("AGENTS.md", "docs"), ("README", "docs"), ("scraped_html", "knowledge base"), ("knowledge_graph", "knowledge base"), ("resource_spec", "knowledge base"),
                 ("tf_registry", "knowledge base"), ("tf_schema", "knowledge base"), ("cfn_benchmark", "ground truth"), ("iac_benchmark", "ground truth"), ("cfn_templates", "ground truth"),
                 ("/volume", "volume/state")):
        if k in p: return c
    if re.fullmatch(rf"{re.escape(SERVER)}/?", p): return "repo root listing"
    if p.startswith(("/usr/", "/etc/", "/tmp", "/var/", "/opt/", "/home/")) and "iac-god" not in p: return "system / other"
    return "repo root / other"

def audit():
    rows, hits = [], []
    for e in EXPS:
        a = pd.read_csv(f"{ROOT}/results/{e}/attempts_all.csv", engine="python")
        fin = set(pd.read_csv(f"{ROOT}/results/{e}/results_final.csv", engine="python").run_id)
        for _, r in a.iterrows():
            rid = r.run_id; d = idx.get(rid)
            base = dict(exp=e, run_id=rid, row=int(r.row_number), final=rid in fin, status=r.status, validity=r.validity, passed=bool(r.final_validation_passed), day=rid[:8])
            if d is None: rows.append(dict(base, has_stream=False)); continue
            ws = f"{SERVER}/runs/{rid}/workspace"
            m = re.search(r'"?(/[^\s"]+/runs/(?:[^/"]+/)?' + rid + r'/workspace)', open(d + "/harness_stream.jsonl").read())
            if m: ws = m.group(1)
            for l in open(d + "/harness_stream.jsonl"):
                if not l.startswith("{"): continue
                try: ev = json.loads(l)
                except Exception: continue
                if ev.get("type") != "tool_use": continue
                pt = ev["part"]; tool = pt.get("tool", ""); st = pt.get("state") or {}; inp = st.get("input") or {}; ok = st.get("status") == "completed"
                paths = [inp[k] for k in PATH_KEYS if isinstance(inp.get(k), str) and inp[k]]
                if tool == "glob" and isinstance(inp.get("pattern"), str) and inp["pattern"].startswith("/"): paths.append(inp["pattern"])
                if tool == "grep" and isinstance(inp.get("pattern"), str): pass
                if tool in ("bash", "shell") and isinstance(inp.get("command"), str): paths += [x.strip() for x in ABS.findall(inp["command"])]
                kind = ("write" if tool in ("write", "edit") else "validate/deploy/submit" if tool.endswith(("validate_iac", "deploy_iac", "submit_template")) else "read/search")
                for p in paths:
                    q = resolve(p, ws)
                    if not inside(q, ws, rid): hits.append(dict(base, tool=tool, kind=kind, ok=ok, path=q, cat=category(q, rid)))
    H = pd.DataFrame(hits)
    return H, pd.DataFrame(rows), idx

def tiers(H):
    S = H[H.ok]
    def tier(g):
        a = g[(~g.cat.isin(["own run folder", "repo root listing"])) | (g.kind != "read/search")]
        return "A" if len(a) else "B"
    t = S.groupby("run_id").apply(tier).rename("tier").reset_index()
    cats = S.groupby("run_id").cat.apply(lambda s: "; ".join(sorted(set(s)))).rename("cats").reset_index()
    kinds = S.groupby("run_id").kind.apply(lambda s: "; ".join(sorted(set(s)))).rename("kinds").reset_index()
    out = []
    for e in EXPS:
        f = pd.read_csv(f"{ROOT}/results/{e}/results_final.csv", engine="python")
        a = pd.read_csv(f"{ROOT}/results/{e}/attempts_all.csv", engine="python")[["run_id", "validity"]]
        f = f[["row_number", "run_id", "final_validation_passed"]].merge(a, on="run_id", how="left"); f["exp"] = e; out.append(f)
    M = pd.concat(out).merge(t, on="run_id", how="left").merge(cats, on="run_id", how="left").merge(kinds, on="run_id", how="left")
    M["tier"] = M.tier.fillna("clean")
    return M

if __name__ == "__main__":
    H, R0, _ = audit()
    H.to_csv(OUT + "hits.csv", index=False)
    M = tiers(H); M.to_csv(OUT + "final_runs.csv", index=False)
    S = H[H.ok]
    T = S.groupby("run_id").agg(exp=("exp", "first"), row=("row", "first"), cats=("cat", lambda s: "; ".join(sorted(set(s)))), kinds=("kind", lambda s: "; ".join(sorted(set(s))))).reset_index()
    T.to_csv(OUT + "tainted_candidates.csv", index=False); print("attempts with outside access (report only):", len(T), "->", OUT + "tainted_candidates.csv")
    if _args.mark_invalid:
        T.to_csv("audit/tainted_runs.csv", index=False); print("MARKED INVALID ->", "audit/tainted_runs.csv")
    else: print("tainted_runs.csv NOT changed (use --mark-invalid when told to)")
    print("hits", len(H))
    for e, x in M.groupby("exp"):
        print(f"\n== {e}: {len(x)} final runs")
        for tr, y in x.groupby("tier"): print(f"   tier {tr}: {len(y)} runs, pass {int(y.final_validation_passed.sum())}")
        print("   A rows:", ",".join(str(r) for r in sorted(x[x.tier == "A"].row_number)), "\n   B rows:", ",".join(str(r) for r in sorted(x[x.tier == "B"].row_number)))
