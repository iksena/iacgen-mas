import argparse, csv, glob, json, os, re, sys
from collections import Counter, defaultdict

IAC = ".."
EXPS = {
    "CFN_RealAWS_Opus55": "CFNEvalRealAWS_Opus55_runs",
    "TF_RealAWS_Opus55": "TFEvalRealAWS_Opus55_runs",
}
NARR = re.compile(
    r"(\bI (?:checked|ran|read|looked at|inspected|listed|opened|searched|grepped|queried|fetched|copied|executed)\b"
    r"|isolated copy|checked the host|\bPID \d+|\bps aux\b|\bHEAD request|anonymous HTTPS|\bcurl -|"
    r"/home/tianyi|miniconda3/envs|benchmark\.py|tf_eval_benchmark|cfn_eval_benchmark)", re.I)


def find_run_dir(organizer, rid):
    for d in (f"{IAC}/runs/{organizer}/{rid}", f"{IAC}/runs/{rid}"):
        if os.path.isdir(d):
            return d
    hits = glob.glob(f"{IAC}/runs/*/{rid}")
    return hits[0] if hits else None


def audit(exp):
    organizer = EXPS[exp]
    fin = {r["run_id"] for r in csv.DictReader(open(f"{IAC}/results/{exp}/results_final.csv"))}
    att = list(csv.DictReader(open(f"{IAC}/results/{exp}/attempts_all.csv")))
    rows, calls_out = [], []
    for a in att:
        rid = a["run_id"]
        d = find_run_dir(organizer, rid)
        rec = dict(exp=exp, row_number=a["row_number"], run_id=rid, in_final=rid in fin,
                   batch=a.get("_batch", ""), n_calls=0, clean=0, tool_use=0, unknown=0,
                   max_prompt_tokens=0, tool_agents="", narration_hits=0, status="")
        if not d or not os.path.exists(f"{d}/llm_calls.jsonl"):
            rec["status"] = "NO_LOG"
            rows.append(rec)
            continue
        agents = Counter()
        for l in open(f"{d}/llm_calls.jsonl"):
            try:
                c = json.loads(l)
            except Exception:
                continue
            tu = c.get("token_usage") or {}
            pt = tu.get("prompt_tokens") if isinstance(tu, dict) else None
            rec["n_calls"] += 1
            txt = str(c.get("response", ""))
            nh = len(NARR.findall(txt))
            rec["narration_hits"] += nh
            if pt == 2:
                kind = "clean"; rec["clean"] += 1
            elif pt in (0, None):
                kind = "unknown"; rec["unknown"] += 1
            else:
                kind = "tool_use"; rec["tool_use"] += 1; agents[c.get("agent")] += 1
                rec["max_prompt_tokens"] = max(rec["max_prompt_tokens"], pt)
            if kind != "clean" or nh:
                m = NARR.search(txt)
                snip = txt[max(0, (m.start() if m else 0) - 100):(m.end() if m else 0) + 160].replace("\n", " ")
                calls_out.append(dict(exp=exp, row_number=a["row_number"], run_id=rid, in_final=rid in fin,
                                      agent=c.get("agent"), iteration=c.get("iteration"), kind=kind,
                                      prompt_tokens=pt, model=c.get("model"), narration=nh, snippet=snip[:300]))
        rec["tool_agents"] = ";".join(f"{k}:{v}" for k, v in agents.items())
        rec["status"] = ("TOOL_USE" if rec["tool_use"] else "UNKNOWN" if rec["unknown"] else "CLEAN")
        rows.append(rec)
    out = f"{IAC}/results/proxy_tool_use_audit_{exp}"
    for suffix, data in (("", rows), ("_calls", calls_out)):
        if data:
            with open(f"{out}{suffix}.csv", "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(data[0].keys())); w.writeheader(); w.writerows(data)
    return rows, calls_out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--exp", nargs="*", default=list(EXPS))
    args = ap.parse_args()
    for exp in args.exp:
        rows, calls = audit(exp)
        fin = [r for r in rows if r["in_final"]]
        print(f"\n=== {exp}: {len(rows)} attempts, {len(fin)} in the final set")
        for name, rs in (("all attempts", rows), ("final set", fin)):
            c = Counter(r["status"] for r in rs)
            print(f"  {name}: {dict(c)}  | calls: {sum(r['n_calls'] for r in rs)} "
                  f"(clean {sum(r['clean'] for r in rs)}, tool_use {sum(r['tool_use'] for r in rs)}, "
                  f"unknown {sum(r['unknown'] for r in rs)})")
        bad = [r for r in fin if r["status"] != "CLEAN"]
        print(f"  final-set rows not CLEAN: {len(bad)} -> rows {sorted(int(r['row_number']) for r in bad)}")


if __name__ == "__main__":
    main()
