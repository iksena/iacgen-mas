import glob, os, re
import pandas as pd

RESULT_KINDS = [("timed out", "TIMEOUT"), ("STATIC VALIDATION PASSED", "SPASS"), ("STATIC VALIDATION FAILED", "SFAIL"),
                ("DEPLOYMENT PASSED", "DPASS"), ("attempt passed", "DPASS"), ("DEPLOYMENT FAILED", "DFAIL"), ("attempt failed", "DFAIL"),
                ("Template submitted", "SUBMIT_OK"), ("Submission refused", "SUBMIT_REFUSED"), ("ITERATION CAP", "CAP")]
CLAIM = re.compile(r"submitted successfully|fully validated|successfully validated|is ready|has been submitted|passed all static|complete", re.I)


def tool_events(run_dir):
    t = open(os.path.join(run_dir, "harness_tool_calls.txt"), errors="ignore").read()
    ev = []
    for name, res in re.findall(r"tool_use #\d+: iacgod_(\w+)\]\n(?:.*\n)*?\[TOOL RESULT\]\n([^\n]*)", t):
        ev.append((name, next((k for s, k in RESULT_KINDS if s in res), "OTHER")))
    return ev


def closing_text(run_dir):
    p = os.path.join(run_dir, "harness_transcript.txt")
    if not os.path.exists(p):
        return ""
    m = re.search(r"final text\s*:\s*(.{0,400})", open(p, errors="ignore").read())
    return m.group(1) if m else ""


def classify(results_csv, runs_root, budget=15):
    idx = {os.path.basename(d.rstrip("/")): d for d in glob.glob(os.path.join(runs_root, "*", "*/"))}
    df = pd.read_csv(results_csv, low_memory=False)
    rows = []
    for _, r in df.iterrows():
        passed = r.validity == "valid_pass" and r.iterations_used <= budget
        if passed:
            continue
        d = idx.get(str(r.run_id))
        ev = tool_events(d) if d and os.path.exists(os.path.join(d, "harness_tool_calls.txt")) else []
        kinds = [k for _, k in ev]
        n_to, n_dp, n_df = kinds.count("TIMEOUT"), kinds.count("DPASS"), kinds.count("DFAIL")
        if r.status == "harness_error" or (r.status == "harness_timeout" and r.iterations_used <= budget):
            cat = "harness"
        elif r.iterations_used > budget:
            cat = "over_budget"
        elif n_to and not n_dp and kinds.count("DFAIL") <= 1 and r.iterations_used < budget:
            cat = "no_deploy_result"
        elif n_dp:
            cat = "edited_after_pass"
        elif r.iteration_cap_reached or r.iterations_used >= budget:
            cat = "budget"
        else:
            cat = "stopped_early"
        rows.append(dict(row_number=r.row_number, run_id=r.run_id, validity=r.validity, iterations_used=r.iterations_used,
                         deploy_timeouts=n_to, deploy_passes=n_dp, deploy_failures=n_df, submitted=bool(r.submitted_by_harness),
                         category=cat, claims_success=bool(CLAIM.search(closing_text(d) if d else ""))))
    return pd.DataFrame(rows)
