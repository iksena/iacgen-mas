import json, glob, os, re, sys
import pandas as pd
sys.path.insert(0, 'audit')
from finalize_results import ENV_RE
FINAL = './result/final'
RUNS = '../runs'
OUT = sys.argv[1]

MODEL_RE = re.compile("|".join([
    r"failed to send cfn-response", r"Invalid \w+ specified", r"is not a valid", r"required parameter",
    r"Unknown parameters", r"HandlerErrorCode: InvalidRequest", r"Unsupported block type", r"Unsupported argument",
    r"ValidationError", r"Template format error", r"Invalid scope requested",
]), re.I)
COLLISION_RE = re.compile(r"already exists|already in use|Only 1 \w+ is allowed|Cluster already exists", re.I)

idx = {}
for p in glob.glob(f'{RUNS}/*/*') + glob.glob(f'{RUNS}/*/*/*'):
    if os.path.isdir(p):
        idx.setdefault(os.path.basename(p), p)

def blocking_text(it):
    parts = [f"[{vr.get('stage')}] " + json.dumps(vr.get('errors'))
             for vr in it.get('validation_results') or [] if not vr.get('passed', True)]
    dv = it.get('deploy_validation_result') or {}
    if not parts and dv.get('target') not in (None, 'skipped') and not dv.get('passed', True):
        parts.append('[deploy] ' + str(dv.get('error_message') or ''))
        parts += [str(fr.get('status_reason') or fr) for fr in dv.get('failed_resources') or []]
    return '\n'.join(parts)

def label(it):
    if it.get('validation_passed'):
        return 'P'
    t = blocking_text(it)
    if not t.strip():
        return '?'
    m = ENV_RE.search(t)
    if not m or MODEL_RE.search(t):
        return 'M'
    if m.group(0).lower() == 'alreadyexists' and not COLLISION_RE.search(t):
        return 'M'
    return 'E'

rows = []
for f in sorted(glob.glob('../results/*/results_final.csv')):
    exp = os.path.basename(os.path.dirname(f))
    d = pd.read_csv(f, low_memory=False)
    for r in d[d.validity.astype(str).str.startswith('invalid')].itertuples():
        p = idx.get(str(r.run_id))
        seq = ''.join(label(json.load(open(fp))) for fp in sorted(glob.glob(f'{p}/iteration_*.json'))) if p else ''
        n_e, n_m = seq.count('E'), seq.count('M')
        if r.validity == 'invalid_environment':
            review = 'invalid_environment' if n_e > n_m else 'valid_fail'
        else:
            review = r.validity
        rows.append(dict(experiment=exp, row_number=int(r.row_number), run_id=r.run_id, validity=r.validity,
                         invalid_reason=r.invalid_reason, iterations=seq, env_iterations=n_e,
                         model_iterations=n_m, review=review))
pd.DataFrame(rows).to_csv(OUT, index=False)
