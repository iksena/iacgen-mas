import glob, json, os, sys
import numpy as np, pandas as pd
from scipy import stats

ROOT = '..'
FINAL = f'result/final'
INTENT = f'ablation_selection/intent_results'
CACHE = f'../results/_analysis_cache'
CONDS = {'NoDenseRAG': 'no-dense-rag', 'NoGraphRAG': 'no-graphrag', 'NoQueryRewrite': 'no-query-rewrite',
         'NoRemediator': 'no-remediator', 'NoPlanner': 'no-planner', 'OpenCodeRetriever': 'opencode-retriever',
         'TrivyAllSeverities': 'trivy-all-sev'}

src = open(f'audit/invalid_rows_review.py').read()
ns = {'__name__': 'rv'}; sys.argv = ['x', '/dev/null']; exec(src[:src.index('rows = []')], ns)
label, run_dir = ns['label'], ns['idx']

def iter_labels(run_id):
    p = run_dir.get(str(run_id))
    return ''.join(label(json.load(open(f))) for f in sorted(glob.glob(f'{p}/iteration_*.json'))) if p else ''

def mcnemar(a, b):
    n01, n10 = int((~a & b).sum()), int((a & ~b).sum())
    p = stats.binomtest(n01, n01 + n10, 0.5).pvalue if n01 + n10 else 1.0
    return p, n10, n01

def wilcox(x, y):
    d = np.asarray(y, float) - np.asarray(x, float)
    return stats.wilcoxon(x, y).pvalue if len(d) and np.any(d != 0) else 1.0

def load(lang, cond):
    r = pd.read_csv(f'../results/{lang}_Ablation_{cond}/results_final.csv', low_memory=False)
    r['passed'] = r.final_validation_passed.astype(str).str.lower().eq('true')
    r['first'] = r.passed & r.iterations_used.eq(1)
    r['repair_turns'] = r.iterations_used - 1
    cov = pd.read_csv(f'{FINAL}/Coverage_{lang}_Ablation_{cond}.csv', low_memory=False)
    if lang == 'CFN':
        cov = cov[['row_number', 'accuracy_pct', 'extra_resources', 'total_generated_resources']]
    else:
        cov = cov.merge(r[['row_number', 'ground_truth_path']], on='ground_truth_path')[
            ['row_number', 'resource_acc_pct', 'resource_extra', 'resource_gen']]
        cov.columns = ['row_number', 'accuracy_pct', 'extra_resources', 'total_generated_resources']
    r = r.merge(cov, on='row_number', how='left')
    tv = pd.read_csv(f'{FINAL}/Trivy_{lang}_Ablation_{cond}.csv', low_memory=False)[['run_id', 'total_failed']]
    r = r.merge(tv, on='run_id', how='left'); r['trivy_clean'] = r.total_failed.eq(0)
    it = pd.read_csv(f'{INTENT}/{"baseline" if cond == "IaCGOD" else CONDS[cond]}.csv')
    it = it[it.lang == lang.lower()][['row_number', 'intent_strict', 'core_score']]
    it['intent_strict'] = it.intent_strict.astype(str).str.lower().isin(['true', '1', '1.0'])
    r = r.merge(it, on='row_number', how='left')
    its = pd.read_pickle(f'{CACHE}/iters_{lang}_Ablation_{cond}.pkl')
    def keyset(x):
        k = set()
        for c in ['syntax_keys', 'schema_keys', 'security_keys', 'deploy_keys']:
            if isinstance(x[c], str) and x[c]: k |= {c[:3] + ':' + s for s in x[c].split('|')}
        return frozenset(k)
    stuck = {}
    for rid, g in its.sort_values('iteration').groupby('run_id'):
        ks = [keyset(x) for _, x in g.iterrows() if not x.validation_passed]
        turns = [(a, b) for a, b in zip(ks, ks[1:])]
        stuck[rid] = (sum(1 for a, b in turns if a and a == b), len(turns))
    r['stuck_turns'] = r.run_id.map(lambda x: stuck.get(x, (0, 0))[0])
    r['n_turns'] = r.run_id.map(lambda x: stuck.get(x, (0, 0))[1])
    r['labels'] = r.run_id.map(iter_labels)
    r['env_iters'] = r.labels.str.count('E')
    return r.set_index('row_number')

rows = []
for lang in ['CFN', 'TF']:
    base = load(lang, 'IaCGOD')
    for cond in CONDS:
        c = load(lang, cond)
        idx = base.index.intersection(c.index); b, d = base.loc[idx], c.loc[idx]
        def add(metric, vb, vc, p, n, note=''):
            rows.append(dict(lang=lang, condition=cond, metric=metric, baseline=vb, ablation=vc, p=p, n=n, note=note))
        for m in ['passed', 'first', 'trivy_clean', 'intent_strict']:
            ok = b[m].notna() & d[m].notna()
            p, lost, gained = mcnemar(b.loc[ok, m].astype(bool).values, d.loc[ok, m].astype(bool).values)
            add(m, round(100 * b.loc[ok, m].mean(), 1), round(100 * d.loc[ok, m].mean(), 1), p, int(ok.sum()), f'lost {lost} gained {gained}')
        both = b.passed & d.passed
        add('iterations (common passes)', b.loc[both, 'iterations_used'].mean(), d.loc[both, 'iterations_used'].mean(),
            wilcox(b.loc[both, 'iterations_used'], d.loc[both, 'iterations_used']), int(both.sum()))
        for m in ['llm_calls_total', 'token_all_tokens', 'accuracy_pct', 'extra_resources', 'total_generated_resources', 'core_score']:
            ok = b[m].notna() & d[m].notna()
            add(m, b.loc[ok, m].mean(), d.loc[ok, m].mean(), wilcox(b.loc[ok, m], d.loc[ok, m]), int(ok.sum()))
        ff = ~b['first'] & ~d['first']; rep = ff & b.passed & d.passed
        add('repair turns (paired)', b.loc[rep, 'repair_turns'].mean(), d.loc[rep, 'repair_turns'].mean(),
            wilcox(b.loc[rep, 'repair_turns'], d.loc[rep, 'repair_turns']), int(rep.sum()))
        w3b, w3d = (b.passed & (b.repair_turns <= 3))[ff], (d.passed & (d.repair_turns <= 3))[ff]
        p, lost, gained = mcnemar(w3b.values, w3d.values)
        add('repaired within 3 turns (paired)', round(100 * w3b.mean(), 1), round(100 * w3d.mean(), 1), p, int(ff.sum()), f'lost {lost} gained {gained}')
        sb = (b.stuck_turns / b.n_turns.replace(0, np.nan))[ff]; sd = (d.stuck_turns / d.n_turns.replace(0, np.nan))[ff]
        ok = sb.notna() & sd.notna()
        add('stuck-turn share per run (paired)', 100 * sb[ok].mean(), 100 * sd[ok].mean(), wilcox(sb[ok], sd[ok]), int(ok.sum()))
        clean = rep & b.env_iters.eq(0) & d.env_iters.eq(0)
        add('repair turns (paired, no env errors)', b.loc[clean, 'repair_turns'].mean(), d.loc[clean, 'repair_turns'].mean(),
            wilcox(b.loc[clean, 'repair_turns'], d.loc[clean, 'repair_turns']), int(clean.sum()))
        add('runs with env iterations', int((b.env_iters > 0).sum()), int((d.env_iters > 0).sum()), np.nan, len(idx),
            f'env iterations {int(b.env_iters.sum())} vs {int(d.env_iters.sum())}')
out = pd.DataFrame(rows)
out['p_holm'] = np.nan
for (lang, m), g in out[out.p.notna()].groupby(['lang', 'metric']):
    order = g.p.sort_values().index; k = len(order); prev = 0
    for i, ix in enumerate(order):
        prev = max(prev, min(1, (k - i) * out.at[ix, 'p'])); out.at[ix, 'p_holm'] = prev
out.to_csv(f'result/ablation_significance.csv', index=False)
pd.set_option('display.width', 250); pd.set_option('display.max_rows', 400)
print(out.round(3).to_string())
