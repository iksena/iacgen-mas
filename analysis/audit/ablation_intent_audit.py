#!/usr/bin/env python3
import argparse
import csv
import json
import os
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'intent_checks'))
import intent_core as ic

csv.field_size_limit(2 ** 31 - 1)

DEFAULT_REPORTS_DIR = Path(__file__).resolve().parents[2] / 'IaCGOD' / 'runs'


class ReportIndex:
    def __init__(self, root: Path):
        self.root, self._idx = Path(root), None

    def template(self, run_id):
        if not run_id or str(run_id) in ('nan', 'None'):
            return None
        if self._idx is None:
            self._idx = {}
            if self.root.exists():
                for dirpath, _, files in os.walk(self.root):
                    if 'final_report.json' in files:
                        self._idx.setdefault(Path(dirpath).name, Path(dirpath) / 'final_report.json')
        p = self._idx.get(str(run_id))
        if p is None:
            return None
        try:
            return json.loads(p.read_text()).get('final_template')
        except Exception:
            return None


def _blank(v) -> bool:
    return v is None or (isinstance(v, float) and v != v) or str(v).strip().lower() in ('', 'nan', 'none', 'null')


def detect_lang(gt_path: str) -> str | None:
    s = str(gt_path)
    if s.startswith('cfn_templates') or s.endswith(('.yaml', '.yml', '.json', '.template')):
        return 'cfn'
    if 'iac_benchmark' in s or 'scenarios' in s:
        return 'tf'
    return None


def spec_usable(lang: str, row: int, infos: dict, allow_invalid=False) -> tuple[bool, str]:
    sp, vp = ic.spec_path(lang, row), ic.validation_path(lang, row)
    if not sp.exists():
        return False, 'no spec'
    if allow_invalid:
        ic.generate_policy(lang, row)
        return True, ''
    if not vp.exists():
        return False, 'spec never validated'
    v = json.loads(vp.read_text())
    info = infos[(lang, row)]
    if v.get('status') != 'valid':
        return False, 'spec validation failed'
    if v.get('gt_hash') != info['gt_hash'] or v.get('prompt_hash') != info['prompt_hash']:
        return False, 'spec stale (GT or prompt changed since validation)'
    if v.get('fixture_hash') != ic.fixture_hash(lang, row):
        return False, 'validation stale (fixture/adapter changed since validation) -- re-run validate'
    if not ic.policy_path(lang, row).exists():
        ic.generate_policy(lang, row)
    return True, ''


def normalize_plan_only(lang: str, template) -> dict:
    if lang != 'tf':
        return ic.normalize_candidate(lang, template)
    if _blank(template):
        raise ValueError('empty template')
    t = ic.strip_fences(str(template)).strip()
    key = ic.sha(f'tf\nv{ic.ADAPTER_VERSION}\n{t}')
    cp = ic.CACHE / 'candidates' / 'tf' / f'{key}.json'
    if cp.exists():
        inp = json.loads(cp.read_text())
        if inp['meta'].get('mode') == 'plan':
            return inp
    inp = ic.normalize_tf({'main.tf': t}, allow_static=False)
    inp['meta']['cache_key'] = key
    cp.parent.mkdir(parents=True, exist_ok=True)
    cp.write_text(json.dumps(inp, default=str))
    return inp


def audit(df: pd.DataFrame, condition: str, lang_override=None, scope='all',
          reports_dir: Path = DEFAULT_REPORTS_DIR, allow_invalid=False) -> pd.DataFrame:
    reports = ReportIndex(reports_dir)
    scope_set = set(ic.scope_rows()) if scope == 'ablation' else None
    fulls = {l: ic.load_full_benchmark(l) for l in ic.LANGS}
    infos, out = {}, []
    for _, r in df.iterrows():
        row = int(float(r['row_number']))
        lang = lang_override or detect_lang(r.get('ground_truth_path', ''))
        rec = {'condition': condition, 'lang': lang, 'row_number': row}
        if 'final_validation_passed' in r:
            rec['final_validation_passed'] = r['final_validation_passed']
        if lang is None:
            out.append({**rec, 'intent_status': 'no_spec', 'error': 'cannot detect language'})
            continue
        if scope_set is not None and (lang, row) not in scope_set:
            continue
        if (lang, row) not in infos:
            try:
                infos[(lang, row)] = ic.scenario_info(lang, row, fulls[lang])
            except KeyError as e:
                out.append({**rec, 'intent_status': 'no_spec', 'error': str(e)})
                continue
        rec['difficulty'] = infos[(lang, row)]['difficulty']
        ok, why = spec_usable(lang, row, infos, allow_invalid)
        if not ok:
            out.append({**rec, 'intent_status': 'no_spec', 'error': why})
            continue
        spec = json.loads(ic.spec_path(lang, row).read_text())
        template, rec['template_source'] = r.get('final_template'), 'csv'
        if _blank(template):
            template = reports.template(r.get('run_id'))
            rec['template_source'] = 'final_report' if not _blank(template) else 'missing'
        try:
            inp = normalize_plan_only(lang, template)
            results = ic.opa_eval(lang, row, inp, 'results')
        except Exception as e:
            s = ic.score(spec, {})
            out.append({**rec, 'intent_status': 'unevaluable', 'error': str(e)[:500], **s,
                        'failed_checks': ';'.join(s['failed_checks'])})
            continue
        s = ic.score(spec, results)
        out.append({**rec, 'intent_status': 'evaluated', 'eval_mode': inp['meta']['mode'],
                    'candidate_key': inp['meta'].get('cache_key'),
                    'eval_warnings': ' | '.join(inp['meta'].get('warnings', []))[:500], **s,
                    'failed_checks': ';'.join(s['failed_checks'])})
        print(f"[{condition}] {lang} {row:>3}: {s['n_core_pass']}/{s['n_core']} core, "
              f"{s['n_pass']}/{s['n_checks']} all ({inp['meta']['mode']})", flush=True)
    return pd.DataFrame(out)


def summarise(res: pd.DataFrame) -> pd.DataFrame:
    scored = res[res['intent_status'].isin(['evaluated', 'unevaluable'])]
    if scored.empty:
        return pd.DataFrame()
    g = scored.groupby(['condition', 'lang'])
    return pd.DataFrame({
        'n_scored': g.size(),
        'n_unevaluable': g['intent_status'].apply(lambda s: (s == 'unevaluable').sum()),
        'intent_strict_rate': g['intent_strict'].mean(),
        'mean_core_score': g['core_score'].mean(),
        'mean_intent_score': g['intent_score'].mean(),
        'mean_resource_score': g['resource_score'].mean(),
        'mean_attribute_score': g['attribute_score'].mean(),
        'mean_relationship_score': g['relationship_score'].mean(),
    }).reset_index()


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--input', required=True, nargs='+')
    p.add_argument('--condition', required=True, help='label, e.g. baseline / no-planner / no-hyde / no-remediator')
    p.add_argument('--lang', choices=ic.LANGS)
    p.add_argument('--scope', choices=['all', 'ablation'], default='ablation')
    p.add_argument('--output-csv')
    p.add_argument('--allow-invalid', action='store_true',
                   help='REVIEW ONLY: score with specs that are not (freshly) valid -- never for reported numbers')
    p.add_argument('--reports-dir', default=str(DEFAULT_REPORTS_DIR),
                   help='where <run_id>/final_report.json live (fallback when final_template is blank)')
    a = p.parse_args()
    frames = [pd.read_csv(f, engine='python') for f in a.input]
    df = pd.concat(frames, ignore_index=True)
    res = audit(df, a.condition, a.lang, a.scope, Path(a.reports_dir), a.allow_invalid)
    out = Path(a.output_csv) if a.output_csv else Path(a.input[0]).with_name(
        Path(a.input[0]).stem + f'_intent_{a.condition}.csv')
    res.to_csv(out, index=False)
    print(f'\nwrote {len(res)} rows -> {out}')
    print(summarise(res).to_string(index=False))
    if 'template_source' in res:
        print('template source:', res['template_source'].value_counts().to_dict())
    miss = res[res['intent_status'] == 'no_spec']
    if len(miss):
        print(f'\n{len(miss)} row(s) not scored: {miss["error"].value_counts().to_dict()}')


if __name__ == '__main__':
    main()
