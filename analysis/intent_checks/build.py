#!/usr/bin/env python3
import argparse
import json
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import intent_core as ic


def _infos(lang=None, rows=None):
    fulls = {l: ic.load_full_benchmark(l) for l in ic.LANGS}
    out = []
    for l, r in ic.scope_rows():
        if lang and l != lang:
            continue
        if rows and r not in rows:
            continue
        out.append(ic.scenario_info(l, r, fulls[l]))
    return out


def write_manifest(infos):
    recs = []
    for i in infos:
        vp = ic.validation_path(i['lang'], i['row_number'])
        v = json.loads(vp.read_text()) if vp.exists() else {}
        vstate = v.get('status', 'not_run')
        if v and (v.get('gt_hash') != i['gt_hash'] or v.get('prompt_hash') != i['prompt_hash']
                  or v.get('fixture_hash') != ic.fixture_hash(i['lang'], i['row_number'])):
            vstate = 'stale'
        fx = ic.fixture_path(i['lang'], i['row_number'])
        fstate = 'missing'
        if fx.exists():
            m = json.loads(fx.read_text())['meta']
            fstate = 'ok' if (m.get('gt_hash') == i['gt_hash']
                              and m.get('adapter_version') == ic.ADAPTER_VERSION) else 'stale'
        recs.append({'lang': i['lang'], 'row_number': i['row_number'], 'difficulty': i['difficulty'],
                     'ground_truth_path': i['ground_truth_path'], 'gt_hash': i['gt_hash'][:16],
                     'prompt_hash': i['prompt_hash'][:16], 'fixture': fstate, 'spec': ic.spec_state(i),
                     'validation': vstate, 'n_checks': v.get('n_checks'), 'n_core': v.get('n_core'),
                     'cross_collisions': len(v.get('cross_all_core_pass', []) or [])})
    df = pd.DataFrame(recs).sort_values(['lang', 'row_number'])
    df.to_csv(ic.MANIFEST, index=False)
    return df


def cmd_sync(a):
    infos = _infos(a.lang, a.rows)
    for i in infos:
        st, msg = ic.build_fixture(i, force=a.force)
        if st != 'cached':
            print(f"{ic.tag(i['lang'], i['row_number'])}: fixture {st} {msg[:400]}")
    df = write_manifest(_infos())
    print(df.groupby(['lang', 'fixture', 'spec']).size().to_string())


def cmd_add(a):
    ic.add_to_scope(a.lang, a.rows)
    print(f'added {a.lang} {a.rows} to {ic.EXTRA_SCOPE.name}; run `sync` next')


def cmd_pending(a):
    for i in _infos(a.lang):
        st = ic.spec_state(i)
        if st != 'ok':
            print(f"{i['lang']} {i['row_number']} L{i['difficulty']} spec={st}")


def cmd_show(a):
    i = ic.scenario_info(a.lang, a.row)
    print(f"# {i['lang']} row {i['row_number']}  L{i['difficulty']}  {i['ground_truth_path']}")
    print(f"# source_hash: gt={i['gt_hash']} prompt={i['prompt_hash']}\n")
    print('PROMPT:\n' + i['prompt'] + '\n')
    fx = ic.fixture_path(a.lang, a.row)
    if not fx.exists():
        print('(no fixture -- run sync)')
        return
    inp = json.loads(fx.read_text())
    print(f"FIXTURE mode={inp['meta']['mode']} warnings={inp['meta']['warnings'][:3]}")
    for r in inp['resources']:
        v = json.dumps(r['values'], default=str)
        print(f"- {r['id']}  [{r['type']}]  refs={r['refs']}\n    {v[:a.width]}{'...' if len(v) > a.width else ''}")


def cmd_validate(a):
    infos = [i for i in _infos(a.lang, a.rows) if ic.spec_path(i['lang'], i['row_number']).exists()]
    cross = {}
    if not a.no_cross:
        for i in _infos():
            fx = ic.fixture_path(i['lang'], i['row_number'])
            if fx.exists():
                cross.setdefault(i['lang'], {})[ic.tag(i['lang'], i['row_number'])] = json.loads(fx.read_text())
    for i in infos:
        rep = ic.validate(i['lang'], i['row_number'], i, cross.get(i['lang']))
        flag = '✅' if rep['status'] == 'valid' else '❌'
        extra = []
        if rep['structural']:
            extra.append(f"structural={rep['structural']}")
        if rep['positive_fail']:
            extra.append(f"GT fails={rep['positive_fail']}")
        if rep['mutation_survivors']:
            extra.append(f"mutation survivors={rep['mutation_survivors']}")
        unj = [f for f in rep.get('strictness_flags', []) if not f['justified']]
        if unj:
            extra.append('NOT IN PROMPT (remove or add "justify"): ' + '; '.join(
                f"{f['check']}:{f['op']}={json.dumps(f['value'])[:60]}" for f in unj))
        if rep.get('vacuous_on_empty'):
            extra.append(f"core checks pass on EMPTY template={rep['vacuous_on_empty']}")
        if rep['cross_all_core_pass']:
            extra.append(f"(warn) other GTs pass all core: {rep['cross_all_core_pass']}")
        print(f"{flag} {ic.tag(i['lang'], i['row_number'])} checks={rep['n_checks']} core={rep['n_core']} "
              + ' | '.join(extra))
    if not a.rows:
        write_manifest(_infos())


def cmd_explain(a):
    res = pd.read_csv(a.result_csv)
    row = res[(res['lang'] == a.lang) & (res['row_number'] == a.row)]
    if row.empty:
        raise SystemExit('row not in result csv')
    row = row.iloc[0]
    print(f"# {a.lang} row {a.row}: status={row['intent_status']} core {row.get('n_core_pass')}/{row.get('n_core')}"
          f" all {row.get('n_pass')}/{row.get('n_checks')}")
    key = row.get('candidate_key')
    if not isinstance(key, str):
        print('no normalised candidate (unevaluable):', row.get('error'))
        return
    inp = json.loads((ic.CACHE / 'candidates' / a.lang / f'{key}.json').read_text())
    spec = json.loads(ic.spec_path(a.lang, a.row).read_text())
    failed = [c for c in spec['checks'] if c['id'] in str(row.get('failed_checks') or '').split(';')]
    sels = spec.get('selectors') or {}
    for c in failed:
        print(f"\n✗ {c['id']} [{c['tier']}]  quote: {c['quote']!r}")
        print('  check:', json.dumps({k: v for k, v in c.items() if k not in ('id', 'tier', 'quote')})[:a.width])
        types = set()
        for l in (c.get('checks') or [c]):
            for k in ('select', 'from', 'to'):
                sel = l.get(k)
                sel = sels.get(sel, {}) if isinstance(sel, str) else (sel or {})
                types |= set(sel.get('types', []))
        hits = [r for r in inp['resources'] if r['type'] in types]
        if not hits:
            print(f"  candidate has NO resource of type {sorted(types)}")
        for r in hits[:4]:
            print(f"  candidate {r['id']} [{r['type']}] refs={r['refs']}\n    {json.dumps(r['values'], default=str)[:a.width]}")
    print(f"\n(all candidate resource types: {sorted({r['type'] for r in inp['resources'] if not r['type'].startswith('__')})})")


def cmd_status(a):
    df = write_manifest(_infos())
    print(df.groupby(['lang', 'spec', 'validation']).size().to_string())
    bad = df[(df['spec'] != 'ok') | (df['validation'] != 'valid')]
    if len(bad):
        print('\nnot yet valid:')
        print(bad[['lang', 'row_number', 'difficulty', 'fixture', 'spec', 'validation']].to_string(index=False))


def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('sync'); s.add_argument('--lang'); s.add_argument('--rows', type=int, nargs='*')
    s.add_argument('--force', action='store_true'); s.set_defaults(fn=cmd_sync)
    s = sub.add_parser('add'); s.add_argument('lang', choices=ic.LANGS); s.add_argument('rows', type=int, nargs='+')
    s.set_defaults(fn=cmd_add)
    s = sub.add_parser('pending'); s.add_argument('--lang'); s.set_defaults(fn=cmd_pending)
    s = sub.add_parser('show'); s.add_argument('lang', choices=ic.LANGS); s.add_argument('row', type=int)
    s.add_argument('--width', type=int, default=600); s.set_defaults(fn=cmd_show)
    s = sub.add_parser('validate'); s.add_argument('--lang'); s.add_argument('--rows', type=int, nargs='*')
    s.add_argument('--no-cross', action='store_true'); s.set_defaults(fn=cmd_validate)
    s = sub.add_parser('status'); s.set_defaults(fn=cmd_status)
    s = sub.add_parser('explain'); s.add_argument('lang', choices=ic.LANGS); s.add_argument('row', type=int)
    s.add_argument('--result-csv', required=True); s.add_argument('--width', type=int, default=700)
    s.set_defaults(fn=cmd_explain)
    a = p.parse_args()
    a.fn(a)


if __name__ == '__main__':
    main()
