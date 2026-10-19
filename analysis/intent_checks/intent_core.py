from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
DA = ROOT.parent
IACGOD_DATA = (DA / '../data').resolve()

LIB_REGO = ROOT / 'lib' / 'intent.rego'
SPECS = ROOT / 'specs'
POLICIES = ROOT / 'policies'
FIXTURES = ROOT / 'fixtures'
VALIDATION = ROOT / 'validation'
CACHE = ROOT / 'cache'
MANIFEST = ROOT / 'manifest.csv'
EXTRA_SCOPE = ROOT / 'scope_extra.csv'

LANGS = ('cfn', 'tf')
FULL_EVAL = {'cfn': IACGOD_DATA / 'cfn_eval_benchmark_real_aws.csv',
             'tf': IACGOD_DATA / 'tf_eval_benchmark_real_aws.csv'}
ABLATION_EVAL = {'cfn': DA / 'ablation_selection' / 'cfn_eval_benchmark_ablation.csv',
                 'tf': DA / 'ablation_selection' / 'tf_eval_benchmark_ablation.csv'}
CFN_BASE = DA / 'cfn_benchmark'
TF_PLUGIN_CACHE = DA / 'iac_benchmark' / '.tf_plugin_cache'
LOCALSTACK = os.environ.get('LOCALSTACK_ENDPOINT', 'http://localhost:4566')

ADAPTER_VERSION = 8

CHECK_KINDS = {'exists', 'attr', 'ref', 'join', 'any_of', 'all_of'}
LEAF_KINDS = {'exists', 'attr', 'ref', 'join'}
OPS = {'eq', 'neq', 'in', 'contains', 'regex', 'gte', 'lte', 'present', 'truthy', 'falsy',
       'len_gte', 'len_eq', 'has_kv', 'port_covers', 'absent', 'match', 'none_eq', 'glob_covers'}
TIERS = {'core', 'detail'}


def tag(lang: str, row: int) -> str:
    return f'{lang}/row_{int(row):03d}'


def spec_path(lang, row): return SPECS / f'{tag(lang, row)}.json'
def policy_path(lang, row): return POLICIES / f'{tag(lang, row)}.rego'
def fixture_path(lang, row): return FIXTURES / f'{tag(lang, row)}.input.json'
def validation_path(lang, row): return VALIDATION / f'{tag(lang, row)}.json'
def package_name(lang, row): return f'intent.{lang}.row_{int(row):03d}'


def sha(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def declared(rtype: str, name: str, gated: bool, detail=None, properties=None, cfg=None, refs=None) -> dict:
    rid = f'__declared__.{rtype}.{name}'
    return {'id': rid, 'cfg': cfg or rid, 'type': '__declared__', 'refs': sorted(refs or []),
            'values': {'type': rtype, 'name': name, 'gated': gated, 'gate': detail,
                       'properties': properties if properties is not None else {}}}


def load_full_benchmark(lang: str) -> pd.DataFrame:
    df = pd.read_csv(FULL_EVAL[lang])
    df['row_number'] = df['row_number'].astype(int)
    return df


def scope_rows() -> list[tuple[str, int]]:
    rows = set()
    for lang in LANGS:
        if ABLATION_EVAL[lang].exists():
            rows |= {(lang, int(r)) for r in pd.read_csv(ABLATION_EVAL[lang])['row_number']}
    if EXTRA_SCOPE.exists():
        ex = pd.read_csv(EXTRA_SCOPE)
        rows |= {(str(l), int(r)) for l, r in zip(ex['lang'], ex['row_number'])}
    return sorted(rows)


def add_to_scope(lang: str, rows: list[int]):
    ex = pd.read_csv(EXTRA_SCOPE) if EXTRA_SCOPE.exists() else pd.DataFrame(columns=['lang', 'row_number'])
    full = set(load_full_benchmark(lang)['row_number'])
    missing = [r for r in rows if r not in full]
    if missing:
        raise SystemExit(f'{lang} row(s) {missing} are not in {FULL_EVAL[lang].name}')
    add = pd.DataFrame({'lang': lang, 'row_number': rows})
    pd.concat([ex, add]).drop_duplicates().sort_values(['lang', 'row_number']).to_csv(EXTRA_SCOPE, index=False)


def gt_files(lang: str, gt_path: str) -> dict[str, str]:
    if lang == 'cfn':
        p = CFN_BASE / gt_path
        return {p.name: p.read_text(encoding='utf-8', errors='ignore')}
    folder = DA / gt_path
    return {f.name: f.read_text(encoding='utf-8', errors='ignore') for f in sorted(folder.glob('*.tf'))}


def gt_hash(files: dict[str, str]) -> str:
    return sha(''.join(f'--{n}--\n{t}' for n, t in sorted(files.items())))


def scenario_info(lang: str, row: int, full: pd.DataFrame | None = None) -> dict:
    full = full if full is not None else load_full_benchmark(lang)
    rec = full[full['row_number'] == int(row)]
    if rec.empty:
        raise KeyError(f'{lang} row {row} not in the full benchmark')
    rec = rec.iloc[0]
    files = gt_files(lang, rec['ground_truth_path'])
    return {'lang': lang, 'row_number': int(row), 'difficulty': int(rec['difficulty']),
            'ground_truth_path': rec['ground_truth_path'], 'prompt': rec['prompt'],
            'gt_hash': gt_hash(files), 'prompt_hash': sha(str(rec['prompt'])), 'files': files}


def spec_state(info: dict) -> str:
    p = spec_path(info['lang'], info['row_number'])
    if not p.exists():
        return 'missing'
    spec = json.loads(p.read_text())
    src = spec.get('source_hash', {})
    if src.get('gt') != info['gt_hash'] or src.get('prompt') != info['prompt_hash']:
        return 'stale'
    return 'ok'


PSEUDO = {'AWS::Region': 'us-east-1', 'AWS::AccountId': '123456789012', 'AWS::StackName': 'stack',
          'AWS::StackId': 'arn:aws:cloudformation:us-east-1:123456789012:stack/stack/id',
          'AWS::Partition': 'aws', 'AWS::URLSuffix': 'amazonaws.com', 'AWS::NotificationARNs': []}
NOVALUE = object()


class _AnyPolicyMap(dict):
    def __contains__(self, k): return True
    def __getitem__(self, k): return f'arn:aws:iam::aws:policy/{k}'
    def get(self, k, d=None): return self[k]


class _PolicyLoader:
    def load(self): return _AnyPolicyMap()


def _cfn_decode(text: str) -> dict:
    from cfnlint.decode import decode_str
    tpl, matches = decode_str(text)
    if tpl is None:
        raise ValueError(f'CFN parse error: {matches[:1]}')
    return json.loads(json.dumps(tpl, default=str))


def _param_default(p: dict):
    if 'Default' not in p:
        return None
    d = p['Default']
    t = str(p.get('Type', ''))
    if isinstance(d, str) and (t == 'CommaDelimitedList' or t.startswith('List<')):
        return [x.strip() for x in d.split(',')]
    return d


def _sam_expand(tpl: dict, params: dict) -> dict:
    from samtranslator.translator.transform import transform
    tpl = copy.deepcopy(tpl)
    for r in tpl.get('Resources', {}).values():
        props = r.get('Properties') or {}
        for k in ('CodeUri', 'ContentUri', 'DefinitionUri'):
            if isinstance(props.get(k), str) and not props[k].startswith('s3://'):
                props[k] = f's3://placeholder-bucket/{props[k].strip("./") or "code"}'
    pv = {**{k: v for k, v in params.items() if v is not None}, **PSEUDO}
    return transform(tpl, pv, _PolicyLoader())


class _CfnCtx:
    def __init__(self, tpl):
        self.params = {n: _param_default(p or {}) for n, p in (tpl.get('Parameters') or {}).items()}
        self.resources = set((tpl.get('Resources') or {}).keys())
        self.mappings = tpl.get('Mappings') or {}
        self.conditions = tpl.get('Conditions') or {}
        self._cond_cache = {}
        self.refs = set()

    def cond(self, name, depth=0):
        if name in self._cond_cache:
            return self._cond_cache[name]
        if name not in self.conditions or depth > 20:
            return True
        self._cond_cache[name] = True
        v = self._eval_cond(self.conditions[name], depth)
        self._cond_cache[name] = True if v is None else bool(v)
        return self._cond_cache[name]

    def _eval_cond(self, c, depth):
        if not isinstance(c, dict) or len(c) != 1:
            return None
        k, v = next(iter(c.items()))
        if k == 'Condition':
            return self.cond(v, depth + 1)
        if k == 'Fn::Equals':
            a, b = (self.resolve(x) for x in v)
            if isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
                return None
            return str(a) == str(b)
        if k == 'Fn::Not':
            r = self._eval_cond(v[0], depth + 1)
            return None if r is None else not r
        if k in ('Fn::And', 'Fn::Or'):
            rs = [self._eval_cond(x, depth + 1) for x in v]
            if None in rs:
                return None
            return all(rs) if k == 'Fn::And' else any(rs)
        return None

    def _ref(self, name):
        if name in PSEUDO:
            return PSEUDO[name]
        if name == 'AWS::NoValue':
            return NOVALUE
        if name in self.params:
            d = self.params[name]
            return f'<param:{name}>' if d is None else d
        if name in self.resources:
            self.refs.add(name)
        return {'ref': name}

    def _sub(self, s, local):
        def repl(m):
            key = m.group(1)
            if key.startswith('!'):
                return '${' + key[1:] + '}'
            if key in local:
                return str(local[key])
            base = key.split('.')[0]
            if key in PSEUDO:
                return str(PSEUDO[key])
            if key in self.params:
                d = self.params[key]
                return f'<param:{key}>' if d is None else (','.join(map(str, d)) if isinstance(d, list) else str(d))
            if base in self.resources:
                self.refs.add(base)
            return '${' + key + '}'
        return re.sub(r'\$\{([^}]+)\}', repl, s)

    def resolve(self, v):
        if isinstance(v, list):
            out = [self.resolve(x) for x in v]
            return [x for x in out if x is not NOVALUE]
        if not isinstance(v, dict):
            return v
        if len(v) == 1:
            k, a = next(iter(v.items()))
            if k == 'Ref':
                return self._ref(a)
            if k == 'Fn::GetAtt':
                parts = a.split('.', 1) if isinstance(a, str) else a
                if parts and isinstance(parts[0], str):
                    if parts[0] in self.resources:
                        self.refs.add(parts[0])
                    return {'ref': parts[0], 'attr': parts[1] if len(parts) > 1 else None}
            if k == 'Fn::Sub':
                if isinstance(a, str):
                    return self._sub(a, {})
                if isinstance(a, list) and a and isinstance(a[0], str):
                    local = {n: self.resolve(x) for n, x in (a[1] if len(a) > 1 else {}).items()}
                    return self._sub(a[0], local)
            if k == 'Fn::Join' and isinstance(a, list) and len(a) == 2:
                parts = self.resolve(a[1])
                if isinstance(parts, list) and all(isinstance(x, (str, int, float)) for x in parts):
                    return str(a[0]).join(str(x) for x in parts)
                return {'Fn::Join': [a[0], parts]}
            if k == 'Fn::If' and isinstance(a, list) and len(a) == 3:
                return self.resolve(a[1] if self.cond(a[0]) else a[2])
            if k == 'Fn::Select' and isinstance(a, list) and len(a) == 2:
                idx, lst = self.resolve(a[0]), self.resolve(a[1])
                try:
                    return lst[int(idx)]
                except Exception:
                    return {'Fn::Select': [idx, lst]}
            if k == 'Fn::GetAZs':
                return ['us-east-1a', 'us-east-1b', 'us-east-1c']
            if k == 'Fn::FindInMap' and isinstance(a, list) and len(a) >= 3:
                keys = [self.resolve(x) for x in a[:3]]
                try:
                    return self.resolve(self.mappings[keys[0]][keys[1]][keys[2]])
                except Exception:
                    return {'Fn::FindInMap': keys}
            if k == 'Fn::Split' and isinstance(a, list) and len(a) == 2:
                s = self.resolve(a[1])
                return s.split(a[0]) if isinstance(s, str) else {'Fn::Split': [a[0], s]}
            if k == 'Fn::Base64':
                return self.resolve(a)
            if k == 'Fn::ImportValue':
                return {'import': self.resolve(a)}
        out = {}
        for k, x in v.items():
            r = self.resolve(x)
            if r is not NOVALUE:
                out[k] = r
        return out


_IAM_LIST_KEYS = ('Action', 'NotAction', 'Resource', 'NotResource')


def canonical_iam(v):
    if isinstance(v, list):
        return [canonical_iam(x) for x in v]
    if not isinstance(v, dict):
        return v
    out = {k: canonical_iam(x) for k, x in v.items()}
    if 'Statement' in out and isinstance(out['Statement'], dict):
        out['Statement'] = [out['Statement']]
    if 'Effect' in out:
        for k in _IAM_LIST_KEYS:
            if isinstance(out.get(k), str):
                out[k] = [out[k]]
        for pk in ('Principal', 'NotPrincipal'):
            if isinstance(out.get(pk), dict):
                out[pk] = {t: ([x] if isinstance(x, str) else x) for t, x in out[pk].items()}
    return out


def normalize_cfn(text: str) -> dict:
    tpl = _cfn_decode(text)
    if not isinstance(tpl, dict) or not isinstance(tpl.get('Resources'), dict):
        raise ValueError('not a CloudFormation template (no Resources mapping)')
    meta = {'lang': 'cfn', 'mode': 'parsed', 'warnings': []}
    transforms = tpl.get('Transform') or []
    transforms = [transforms] if isinstance(transforms, str) else transforms
    if any('Serverless' in str(t) for t in transforms):
        params = {n: _param_default(p or {}) for n, p in (tpl.get('Parameters') or {}).items()}
        try:
            tpl = _sam_expand(tpl, params)
            meta['mode'] = 'sam_expanded'
        except Exception as e:
            meta['warnings'].append(f'SAM expansion failed: {str(e)[:300]}')
    ctx = _CfnCtx(tpl)
    resources, decl = [], []
    for lid, r in (tpl.get('Resources') or {}).items():
        if not isinstance(r, dict):
            continue
        ctx.refs = set()
        dprops = canonical_iam(ctx.resolve(r.get('Properties') or {}))
        decl.append(declared(r.get('Type', ''), lid, bool(r.get('Condition')), r.get('Condition'),
                             dprops, cfg=lid, refs=ctx.refs - {lid}))
        if r.get('Condition') and not ctx.cond(r['Condition']):
            meta['warnings'].append(f'{lid} excluded: condition {r["Condition"]} false under defaults')
            continue
        ctx.refs = set()
        values = canonical_iam(ctx.resolve(r.get('Properties') or {}))
        rattrs = {k: r[k] for k in ('DeletionPolicy', 'UpdateReplacePolicy', 'UpdatePolicy',
                                     'CreationPolicy', 'Condition') if k in r}
        if 'DependsOn' in r:
            rattrs['DependsOn'] = [r['DependsOn']] if isinstance(r['DependsOn'], str) else r['DependsOn']
        if 'Metadata' in r:
            rattrs['Metadata'] = ctx.resolve(r['Metadata'])
        if rattrs and isinstance(values, dict):
            values['__resource__'] = rattrs
        refs = sorted(ctx.refs - {lid})
        resources.append({'id': lid, 'cfg': lid, 'type': r.get('Type', ''), 'values': values, 'refs': refs})
    for name, p in (tpl.get('Parameters') or {}).items():
        p = p or {}
        resources.append({'id': f'__parameter__.{name}', 'cfg': f'__parameter__.{name}', 'type': '__parameter__',
                          'values': {'name': name, 'type': p.get('Type'), 'default': _param_default(p),
                                     'allowed_values': p.get('AllowedValues')}, 'refs': []})
    for name, o in (tpl.get('Outputs') or {}).items():
        if not isinstance(o, dict):
            continue
        if o.get('Condition') and not ctx.cond(o['Condition']):
            continue
        ctx.refs = set()
        val = ctx.resolve(o.get('Value'))
        resources.append({'id': f'__output__.{name}', 'cfg': f'__output__.{name}', 'type': '__output__',
                          'values': {'name': name, 'value': val, 'description': o.get('Description'),
                                     'export': ctx.resolve((o.get('Export') or {}).get('Name'))},
                          'refs': sorted(ctx.refs)})
    return {'meta': meta, 'resources': resources + decl}


def _strip_block(text: str, header_re: str) -> str:
    out, pos = [], 0
    for m in re.finditer(header_re, text):
        if m.start() < pos:
            continue
        i, depth = m.end(), 1
        while i < len(text) and depth:
            depth += {'{': 1, '}': -1}.get(text[i], 0)
            i += 1
        out.append(text[pos:m.start()])
        pos = i
    out.append(text[pos:])
    return ''.join(out)


def _prepare_tf(files: dict[str, str]) -> dict[str, str]:
    return {n: _strip_block(_strip_block(t, r'\bbackend\s+"[^"]*"\s*\{'), r'\bcloud\s*\{')
            for n, t in files.items()}


def tf_env() -> dict:
    env = os.environ.copy()
    env.update({'AWS_ACCESS_KEY_ID': 'test', 'AWS_SECRET_ACCESS_KEY': 'test', 'AWS_DEFAULT_REGION': 'us-east-1',
                'AWS_REGION': 'us-east-1', 'TF_PLUGIN_CACHE_DIR': str(TF_PLUGIN_CACHE),
                'TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE': 'true', 'TF_IN_AUTOMATION': '1',
                'GIT_TERMINAL_PROMPT': '0', 'PATH': f"/opt/homebrew/bin:{env.get('PATH', '')}"})
    env.pop('AWS_PROFILE', None)
    return env


def _run(cmd, cwd, timeout):
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout, env=tf_env())
    return r.returncode, (r.stdout or '') + (r.stderr or '')


def tf_plan_json(files: dict[str, str]) -> tuple[dict | None, str]:
    with tempfile.TemporaryDirectory() as d:
        for n, t in _prepare_tf(files).items():
            Path(d, n).write_text(t, encoding='utf-8')
        try:
            rc, log = _run(['tflocal', 'init', '-backend=false', '-input=false', '-no-color'], d, 900)
            if rc != 0:
                return None, 'init: ' + log[-2000:]
            rc, log = _run(['tflocal', 'plan', '-input=false', '-no-color', '-lock=false', '-out=tfplan'], d, 900)
            if rc != 0:
                return None, 'plan: ' + log[-2000:]
            rc, out = _run(['tflocal', 'show', '-json', 'tfplan'], d, 300)
            if rc != 0:
                return None, 'show: ' + out[-2000:]
            return json.loads(out[out.index('{'):]), ''
        except subprocess.TimeoutExpired as e:
            return None, f'timeout: {e.cmd}'


_REF_RE = re.compile(r'\b((?:data\.)?[a-z][a-z0-9]*_[a-z0-9_]+\.[A-Za-z_][\w-]*|module\.[\w-]+\.[\w-]+|var\.[\w-]+|local\.[\w-]+)')


def _hcl_locals(files: dict[str, str]) -> dict[str, list[str]]:
    out = {}
    for t in files.values():
        for m in re.finditer(r'\blocals\s*\{', t):
            i, depth = m.end(), 1
            while i < len(t) and depth:
                depth += {'{': 1, '}': -1}.get(t[i], 0)
                i += 1
            body = t[m.end():i - 1]
            for am in re.finditer(r'^\s*([A-Za-z_][\w-]*)\s*=', body, re.M):
                nxt = re.search(r'^\s*[A-Za-z_][\w-]*\s*=', body[am.end():], re.M)
                expr = body[am.end(): am.end() + (nxt.start() if nxt else len(body))]
                out[am.group(1)] = _REF_RE.findall(expr)
    return out


def tf_declared(files: dict[str, str]) -> list[dict]:
    try:
        doc, _, _ = _tf_static_doc(files)
        bodies = {(t, n): b for block in doc['resource'] for t, named in block.items() for n, b in named.items()}
        bodies.update({('data.' + t, n): b for block in doc['data'] for t, named in block.items()
                       for n, b in named.items()})
    except Exception:
        bodies = {}
    out = []
    locals_ = _hcl_locals(files)
    for t in files.values():
        for m in re.finditer(r'^\s*(resource|data)\s+"([^"]+)"\s+"([^"]+)"\s*\{', t, re.M):
            i, depth = m.end(), 1
            while i < len(t) and depth:
                depth += {'{': 1, '}': -1}.get(t[i], 0)
                i += 1
            gate = re.search(r'^\s*(count|for_each)\s*=\s*(.+)$', t[m.end():i], re.M)
            rtype = m.group(2) if m.group(1) == 'resource' else f'data.{m.group(2)}'
            body = bodies.get((rtype, m.group(3)), {})
            cfgaddr = f'{rtype}.{m.group(3)}'
            refs = _static_refs(body, locals_) if body else set(
                '.'.join(x.split('.')[:3 if x.startswith('data.') else 2])
                for x in _REF_RE.findall(t[m.end():i]) if not x.startswith(('var.', 'local.', 'module.')))
            out.append(declared(rtype, m.group(3), bool(gate), gate.group(2).strip()[:200] if gate else None,
                                body, cfg=cfgaddr, refs=refs - {cfgaddr}))
    return out


def _collect_refs(expr) -> list[str]:
    out = []
    if isinstance(expr, dict):
        for k, v in expr.items():
            if k == 'references' and isinstance(v, list):
                out += [x for x in v if isinstance(x, str)]
            else:
                out += _collect_refs(v)
    elif isinstance(expr, list):
        for x in expr:
            out += _collect_refs(x)
    return out


class _TfRefResolver:
    def __init__(self, config: dict, locals_: dict[str, list[str]]):
        self.inputs, self.outputs, self.res_raw = {}, {}, {}
        self.locals = locals_
        self._walk(config.get('root_module', {}), '')

    def _walk(self, mod, prefix):
        for r in mod.get('resources', []):
            raw = _collect_refs(r.get('expressions', {}))
            raw += _collect_refs(r.get('count_expression', {})) + _collect_refs(r.get('for_each_expression', {}))
            self.res_raw[prefix + r['address']] = (raw, prefix)
        for name, o in (mod.get('outputs') or {}).items():
            self.outputs[prefix + name] = _collect_refs(o.get('expression', {}))
        for name, mc in (mod.get('module_calls') or {}).items():
            child = f'{prefix}module.{name}.'
            self.inputs[child] = {k: _collect_refs(v) for k, v in (mc.get('expressions') or {}).items()}
            self._walk(mc.get('module', {}), child)

    @staticmethod
    def _parent(prefix):
        parts = prefix.rstrip('.').split('.')
        return '.'.join(parts[:-2]) + '.' if len(parts) > 2 else ''

    def resolve(self, ref: str, prefix: str, depth=0) -> set[str]:
        if depth > 12:
            return set()
        p = ref.split('.')
        if p[0] in ('count', 'each', 'path', 'self', 'terraform'):
            return set()
        if p[0] == 'var' and len(p) > 1:
            if not prefix:
                return set()
            raws = self.inputs.get(prefix, {}).get(p[1], [])
            return set().union(*[self.resolve(x, self._parent(prefix), depth + 1) for x in raws]) if raws else set()
        if p[0] == 'local' and len(p) > 1:
            raws = self.locals.get(p[1], []) if not prefix else []
            return set().union(*[self.resolve(x, prefix, depth + 1) for x in raws]) if raws else set()
        if p[0] == 'module' and len(p) > 2:
            child = f'{prefix}module.{p[1]}.'
            raws = self.outputs.get(child + p[2], [])
            return set().union(*[self.resolve(x, child, depth + 1) for x in raws]) if raws else set()
        if p[0] == 'data' and len(p) > 2:
            return {f'{prefix}data.{p[1]}.{p[2]}'}
        if len(p) >= 2 and '_' in p[0]:
            name = re.sub(r'\[.*', '', p[1])
            return {f'{prefix}{p[0]}.{name}'}
        return set()

    def refs_for(self, cfg_addr: str) -> set[str]:
        raw, prefix = self.res_raw.get(cfg_addr, ([], ''))
        out = set()
        for x in raw:
            out |= self.resolve(x, prefix)
        return out - {cfg_addr}


def _cfg_addr(address: str) -> str:
    return re.sub(r'\[[^\]]*\]', '', address)


def tf_depends_on(files: dict[str, str]) -> dict[str, set[str]]:
    out = {}
    for t in files.values():
        for m in re.finditer(r'^\s*(resource|data)\s+"([^"]+)"\s+"([^"]+)"\s*\{', t, re.M):
            i, depth = m.end(), 1
            while i < len(t) and depth:
                depth += {'{': 1, '}': -1}.get(t[i], 0)
                i += 1
            dm = re.search(r'^\s*depends_on\s*=\s*\[([^\]]*)\]', t[m.end():i], re.M)
            if dm:
                cfg = (m.group(2) if m.group(1) == 'resource' else f'data.{m.group(2)}') + f'.{m.group(3)}'
                out[cfg] = {'.'.join(x.split('.')[:3 if x.startswith('data.') else 2])
                            for x in re.findall(r'[\w.-]+', dm.group(1)) if '.' in x}
    return out


def normalize_tf_plan(plan: dict, files: dict[str, str]) -> dict:
    cfg = plan.get('configuration', {})
    resolver = _TfRefResolver(cfg, _hcl_locals(files))
    deps = tf_depends_on(files)
    resources = []
    for rc in plan.get('resource_changes', []):
        actions = rc.get('change', {}).get('actions', [])
        if actions == ['delete']:
            continue
        mode = rc.get('mode', 'managed')
        ca = _cfg_addr(rc['address'])
        resources.append({'id': rc['address'], 'cfg': ca,
                          'type': rc['type'] if mode == 'managed' else f'data.{rc["type"]}',
                          'values': rc.get('change', {}).get('after') or {},
                          'refs': sorted(resolver.refs_for(ca) | deps.get(ca, set()))})
    for name, v in (plan.get('variables') or {}).items():
        resources.append({'id': f'__parameter__.{name}', 'cfg': f'__parameter__.{name}', 'type': '__parameter__',
                          'values': {'name': name, 'default': v.get('value')}, 'refs': []})
    planned_out = (plan.get('planned_values') or {}).get('outputs') or {}
    for name, o in (cfg.get('root_module', {}).get('outputs') or {}).items():
        refs = set()
        for x in _collect_refs(o.get('expression', {})):
            refs |= resolver.resolve(x, '')
        resources.append({'id': f'__output__.{name}', 'cfg': f'__output__.{name}', 'type': '__output__',
                          'values': {'name': name, 'value': (planned_out.get(name) or {}).get('value'),
                                     'description': o.get('description')},
                          'refs': sorted(refs)})
    return {'meta': {'lang': 'tf', 'mode': 'plan', 'warnings': []}, 'resources': resources + tf_declared(files)}


def _hcl_unwrap(d: dict) -> dict:
    out = {}
    for k, v in d.items():
        if str(k).startswith('__'):
            continue
        if k == 'dynamic' and isinstance(v, list):
            out[k] = {lbl: _hcl_unwrap(body) for e in v if isinstance(e, dict)
                      for lbl, body in e.items() if isinstance(body, dict)}
            continue
        if (isinstance(v, list) and v and all(isinstance(e, dict) for e in v)
                and all(all(isinstance(x, list) for kk, x in e.items() if not str(kk).startswith('__'))
                        for e in v)):
            out[k] = [_hcl_unwrap(e) for e in v]
        elif isinstance(v, list) and len(v) == 1:
            out[k] = v[0]
        else:
            out[k] = v
    return out


def _tf_static_doc(files: dict[str, str]):
    import hcl2
    doc = {'resource': [], 'data': [], 'variable': [], 'output': []}
    warnings = []
    for n, t in files.items():
        try:
            d = hcl2.loads(t)
        except Exception as e:
            warnings.append(f'hcl2 parse failed for {n}: {str(e)[:200]}')
            continue
        for k in doc:
            for block in d.get(k, []):
                doc[k].append({t: ({n: _hcl_unwrap(b) for n, b in named.items()} if k in ('resource', 'data')
                                   else _hcl_unwrap(named))
                               for t, named in block.items()})
    var_defaults = {}
    for block in doc['variable']:
        for name, body in block.items():
            var_defaults[name] = body.get('default')

    def subst(v):
        if isinstance(v, str):
            m = re.fullmatch(r'\$\{var\.([\w-]+)\}', v.strip())
            if m and var_defaults.get(m.group(1)) is not None:
                return var_defaults[m.group(1)]
            return v
        if isinstance(v, list):
            return [subst(x) for x in v]
        if isinstance(v, dict):
            return {k: subst(x) for k, x in v.items()}
        return v

    for mode_key in ('resource', 'data', 'output'):
        doc[mode_key] = [{t: ({n: subst(b) for n, b in named.items()} if mode_key != 'output' else subst(named))
                          for t, named in block.items()} for block in doc[mode_key]]
    return doc, var_defaults, warnings


def _static_refs(body, locals_) -> set[str]:
    refs = set()
    for x in set(_REF_RE.findall(json.dumps(body, default=str))):
        if x.startswith('local.'):
            refs |= {y for y in locals_.get(x.split('.')[1], []) if not y.startswith(('var.', 'local.', 'module.'))}
        elif not x.startswith(('var.', 'module.')):
            refs.add('.'.join(x.split('.')[:3 if x.startswith('data.') else 2]))
    return {'.'.join(r.split('.')[:3 if r.startswith('data.') else 2]) for r in refs}


def normalize_tf_static(files: dict[str, str]) -> dict:
    doc, var_defaults, warnings = _tf_static_doc(files)
    locals_ = _hcl_locals(files)
    resources = []
    for mode_key, prefix in (('resource', ''), ('data', 'data.')):
        for block in doc[mode_key]:
            for rtype, named in block.items():
                for name, body in named.items():
                    cfgaddr = f'{prefix}{rtype}.{name}'
                    resources.append({'id': cfgaddr, 'cfg': cfgaddr, 'type': f'{prefix}{rtype}', 'values': body,
                                      'refs': sorted(_static_refs(body, locals_) - {cfgaddr})})
    for name, d in var_defaults.items():
        resources.append({'id': f'__parameter__.{name}', 'cfg': f'__parameter__.{name}', 'type': '__parameter__',
                          'values': {'name': name, 'default': d}, 'refs': []})
    for block in doc['output']:
        for name, body in block.items():
            resources.append({'id': f'__output__.{name}', 'cfg': f'__output__.{name}', 'type': '__output__',
                              'values': {'name': name, 'value': None, 'description': body.get('description')},
                              'refs': sorted(_static_refs(body, locals_))})
    return {'meta': {'lang': 'tf', 'mode': 'static', 'warnings': warnings},
            'resources': resources + tf_declared(files)}


def normalize_tf(files: dict[str, str], allow_static=True) -> dict:
    plan, err = tf_plan_json(files)
    if plan is not None:
        return normalize_tf_plan(plan, files)
    if not allow_static:
        raise RuntimeError(err)
    out = normalize_tf_static(files)
    out['meta']['warnings'].insert(0, f'plan failed, static fallback: {err[-600:]}')
    return out


def build_fixture(info: dict, force=False) -> tuple[str, str]:
    p = fixture_path(info['lang'], info['row_number'])
    if p.exists() and not force:
        old = json.loads(p.read_text()).get('meta', {})
        if old.get('gt_hash') == info['gt_hash'] and old.get('adapter_version') == ADAPTER_VERSION:
            return 'cached', ''
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        if info['lang'] == 'cfn':
            inp = normalize_cfn(next(iter(info['files'].values())))
        else:
            inp = normalize_tf(info['files'], allow_static=False)
    except Exception as e:
        return 'error', str(e)[:1500]
    inp['meta']['gt_hash'] = info['gt_hash']
    inp['meta']['adapter_version'] = ADAPTER_VERSION
    tmp = p.with_suffix('.tmp')
    tmp.write_text(json.dumps(inp, indent=1, default=str))
    tmp.replace(p)
    return 'built', ''


def fixture_hash(lang, row) -> str | None:
    p = fixture_path(lang, row)
    return sha(p.read_text()) if p.exists() else None


def _path_list(path) -> list:
    if isinstance(path, list):
        return path
    return [int(s) if s.isdigit() else s for s in str(path).split('.')] if path != '' else []


def _compile_cond(c: dict) -> dict:
    c = dict(c)
    c['path'] = _path_list(c.get('path', ''))
    if c.get('op') == 'match':
        c['value'] = [_compile_cond(sc) for sc in c.get('value', [])]
    return c


def _compile_selector(s):
    if isinstance(s, str):
        return s
    s = dict(s)
    s['where'] = [_compile_cond(c) for c in s.get('where', [])]
    return s


def _compile_leaf(l: dict) -> dict:
    l = dict(l)
    for k in ('select', 'from', 'to'):
        if k in l:
            l[k] = _compile_selector(l[k])
    if 'cond' in l:
        l['cond'] = _compile_cond(l['cond'])
    for k in ('from_path', 'to_path', 'distinct_path'):
        if k in l:
            l[k] = _path_list(l[k])
    return l


def compile_spec(spec: dict) -> dict:
    out = {'selectors': {n: _compile_selector(s) for n, s in (spec.get('selectors') or {}).items()},
           'checks': []}
    for c in spec['checks']:
        cc = _compile_leaf(c) if c['kind'] in LEAF_KINDS else {**c, 'checks': [_compile_leaf(x) for x in c['checks']]}
        out['checks'].append(cc)
    return out


def generate_policy(lang: str, row: int) -> Path:
    spec = json.loads(spec_path(lang, row).read_text())
    compiled = compile_spec(spec)
    body = (f'package {package_name(lang, row)}\n\nimport rego.v1\n\nimport data.intent.lib\n\n'
            f'spec := {json.dumps(compiled, indent=1, ensure_ascii=True)}\n\n'
            f'results := lib.evaluate(spec)\n\ntargets := lib.targets(spec)\n')
    p = policy_path(lang, row)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


_QUOTE_MAP = str.maketrans({'\u2018': "'", '\u2019': "'", '\u201c': '"', '\u201d': '"',
                            '\u2013': '-', '\u2014': '-', '\u00a0': ' '})


def _quote_norm(text) -> str:
    return re.sub(r'\s+', ' ', str(text).translate(_QUOTE_MAP)).lower().strip()


def structural_errors(spec: dict, info: dict) -> list[str]:
    errs = []
    if spec.get('lang') != info['lang'] or int(spec.get('row_number', -1)) != info['row_number']:
        errs.append('lang/row_number do not match the file location')
    sels = spec.get('selectors') or {}
    prompt_norm = _quote_norm(info['prompt'])

    def check_sel(s, where):
        if isinstance(s, str):
            if s not in sels:
                errs.append(f'{where}: unknown selector {s!r}')
            return
        if not isinstance(s, dict) or not s.get('types'):
            errs.append(f'{where}: selector needs non-empty "types"')
            return
        for c in s.get('where', []):
            check_cond(c, where)

    def check_cond(c, where):
        if c.get('op') not in OPS:
            errs.append(f'{where}: unknown op {c.get("op")!r}')
        if c.get('op') == 'match':
            for sc in c.get('value', []):
                if sc.get('op') in ('match', None) or sc.get('op') not in OPS:
                    errs.append(f'{where}: bad sub-condition op {sc.get("op")!r}')
        if 'path' not in c:
            errs.append(f'{where}: condition without path')

    def check_leaf(l, where):
        if l.get('kind') not in LEAF_KINDS:
            errs.append(f'{where}: leaf kind must be one of {sorted(LEAF_KINDS)}')
            return
        if l['kind'] in ('exists', 'attr'):
            check_sel(l.get('select'), where)
        if l['kind'] == 'exists' and int(l.get('min', 1)) < 1:
            errs.append(f'{where}: exists.min < 1 is vacuous')
        if l['kind'] == 'attr':
            if 'cond' not in l:
                errs.append(f'{where}: attr without cond')
            else:
                check_cond(l['cond'], where)
        if l['kind'] in ('ref', 'join'):
            check_sel(l.get('from'), where)
            check_sel(l.get('to'), where)
        if l['kind'] == 'join' and ('from_path' not in l or 'to_path' not in l):
            errs.append(f'{where}: join needs from_path and to_path')

    for n, s in sels.items():
        check_sel(s, f'selector {n}')
    ids = [c.get('id') for c in spec.get('checks', [])]
    if not ids:
        errs.append('no checks')
    if len(ids) != len(set(ids)):
        errs.append('duplicate check ids')
    if not any(c.get('tier') == 'core' for c in spec.get('checks', [])):
        errs.append('no core check')
    for c in spec.get('checks', []):
        w = f'check {c.get("id")}'
        if c.get('tier') not in TIERS:
            errs.append(f'{w}: tier must be core|detail')
        q = _quote_norm(c.get('quote', ''))
        if not q:
            errs.append(f'{w}: missing prompt quote')
        elif q not in prompt_norm:
            errs.append(f'{w}: quote is not a verbatim span of the prompt: {c.get("quote")!r}')
        if c.get('kind') in ('any_of', 'all_of'):
            if not c.get('checks'):
                errs.append(f'{w}: empty {c["kind"]}')
            for i, l in enumerate(c.get('checks', [])):
                check_leaf(l, f'{w}[{i}]')
        else:
            check_leaf(c, w)
    return errs


_VALUELESS_OPS = {'present', 'absent', 'truthy', 'falsy', 'match'}
_NUMBER_WORDS = r'\b(one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|both|pair|multiple|several|each|every|all)\b|\d'


_GENERIC_TOKENS = {'aws', 'amazonaws', 'com', 'arn', 'iam', 'policy', 'service', 'role', 'the', 'and',
                   'for', 'with', 'from', 'all', 'resource', 'resources', 'default', 'allow', 'enabled'}
_LITERAL_ONLY = re.compile(r'^(\d+(\.\d+){3}(/\d+)?|[a-z]{2}(-gov)?-[a-z]+-\d[a-z]?|arn:.*|\d+(\.\d+)?)$', re.I)


def _tokens(text: str) -> list[str]:
    parts = re.findall(r'[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+', str(text))
    return [t.lower() for t in parts if len(t) >= 3 and t.lower() not in _GENERIC_TOKENS]


def _token_in(tok: str, prompt_norm: str, prompt_flat: str) -> bool:
    stem = tok[:-1] if tok.endswith('s') and len(tok) > 4 else tok
    return stem in prompt_norm or stem in prompt_flat


def _literal_in_prompt(value, prompt_norm: str) -> bool:
    if isinstance(value, bool) or value is None:
        return True
    if isinstance(value, (int, float)):
        n = int(value) if float(value).is_integer() else value
        return re.search(rf'(?<![\d.]){re.escape(str(n))}(?![\d])', prompt_norm) is not None
    v = _quote_norm(value)
    if not v or v in prompt_norm:
        return True
    if _LITERAL_ONLY.match(v):
        return False
    toks = _tokens(value)
    if not toks:
        return True
    flat = re.sub(r'[^a-z0-9]', '', prompt_norm)
    hit = sum(_token_in(t, prompt_norm, flat) for t in toks)
    return hit >= max(1, (len(toks) + 1) // 2)


def _regex_tokens_in_prompt(pattern: str, prompt_norm: str) -> bool:
    words = re.findall(r'[A-Za-z0-9]{3,}', re.sub(r'\(\?[a-z]+\)|\\[a-zA-Z]', ' ', pattern))
    if not words:
        return True
    flat = re.sub(r'[^a-z0-9]', '', prompt_norm)
    return any(_token_in(t, prompt_norm, flat) for w in words for t in (_tokens(w) or [w.lower()]))


def strictness_flags(spec: dict, info: dict) -> list[dict]:
    prompt_norm = _quote_norm(info['prompt'])
    sels = spec.get('selectors') or {}
    flags = []

    def lint_cond(c, owner, justified):
        op, val = c.get('op'), c.get('value')
        if c.get('path') in ('type', ['type']) and op in ('eq', 'in', 'regex'):
            return
        if op == 'match':
            for sc in val or []:
                lint_cond(sc, owner, justified)
            return
        if op in _VALUELESS_OPS or val is None:
            return
        ok = True
        if op == 'regex':
            ok = _regex_tokens_in_prompt(str(val), prompt_norm)
        elif op == 'in':
            ok = any(_literal_in_prompt(x, prompt_norm) for x in (val or []))
        elif op == 'has_kv' and isinstance(val, dict):
            ok = _literal_in_prompt(val.get('key'), prompt_norm) and _literal_in_prompt(val.get('value'), prompt_norm)
        elif op == 'glob_covers':
            ok = _literal_in_prompt(val, prompt_norm) or _literal_in_prompt(str(val).split(':')[-1], prompt_norm)
        elif op in ('len_gte', 'len_eq') and isinstance(val, (int, float)) and val <= 1:
            ok = True
        else:
            ok = _literal_in_prompt(val, prompt_norm)
        if not ok:
            flags.append({'check': owner, 'path': c.get('path'), 'op': op, 'value': val,
                          'justified': justified})

    def lint_sel(s, owner, justified):
        if isinstance(s, str):
            s = sels.get(s, {})
        for c in (s or {}).get('where', []):
            lint_cond(c, owner, justified)

    for c in spec.get('checks', []):
        justified = bool(str(c.get('justify', '')).strip())
        leaves = c.get('checks', []) if c.get('kind') in ('any_of', 'all_of') else [c]
        for l in leaves:
            for k in ('select', 'from', 'to'):
                if k in l:
                    lint_sel(l[k], c['id'], justified)
            if 'cond' in l:
                lint_cond(l['cond'], c['id'], justified)
            if l.get('kind') == 'exists' and (int(l.get('min', 1)) > 1 or 'max' in l):
                if not re.search(_NUMBER_WORDS, _quote_norm(c.get('quote', ''))):
                    flags.append({'check': c['id'], 'path': None, 'op': 'count',
                                  'value': {'min': l.get('min', 1), 'max': l.get('max')},
                                  'justified': justified})
    return flags


class OpaError(RuntimeError):
    pass


def opa_eval_many(lang: str, row: int, inputs: dict[str, dict], what='results') -> dict[str, dict]:
    pkg = package_name(lang, row)
    keys = list(inputs)
    if not keys:
        return {}
    with tempfile.TemporaryDirectory() as d:
        dp = Path(d, 'inputs.json')
        dp.write_text(json.dumps({'intent_inputs': {f'i{n}': inputs[k] for n, k in enumerate(keys)}}, default=str))
        query = '; '.join(f'r{n} := data.{pkg}.{what} with input as data.intent_inputs.i{n}' for n in range(len(keys)))
        r = subprocess.run(['opa', 'eval', '-f', 'json', '-d', str(LIB_REGO), '-d', str(policy_path(lang, row)),
                            '-d', str(dp), query], capture_output=True, text=True, timeout=900)
    try:
        out = json.loads(r.stdout)
    except Exception:
        raise OpaError((r.stderr or r.stdout)[:2000])
    if out.get('errors') or r.returncode != 0:
        raise OpaError(json.dumps(out.get('errors') or r.stderr)[:2000])
    res = out.get('result') or []
    if not res:
        raise OpaError('undefined result')
    b = res[0]['bindings']
    return {k: b[f'r{n}'] for n, k in enumerate(keys)}


def opa_eval(lang, row, inp, what='results') -> dict:
    return opa_eval_many(lang, row, {'one': inp}, what)['one']


SENTINEL = '__MUTATED__'


def _mutate_path(obj, pattern, fn):
    if not pattern:
        return
    head, rest = pattern[0], pattern[1:]
    if isinstance(obj, dict):
        keys = list(obj.keys()) if head == '*' else ([head] if head in obj else [])
    elif isinstance(obj, list):
        keys = list(range(len(obj))) if head == '*' else ([head] if isinstance(head, int) and head < len(obj) else [])
    else:
        return
    for k in keys:
        if rest:
            _mutate_path(obj[k], rest, fn)
        else:
            fn(obj, k)


def _break_value(op, want=None):
    if op == 'len_eq':
        return [SENTINEL] if want == 0 else []
    return {'present': None, 'len_gte': [], 'falsy': True}.get(op, SENTINEL)


def _apply_leaf_mutation(inp, leaf, tgt):
    by_id = {r['id']: r for r in inp['resources']}
    kind = leaf['kind']
    if kind == 'exists' and leaf.get('distinct_path'):
        for rid in tgt['select']:
            r = by_id.get(rid)
            if r is not None:
                def same(parent, k):
                    parent[k] = SENTINEL
                _mutate_path(r['values'], leaf['distinct_path'], same)
    elif kind == 'exists':
        ids = set(tgt['select'])
        inp['resources'] = [r for r in inp['resources'] if r['id'] not in ids]
    elif kind == 'attr':
        cond = leaf['cond']
        for rid in tgt['select']:
            r = by_id.get(rid)
            if r is None:
                continue
            if not cond['path'] and cond['op'] != 'absent':
                r['values'] = {'__mutated__': SENTINEL}
            elif cond['op'] == 'absent':
                if all(not isinstance(s, str) or s != '*' for s in cond['path']):
                    cur = r['values']
                    for s in cond['path'][:-1]:
                        cur = cur.setdefault(s, {}) if isinstance(cur, dict) else cur
                    if isinstance(cur, dict):
                        cur[cond['path'][-1]] = SENTINEL
            elif cond['op'] == 'match':
                def blank(parent, k):
                    parent[k] = {}
                _mutate_path(r['values'], cond['path'], blank)
            elif cond['op'] == 'none_eq':
                want = cond.get('value')
                if cond['path'] and cond['path'][-1] == '*':
                    def append(parent, k, want=want):
                        if isinstance(parent[k], list):
                            parent[k].append(want)
                    if len(cond['path']) == 1:
                        if isinstance(r['values'], list):
                            r['values'].append(want)
                    else:
                        _mutate_path(r['values'], cond['path'][:-1], append)
                else:
                    def put_want(parent, k, want=want):
                        parent[k] = want
                    _mutate_path(r['values'], cond['path'], put_want)
            else:
                val = _break_value(cond['op'], cond.get('value'))
                if cond['op'] == 'neq':
                    val = cond.get('value')

                def put(parent, k, val=val):
                    parent[k] = val
                _mutate_path(r['values'], cond['path'], put)
    elif kind == 'join':
        for rid in tgt['from']:
            r = by_id.get(rid)
            if r is not None:
                if leaf['from_path']:
                    def put(parent, k):
                        parent[k] = SENTINEL
                    _mutate_path(r['values'], leaf['from_path'], put)
                else:
                    r['values'] = SENTINEL
    elif kind == 'ref':
        to_cfgs = {by_id[i]['cfg'] for i in tgt['to'] if i in by_id}
        from_cfgs = {by_id[i]['cfg'] for i in tgt['from'] if i in by_id}
        for i in tgt['from']:
            if i in by_id:
                by_id[i]['refs'] = [x for x in by_id[i]['refs'] if x not in to_cfgs]
        if leaf.get('bidirectional'):
            for i in tgt['to']:
                if i in by_id:
                    by_id[i]['refs'] = [x for x in by_id[i]['refs'] if x not in from_cfgs]


def build_mutants(compiled: dict, fixture: dict, targets: dict) -> dict[str, dict]:
    mutants = {}
    for c in compiled['checks']:
        leaves = c['checks'] if c['kind'] in ('any_of', 'all_of') else [c]
        tgts = targets.get(c['id'], [])
        if c['kind'] == 'all_of':
            for i, (leaf, t) in enumerate(zip(leaves, tgts)):
                m = copy.deepcopy(fixture)
                _apply_leaf_mutation(m, leaf, t)
                mutants[f'{c["id"]}#{i}'] = m
        else:
            m = copy.deepcopy(fixture)
            for leaf, t in zip(leaves, tgts):
                _apply_leaf_mutation(m, leaf, t)
            mutants[c['id']] = m
    return mutants


def validate(lang: str, row: int, info: dict, cross_fixtures: dict[str, dict] | None = None) -> dict:
    report = {'lang': lang, 'row_number': row, 'status': 'invalid', 'structural': [], 'positive_fail': [],
              'mutation_survivors': [], 'cross_all_core_pass': [], 'n_checks': 0, 'n_core': 0}
    spec = json.loads(spec_path(lang, row).read_text())
    report['n_checks'] = len(spec.get('checks', []))
    report['n_core'] = sum(c.get('tier') == 'core' for c in spec.get('checks', []))
    report['structural'] = structural_errors(spec, info)
    report['strictness_flags'] = strictness_flags(spec, info)
    if spec_state(info) != 'ok':
        report['structural'].append(f'spec is {spec_state(info)} (source_hash does not match current GT/prompt)')
    if report['structural']:
        return report
    generate_policy(lang, row)
    fixture = json.loads(fixture_path(lang, row).read_text())
    compiled = compile_spec(spec)
    try:
        res = opa_eval(lang, row, fixture, 'results')
        targets = opa_eval(lang, row, fixture, 'targets')
        report['positive_fail'] = sorted(k for k, v in res.items() if not v)
        mutants = build_mutants(compiled, fixture, targets)
        batch = {**mutants, '__gt__': fixture,
                 '__empty__': {'meta': {'lang': lang, 'mode': 'empty', 'warnings': []}, 'resources': []}}
        mres = opa_eval_many(lang, row, batch, 'results')
        if mres.pop('__gt__') != res:
            raise OpaError('batched evaluation disagrees with single evaluation -- harness bug')
        empty = mres.pop('__empty__')
        report['vacuous_on_empty'] = sorted(c['id'] for c in spec['checks']
                                            if c['tier'] == 'core' and empty.get(c['id']))
        for mid, r in mres.items():
            cid = mid.split('#')[0]
            if r.get(cid):
                report['mutation_survivors'].append(mid)
        if cross_fixtures:
            others = {k: v for k, v in cross_fixtures.items() if k != tag(lang, row)}
            cres = opa_eval_many(lang, row, others, 'results')
            core_ids = [c['id'] for c in spec['checks'] if c['tier'] == 'core']
            report['cross_all_core_pass'] = sorted(k for k, r in cres.items() if all(r.get(i) for i in core_ids))
    except OpaError as e:
        report['structural'].append(f'opa error: {e}')
        return report
    unjustified = [f for f in report['strictness_flags'] if not f['justified']]
    if (not report['positive_fail'] and not report['mutation_survivors'] and not report['vacuous_on_empty']
            and not unjustified):
        report['status'] = 'valid'
    report['gt_hash'] = info['gt_hash']
    report['prompt_hash'] = info['prompt_hash']
    report['fixture_hash'] = fixture_hash(lang, row)
    p = validation_path(lang, row)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(report, indent=1))
    return report


def strip_fences(text: str) -> str:
    m = re.search(r'```[a-zA-Z0-9_-]*\n(.*?)```', text, re.S)
    return m.group(1) if m else text


def normalize_candidate(lang: str, template: str) -> dict:
    if template is None or (isinstance(template, float) and template != template):
        raise ValueError('empty template')
    template = strip_fences(str(template)).strip()
    if not template or template.lower() in ('nan', 'none', 'null'):
        raise ValueError('empty template')
    key = sha(f'{lang}\nv{ADAPTER_VERSION}\n{template}')
    cp = CACHE / 'candidates' / lang / f'{key}.json'
    if cp.exists():
        return json.loads(cp.read_text())
    inp = normalize_cfn(template) if lang == 'cfn' else normalize_tf({'main.tf': template})
    inp['meta']['cache_key'] = key
    cp.parent.mkdir(parents=True, exist_ok=True)
    cp.write_text(json.dumps(inp, default=str))
    return inp


def check_category(c: dict, spec: dict) -> str:
    leaf = c['checks'][0] if c['kind'] in ('any_of', 'all_of') else c
    sel = leaf.get('select') or leaf.get('from')
    sel = (spec.get('selectors') or {}).get(sel, sel) if isinstance(sel, str) else sel
    if isinstance(sel, dict) and sel.get('types') == ['__output__']:
        return 'output'
    return {'exists': 'resource', 'attr': 'attribute', 'ref': 'relationship', 'join': 'relationship'}[leaf['kind']]


def score(spec: dict, results: dict) -> dict:
    checks = spec['checks']
    core = [c for c in checks if c['tier'] == 'core']
    cats = {}
    for c in checks:
        cats.setdefault(check_category(c, spec), []).append(bool(results.get(c['id'])))
    out = {'n_checks': len(checks), 'n_pass': sum(bool(results.get(c['id'])) for c in checks),
           'n_core': len(core), 'n_core_pass': sum(bool(results.get(c['id'])) for c in core)}
    out['intent_strict'] = out['n_core_pass'] == out['n_core']
    out['core_score'] = out['n_core_pass'] / out['n_core'] if out['n_core'] else None
    out['intent_score'] = out['n_pass'] / out['n_checks'] if out['n_checks'] else None
    for cat in ('resource', 'attribute', 'relationship', 'output'):
        v = cats.get(cat, [])
        out[f'{cat}_score'] = sum(v) / len(v) if v else None
    out['failed_checks'] = [c['id'] for c in checks if not results.get(c['id'])]
    return out
