from __future__ import annotations

import glob
import json
import os
from collections import Counter
from concurrent.futures import ProcessPoolExecutor

import pandas as pd

STAGE_CLASS = {"yaml": "syntax", "terraform-validate": "syntax", "cfn-lint": "schema", "tflint": "schema", "trivy": "security"}
CLASSES = ["syntax", "schema", "security", "deploy"]
BLOCKING_DEFAULT = ("CRITICAL", "HIGH")

try:
    import tiktoken
    _ENC = tiktoken.get_encoding("cl100k_base")
except Exception:
    _ENC = None


def n_tokens(text: str) -> int:
    if not text:
        return 0
    return len(_ENC.encode(text, disallowed_special=())) if _ENC else len(text) // 4


def _cfn_loader():
    import yaml

    class L(yaml.SafeLoader):
        pass

    def _tag(loader, suffix, node):
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node, deep=True)
        return loader.construct_mapping(node, deep=True)

    L.add_multi_constructor("!", _tag)
    return L


_CFN_LOADER = None


def cfn_resources(template: str, with_parameters: bool = False):
    global _CFN_LOADER
    import yaml
    if _CFN_LOADER is None:
        _CFN_LOADER = _cfn_loader()
    try:
        doc = yaml.load(template, Loader=_CFN_LOADER)
    except Exception:
        return (None, set()) if with_parameters else None
    res = doc.get("Resources") if isinstance(doc, dict) else None
    if not isinstance(res, dict):
        return (None, set()) if with_parameters else None
    out = {str(k): str(v.get("Type")) for k, v in res.items() if isinstance(v, dict) and isinstance(v.get("Type"), str)}
    if with_parameters:
        params = doc.get("Parameters")
        return out, ({str(k) for k in params} if isinstance(params, dict) else set())
    return out


def tf_resources(template: str) -> dict[str, str] | None:
    try:
        import hcl2
        doc = hcl2.loads(template)
    except Exception:
        return None
    out = {}
    for block in doc.get("resource", []) or []:
        for rtype, named in block.items():
            rtype = str(rtype).strip('"')
            for name in (named or {}):
                out[f"{rtype}.{str(name).strip(chr(34))}"] = rtype
    return out


def _load_json(text):
    try:
        return json.loads(text)
    except Exception:
        return None


def _tf_text_diagnostics(text: str) -> list[str]:
    summaries = [ln[len("Error: "):].strip() for ln in text.splitlines() if ln.startswith("Error: ")]
    if len(summaries) > 1 and summaries[0].startswith("Terraform encountered problems during initialisation"):
        summaries = summaries[1:]
    return summaries


def stage_errors(stage: str, rec: dict, resources: dict | None, lang: str, blocking) -> list[tuple[str, str]]:
    raw = rec.get("raw_output") or ""
    out: list[tuple[str, str]] = []
    if stage == "cfn-lint":
        items = _load_json(raw) or []
        blocking_items = [i for i in items if i.get("Level") == "Error"] or items
        for item in blocking_items:
            path = (item.get("Location") or {}).get("Path") or []
            rtype = ""
            if len(path) > 1 and path[0] == "Resources" and resources:
                rtype = resources.get(str(path[1]), "")
            out.append(((item.get("Rule") or {}).get("Id") or "unknown-rule", rtype))
    elif stage == "trivy":
        for res in (_load_json(raw) or {}).get("Results", []) or []:
            for m in res.get("Misconfigurations", []) or []:
                if m.get("Status", "FAIL") != "FAIL":
                    continue
                if blocking != "all" and m.get("Severity") not in blocking:
                    continue
                addr = ((m.get("CauseMetadata") or {}).get("Resource")) or ""
                if lang == "TF":
                    parts = addr.split(".")
                    rtype = parts[-2] if len(parts) >= 2 else ""
                else:
                    rtype = (resources or {}).get(addr, "")
                out.append((m.get("ID") or "unknown-rule", rtype))
    elif stage == "terraform-validate":
        js = _load_json(raw)
        if isinstance(js, dict) and "diagnostics" in js:
            out = [(d.get("summary") or "unknown", "") for d in js["diagnostics"] if d.get("severity") == "error"]
        else:
            out = [(f"init: {s}", "") for s in _tf_text_diagnostics(raw)] or [("init: failed", "")]
    elif stage == "tflint":
        js = _load_json(raw)
        if isinstance(js, dict):
            issues = js.get("issues", [])
            issues = [i for i in issues if (i.get("rule") or {}).get("severity") == "error"] or issues
            out = [((i.get("rule") or {}).get("name") or "unknown-rule", "") for i in issues]
            out += [("tflint-error", "") for _ in js.get("errors", [])]
        elif rec.get("errors"):
            out = [("tflint-error", "")]
    elif stage == "yaml":
        out = [("yaml-syntax", "")] * max(1, len(rec.get("errors") or []))
    return out


def deploy_errors(dv: dict, resources: dict | None, lang: str, parameters: set | None = None) -> list[tuple[str, str]]:
    out = []
    stack_name = str(dv.get("stack_id") or "").split("/")[1] if "/" in str(dv.get("stack_id") or "") else None
    for fr in dv.get("failed_resources") or []:
        name = str((fr or {}).get("logical_name") or "")
        if lang == "TF":
            parts = name.split(".")
            if len(parts) >= 2:
                out.append((parts[-2], parts[-2]))
            else:
                summary = str((fr or {}).get("status_reason") or "").split("\n")[0].split(" \u2014 ")[0].strip()
                out.append((f"{name or 'stage'}: {summary}"[:100], ""))
        else:
            if name in (resources or {}):
                out.append((resources[name], resources[name]))
            elif name in (parameters or set()):
                out.append(("parameter", ""))
            elif stack_name is not None and name == stack_name:
                out.append(("stack-level", ""))
            else:
                out.append(("unknown-resource", ""))
    return out or [("stack-level", "")]


def context_headings(ctx: str) -> list[str]:
    heads = []
    for ln in ctx.splitlines():
        if ln.startswith("#"):
            heads.append(ln.lstrip("#").strip())
    return heads


def index_runs(runs_dir: str) -> dict[str, str]:
    idx = {}
    for p in glob.glob(os.path.join(runs_dir, "*", "final_report.json")):
        idx[os.path.basename(os.path.dirname(p))] = os.path.dirname(p)
    for p in glob.glob(os.path.join(runs_dir, "*", "*", "final_report.json")):
        idx.setdefault(os.path.basename(os.path.dirname(p)), os.path.dirname(p))
    return idx


def parse_run(args):
    run_id, folder, lang, blocking = args
    try:
        fr = json.load(open(os.path.join(folder, "final_report.json")))
    except Exception:
        return []
    turns = {t.get("iteration"): t for t in fr.get("remediation_history", [])}
    rows = []
    for f in sorted(glob.glob(os.path.join(folder, "iteration_*.json"))):
        try:
            it = json.load(open(f))
        except Exception:
            continue
        i = int(it.get("iteration", 0))
        tmpl = it.get("iac_template", "") or ""
        params: set = set()
        if lang == "TF":
            res = tf_resources(tmpl)
        else:
            res, params = cfn_resources(tmpl, with_parameters=True)
        types = Counter(res.values()) if res is not None else None
        r = {"run_id": run_id, "iteration": i, "validation_passed": bool(it.get("validation_passed")),
             "template_parsed": res is not None, "n_resources": len(res) if res is not None else None,
             "res_types": json.dumps(dict(types), sort_keys=True) if types is not None else None, "tmpl_chars": len(tmpl)}
        fail_types: list[str] = []
        for cls in ("syntax", "schema", "security"):
            r[f"{cls}_ran"] = False
        security_skipped = False
        for v in it.get("validation_results", []):
            st = v.get("stage")
            cls = STAGE_CLASS.get(st)
            if not cls:
                continue
            if cls == "security" and str(v.get("raw_output") or "").startswith("Skipped"):
                security_skipped = True
            errs = stage_errors(st, v, res, lang, blocking) if not v.get("passed") else []
            r[f"{cls}_ran"] = True
            r[f"{cls}_ok"] = bool(v.get("passed"))
            r[f"{cls}_n"] = len(errs)
            r[f"{cls}_n_logged"] = len(v.get("errors") or [])
            r[f"{cls}_keys"] = "|".join(dict.fromkeys(k for k, _ in errs))
            fail_types += [t for _, t in errs if t]
        static_failed = any(r[f"{c}_ran"] and not r[f"{c}_ok"] for c in ("syntax", "schema"))
        if r["security_ran"] and (security_skipped or static_failed):
            r["security_ran"], r["security_ok"], r["security_n"], r["security_keys"] = False, False, 0, ""
        dv = it.get("deploy_validation_result") or {}
        r["deploy_target"] = dv.get("target")
        r["deploy_ran"] = dv.get("target") not in (None, "skipped") and not static_failed \
            and not (r["security_ran"] and not r["security_ok"])
        r["deploy_ok"] = bool(dv.get("passed")) if r["deploy_ran"] else None
        derr = deploy_errors(dv, res, lang, params) if (r["deploy_ran"] and not dv.get("passed")) else []
        r["deploy_keys"] = "|".join(dict.fromkeys(k for k, _ in derr))
        r["deploy_n_failed_resources"] = len(dv.get("failed_resources") or [])
        fail_types += [t for _, t in derr if t]
        r["fail_types"] = "|".join(dict.fromkeys(fail_types))
        t = turns.get(i)
        r["has_turn"] = t is not None
        if t is not None:
            ctx = t.get("retriever_context") or ""
            heads = set(context_headings(ctx))
            r["ctx_tokens"] = n_tokens(ctx)
            r["n_queries"] = len(t.get("retrieval_queries") or [])
            r["suggestion_tokens"] = n_tokens(t.get("suggestion") or "")
            r["errors_tokens"] = n_tokens(t.get("formatted_errors") or "")
            r["ctx_n_headings"] = len(heads)
            r["ctx_covers_failing_type"] = bool(set(fail_types) & heads) if fail_types else None
        rows.append(r)
    return rows


def build_iteration_table(run_meta: pd.DataFrame, runs_dir: str, lang: str, workers: int = 8, index: dict | None = None,
                          blocking=BLOCKING_DEFAULT) -> pd.DataFrame:
    index = index or index_runs(runs_dir)
    jobs = [(rid, index[rid], lang, blocking) for rid in run_meta["run_id"].dropna().astype(str) if rid in index]
    with ProcessPoolExecutor(workers) as ex:
        out = list(ex.map(parse_run, jobs, chunksize=4))
    df = pd.DataFrame([r for rows in out for r in rows])
    if df.empty:
        return df
    return df.merge(run_meta[["run_id", "row_number"]].astype({"run_id": str}), on="run_id", how="left")
