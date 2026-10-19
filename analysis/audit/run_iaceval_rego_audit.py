#!/usr/bin/env python3
import argparse
import csv
import glob
import os
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pandas as pd

csv.field_size_limit(sys.maxsize)
HERE = Path(__file__).resolve().parent
AUDIT = HERE / "rego_intent_audit.py"
PARQUET = "../data/iac_eval/train.parquet"
REQUIRED_VERSION = re.compile(r"^\s*required_version\s*=.*$\n?", re.M)
ENV_RE = re.compile(r"timed out after|Failed to query available provider packages|Failed to install provider|"
                    r"no such host|registry\.terraform\.io|releases\.hashicorp\.com")


def split_parts(df, out, parts, name):
    for k in range(parts):
        df[df.row_number % parts == k][["row_number", "final_template"]].to_csv(out / f"{name}{k}.csv", index=False)


def prepare(a):
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    if a.references:
        bench = pd.read_parquet(a.parquet)
        ref = pd.DataFrame({"row_number": range(len(bench)), "final_template": bench["Reference output"].fillna("")})
        ref.to_csv(out / "IaCEval_reference_outputs.csv", index=False)
        ref["required_version_removed"] = ref.final_template.str.contains(REQUIRED_VERSION)
        ref["final_template"] = ref.final_template.str.replace(REQUIRED_VERSION, "", regex=True)
        ref.to_csv(out / "IaCEval_reference_outputs_relaxed.csv", index=False)
        split_parts(ref, out, a.parts, "_in_part")
        print(f"{len(ref)} references, {int(ref.required_version_removed.sum())} required_version lines removed")
    if a.templates:
        t = pd.read_csv(a.templates, engine="python", usecols=["row_number", "final_template"])
        split_parts(t, out, a.parts, "_in_part")
        print(f"{len(t)} templates from {a.templates}")


def dummy_profile():
    d = Path(tempfile.mkdtemp(prefix="rgaws"))
    (d / "config").write_text("[profile admin-1]\nregion = us-east-1\n[default]\nregion = us-east-1\n")
    (d / "credentials").write_text("[admin-1]\naws_access_key_id = test\naws_secret_access_key = test\n"
                                   "[default]\naws_access_key_id = test\naws_secret_access_key = test\n")
    return d


def mirror_config(mirror):
    f = Path(tempfile.mkdtemp(prefix="tfrc")) / "mirror.tfrc"
    f.write_text('provider_installation {\n  filesystem_mirror {\n    path    = "%s"\n'
                 '    include = ["registry.terraform.io/hashicorp/*"]\n  }\n'
                 '  direct {\n    exclude = ["registry.terraform.io/hashicorp/*"]\n  }\n}\n' % mirror)
    return f


def launch(inputs, out, prefix, tag, parquet, tf_mirror=None, tmp_root="/tmp"):
    out = Path(out)
    (out / "plans").mkdir(parents=True, exist_ok=True)
    prof = dummy_profile()
    env = dict(os.environ, AWS_CONFIG_FILE=str(prof / "config"), AWS_SHARED_CREDENTIALS_FILE=str(prof / "credentials"))
    if tf_mirror:
        env["TF_CLI_CONFIG_FILE"] = str(mirror_config(tf_mirror))
    procs = []
    for k, inp in enumerate(inputs):
        tmp = Path(tmp_root) / f"rg{k + 1}"
        tmp.mkdir(parents=True, exist_ok=True)
        cmd = [sys.executable, "-u", str(AUDIT), "--input", str(inp), "--benchmark-parquet", parquet,
               "--output-csv", str(out / f"{prefix}_{tag}{k}.csv"), "--plan-dir", str(out / "plans")]
        log = open(out / f"log_{tag}{k}.txt", "w")
        procs.append(subprocess.Popen(cmd, env=dict(env, TMPDIR=str(tmp)), stdout=log, stderr=subprocess.STDOUT))
        time.sleep(20)
    for p in procs:
        p.wait()
    print("done:", [p.returncode for p in procs])


def run(a):
    inputs = sorted(glob.glob(f"{a.inputs}/_in_part*.csv"))
    launch(inputs, a.out, a.prefix, "part", a.parquet, a.tf_mirror, a.tmp_root)


def rerun(a):
    out = Path(a.out)
    done = pd.concat([pd.read_csv(f) for f in sorted(glob.glob(f"{out}/{a.prefix}_*.csv"))])
    done = done.drop_duplicates("row_number", keep="last")
    rows = done[done.terraform_error.fillna("").str.contains(ENV_RE)].row_number
    src = pd.read_csv(a.inputs_csv, engine="python", usecols=["row_number", "final_template"])
    src = src[src.row_number.isin(rows)]
    inputs = []
    for k in range(a.parts):
        f = out / f"_{a.tag}_in{k}.csv"
        src[src.row_number % a.parts == k].to_csv(f, index=False)
        inputs.append(f)
    print(f"re-running {len(src)} rows with environment errors")
    launch(inputs, out, a.prefix, a.tag, a.parquet, a.tf_mirror, a.tmp_root)


def main():
    ap = argparse.ArgumentParser(description="IaC-Eval Rego intent audit: prepare inputs, run workers, re-run environment errors.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--references", action="store_true")
    p.add_argument("--templates", help="results CSV with row_number, final_template")
    p.add_argument("--out", required=True)
    p.add_argument("--parts", type=int, default=4)
    p.add_argument("--parquet", default=PARQUET)
    for name, fn in (("run", run), ("rerun", rerun)):
        q = sub.add_parser(name)
        q.add_argument("--out", required=True)
        q.add_argument("--prefix", required=True, help="output file prefix, e.g. Rego_reference or Rego_glm")
        q.add_argument("--parquet", default=PARQUET)
        q.add_argument("--tf-mirror", help="filesystem mirror of the HashiCorp providers")
        q.add_argument("--tmp-root", default="/tmp")
        if name == "run":
            q.add_argument("--inputs", required=True, help="folder with _in_part*.csv")
        else:
            q.add_argument("--inputs-csv", required=True, help="row_number, final_template of every row")
            q.add_argument("--tag", required=True, help="re-run name, e.g. rerun, rrB")
            q.add_argument("--parts", type=int, default=2)
        q.set_defaults(fn=fn)
    p.set_defaults(fn=prepare)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
