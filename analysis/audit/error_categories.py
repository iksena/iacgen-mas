from __future__ import annotations

import glob
import json
import os
import re
from concurrent.futures import ProcessPoolExecutor

import pandas as pd

import repair_loop as rl

_YAMLLINT_TAG = re.compile(r"^\[([a-z\-]+)\]")
_YAMLLINT_TAIL = re.compile(r"\(([a-z\-]+)\)\s*$")


def _yamllint_rule(line: str) -> str:
    m = _YAMLLINT_TAG.match(line)
    if m:
        return m.group(1)
    m = _YAMLLINT_TAIL.search(line)
    return m.group(1) if m else "other"


def _stage_messages(stage: str, rec: dict, lang: str, blocking) -> list[tuple[str, str, str]]:
    raw = rec.get("raw_output") or ""
    out = []
    if stage == "cfn-lint":
        items = rl._load_json(raw) or []
        items = [i for i in items if i.get("Level") == "Error"] or items
        for i in items:
            rule = i.get("Rule") or {}
            out.append((rule.get("Id") or "unknown-rule", "", f"{rule.get('ShortDescription') or ''}: {i.get('Message') or ''}"))
    elif stage == "trivy":
        for res in (rl._load_json(raw) or {}).get("Results", []) or []:
            for m in res.get("Misconfigurations", []) or []:
                if m.get("Status", "FAIL") != "FAIL":
                    continue
                if blocking != "all" and m.get("Severity") not in blocking:
                    continue
                out.append((m.get("ID") or "unknown-rule", m.get("Severity") or "", m.get("Title") or ""))
    elif stage == "terraform-validate":
        js = rl._load_json(raw)
        if isinstance(js, dict) and "diagnostics" in js:
            out = [(d.get("summary") or "unknown", "", f"{d.get('summary') or ''}: {d.get('detail') or ''}")
                   for d in js["diagnostics"] if d.get("severity") == "error"]
        else:
            blocks = raw.split("\nError: ")
            sums = rl._tf_text_diagnostics(raw)
            msgs = {}
            for b in blocks:
                head = b.split("\n", 1)
                s = head[0].replace("Error: ", "").strip()
                msgs.setdefault(s, " ".join(b.split()))
            out = [(f"init: {s}", "", msgs.get(s, s)[:400]) for s in sums] or [("init: failed", "", raw[:400])]
    elif stage == "tflint":
        js = rl._load_json(raw)
        if isinstance(js, dict):
            issues = js.get("issues", [])
            issues = [i for i in issues if (i.get("rule") or {}).get("severity") == "error"] or issues
            out = [((i.get("rule") or {}).get("name") or "unknown-rule", "", i.get("message") or "") for i in issues]
            out += [("tflint-error", "", str(e)[:300]) for e in js.get("errors", [])]
        elif rec.get("errors"):
            out = [("tflint-error", "", str(rec.get("errors"))[:300])]
    elif stage == "yaml":
        errs = rec.get("errors") or []
        tags = [(_yamllint_rule(str(e)), str(e)) for e in errs]
        out = [("yaml-syntax", t, m) for t, m in tags] or [("yaml-syntax", "other", str(raw)[:300])]
    return out


def _deploy_messages(dv: dict, resources, lang: str, params) -> list[tuple[str, str, str]]:
    keys = rl.deploy_errors(dv, resources, lang, params)
    frs = dv.get("failed_resources") or []
    if not frs:
        return [(k, "", str(dv.get("error_message") or "")[:600]) for k, _ in keys]
    out = []
    for (k, _), fr in zip(keys, frs):
        reason = str((fr or {}).get("status_reason") or "") or str(dv.get("error_message") or "")
        out.append((k, "", reason[:600]))
    return out


def _parse_run(args):
    run_id, folder, lang, blocking = args
    rows = []
    for f in sorted(glob.glob(os.path.join(folder, "iteration_*.json"))):
        try:
            it = json.load(open(f))
        except Exception:
            continue
        i = int(it.get("iteration", 0))
        tmpl = it.get("iac_template", "") or ""
        if lang == "TF":
            res, params = rl.tf_resources(tmpl), set()
        else:
            res, params = rl.cfn_resources(tmpl, with_parameters=True)
        for v in it.get("validation_results", []):
            cls = rl.STAGE_CLASS.get(v.get("stage"))
            if not cls or v.get("passed"):
                continue
            for k, sub, msg in _stage_messages(v.get("stage"), v, lang, blocking):
                rows.append((run_id, i, cls, v.get("stage"), k, sub, msg))
        dv = it.get("deploy_validation_result") or {}
        if dv.get("target") not in (None, "skipped") and not dv.get("passed"):
            for k, sub, msg in _deploy_messages(dv, res, lang, params):
                rows.append((run_id, i, "deploy", "deploy", k, sub, msg))
    return rows


def extract_messages(run_ids, runs_dir: str, lang: str, index: dict, blocking=rl.BLOCKING_DEFAULT, workers: int = 8) -> pd.DataFrame:
    jobs = [(rid, index[rid], lang, blocking) for rid in pd.Series(run_ids).dropna().astype(str) if rid in index]
    with ProcessPoolExecutor(workers) as ex:
        out = list(ex.map(_parse_run, jobs, chunksize=4))
    return pd.DataFrame([r for rows in out for r in rows], columns=["run_id", "iteration", "cls", "stage", "key", "sub", "msg"])


CATEGORIES = [
    ("Syntax", "Malformed template"),
    ("Syntax", "YAML formatting (yamllint)"),
    ("Schema", "Invalid property or argument"),
    ("Schema", "Missing required property"),
    ("Schema", "Invalid value or type"),
    ("Schema", "Invalid reference or dependency"),
    ("Security", "Encryption missing or weak"),
    ("Security", "Network exposure"),
    ("Security", "Access control and public access"),
    ("Security", "Logging and monitoring"),
    ("Deployment", "Missing value"),
    ("Deployment", "IAM and permission errors"),
    ("Deployment", "Referenced resource or service not available"),
    ("Deployment", "Resource configuration rejected by the provider"),
    ("Deployment", "Template creates no resources"),
    ("Deployment", "Missing provider configuration"),
    ("Deployment", "No actionable message"),
    ("Environment", "Provider installation"),
    ("Environment", "Name collision with leftover resource"),
    ("Environment", "Quota or service limit"),
    ("Environment", "Transient provider failure or account state"),
]
STAGE_OF = {c: s for s, c in CATEGORIES}
COLLATERAL = "(collateral: cancelled by another failure)"
UNMAPPED = "(unmapped)"

YAML_MALFORMED = {"syntax", "key-duplicates"}

CFN_LINT_RULES = {
    "Malformed template": ["E0000", "E0001", "E0002"],
    "Invalid property or argument": ["E3002", "E3001", "E6001", "E3018", "E3014", "E3020", "E3063", "W3011"],
    "Missing required property": ["E3003", "E6002", "E3021", "E3058"],
    "Invalid value or type": ["E3012", "E3030", "E6101", "E6003", "E3031", "E3032", "E3033", "E3034", "E3510", "E3512", "E3530",
                              "E3601", "E3023", "E3024", "E3039", "E2533", "E2531", "E2015", "E2001", "E7001", "E1003", "E1001", "W3037"],
    "Invalid reference or dependency": ["E1010", "E1011", "E1012", "E1017", "E1018", "E1019", "E1020", "E1022", "E1028", "E1029", "E1031",
                                        "E1032", "E1040", "E3004", "E3005", "W3005", "E3006", "E3007", "E3015", "E8001", "E8006", "W1020", "W2001"],
}
CFN_LINT_ID = {rid: cat for cat, ids in CFN_LINT_RULES.items() for rid in ids}
CFN_LINT_FAMILY = [
    (r"^[EW]0", "Malformed template"), (r"^[EW]1", "Invalid reference or dependency"), (r"^[EW][267]", "Invalid value or type"),
    (r"^[EW]8", "Invalid reference or dependency"), (r"^[EW]3", "Invalid value or type"),
]

TF_SUMMARY_RULES = [
    ("Provider installation", r"^(Error: )?Failed to (install provider|query available provider packages)"),
    ("Missing provider configuration", r"^(Invalid provider configuration|invalid AWS Region)"),
    ("Malformed template", r"^(Invalid (character|multi-line string|block definition|single-argument block definition|expression|escape sequence|"
                           r"string literal|argument name|resource type name|resource name|validation expression|variable validation condition)|"
                           r"Unclosed configuration block|Unterminated|Argument or block definition required|"
                           r"Missing (newline|false expression|expression|attribute separator|item separator|key/value separator|name for resource)|"
                           r"Variables not allowed|Function calls not allowed|Unsupported operator|Unbalanced parentheses|Reserved block type name|"
                           r"Extraneous label|Unexpected \"\w+\" block|Duplicate .*(declaration|configuration)|Invalid combination of \"count\" and \"for_each\")"),
    ("Missing required property", r"^(Missing required argument|Insufficient \w+ blocks|Invalid combination of arguments|Not enough list items)"),
    ("Invalid property or argument", r"^(Unsupported argument|Unsupported block type|Unsupported attribute|Conflicting configuration arguments|Too many \w+ blocks)"),
    ("Invalid value or type", r"^(expected .* to be (one of|in the range)|Incorrect attribute value type|Invalid function argument|"
                              r"(Not enough|Too many) function arguments|Inconsistent conditional result types|Invalid operand|Unsuitable value type|"
                              r"Value for unconfigurable attribute|Invalid Configuration for Read-Only Attribute|Invalid Attribute Value Match|"
                              r"Unsupported Terraform Core version|Error in function call|Invalid value for input variable|\"\w+\" must )"),
    ("Invalid reference or dependency", r"^(Reference to undeclared|Invalid reference|Invalid resource type$|Missing resource instance key|Cycle:|"
                                        r"Self-referential block|Module not found|Unreadable module directory|Invalid registry module source address|"
                                        r"Unresolvable module version constraint|Provider configuration not present|Invalid for_each argument|"
                                        r"Invalid count argument|Invalid index)"),
]

SECURITY_RULES = [
    ("Encryption missing or weak", r"encrypt|customer managed key|\bcmk\b|\bkms\b|\btls\b|\bssl\b|plain http"),
    ("Access control and public access", r"public access|public acl|public polic|public bucket|\biam\b|polic(y|ies)|permission|source arn|"
                                         r"session tokens|metadata service|mutable|wildcard|principal"),
    ("Logging and monitoring", r"\blog|trail|monitor|scan|tracing|audit"),
    ("Network exposure", r"public ip|unrestricted|ingress|egress|internet|network acl|all ports|default vpc|\bwaf\b|invalid headers|security group"),
]

MODEL_RE = re.compile("|".join([
    r"failed to send cfn-response", r"Invalid \w+ specified", r"is not a valid", r"required parameter",
    r"Unknown parameters", r"HandlerErrorCode: InvalidRequest", r"Unsupported block type", r"Unsupported argument",
    r"ValidationError", r"Template format error", r"Invalid scope requested",
]), re.I)
DEPLOY_RULES = [
    (COLLATERAL, r"^\s*Resource creation cancelled\s*$"),
    ("Provider installation", r"Failed to install provider|plugin-cache|text file busy|no space left on device|Failed to query available provider packages"),
    ("Missing provider configuration", r"invalid AWS Region|Invalid provider configuration"),
    ("No actionable message", r"Stalled in CREATE_IN_PROGRESS|timed out after|Stack creation timed out"),
    ("Resource configuration rejected by the provider", r"NetworkAclEntryAlreadyExists|Invalid Resource Record|is not permitted in zone|"
                                                        r"should not contain uppercase"),
    ("Quota or service limit", r"LimitExceeded|limit exceeded|[Ll]imit for the maximum|maximum number of|service limit|[Qq]uota|QUOTA_EXHAUSTED|"
                               r"Maximum allowed resources exceeded|reached the limit|Throttl|Rate exceeded|MaxNumberOf\w+Exceeded|"
                               r"less than or equal to 51200"),
    ("Transient provider failure or account state", r"PendingDeletion|TERMINAL ENVIRONMENT BLOCKER"),
    ("Name collision with leftover resource", r"already exists|AlreadyExists|already in use|AlreadyOwnedByYou|Only 1 \w+ is allowed|"
                                              r"scheduled for deletion|DuplicateItem|InvalidKeyPair\.Duplicate"),
    ("IAM and permission errors", r"AccessDenied|Access Denied|not authorized|Unauthorized|Invalid principal|invalid (service )?principals|"
                                  r"MalformedPolicyDocument|AssumeRole policy|InsufficientCapabilities|Insufficient permissions|"
                                  r"InsufficientEncryptionPolicy|IAM Role .* not configured properly|cannot be assumed|PassRole|"
                                  r"action out of service scope|Invalid repository policy|No access to"),
    ("Missing value", r"Required parameter has no Default|No value for required variable|must have values"),
    ("Template creates no resources", r"created 0 resources"),
    ("Malformed template", r"(Template format error|validate_template failed).*(YAML|JSON) not well-formed"),
    ("Invalid value or type", r"Template format error: .*must evaluate to a String|'null' values are not allowed|must match pattern|"
                              r"MaxLength must be on a parameter|Properties validation failed(?!.*(extraneous key|required key|subschemas matched))|"
                              r"expected type: \w+, found"),
    ("Invalid property or argument", r"Properties validation failed.*(extraneous key|subschemas matched)"),
    ("Missing required property", r"Properties validation failed.*required key"),
    ("Invalid reference or dependency", r"Template error: (Fn::|Range|Parameter|unresolved|instance of)"),
    ("Referenced resource or service not available", r"does not exist|not found|cannot be found|could not be found|No Solution Stack named|"
                                                     r"returned no results|no matching|empty result|non-existent|NoSuchEntity|"
                                                     r"Unable to fetch parameters|not subscribed|is not enabled for|couldn't find resource|no such file or directory|"
                                                     r"unable to fetch|multiple .* matched"),
    ("No actionable message", r"Validation failed with \d+ error\(s\)\. Call DescribeEvents|Validation failure detected\. See the operation|"
                              r"Stalled in CREATE_IN_PROGRESS|timed out|timeout while waiting|time exceeded|took longer than|"
                              r"Exceeded attempts to wait|handler returned message: \"null\"|^\s*N/A\s*$|Stack entered terminal status|"
                              r"did not receive a response from your Custom Resource|unexpected deployment status FAILED|"
                              r"Review the application logs|Response object is too long|TERRAFORM CRASH|unknown identity type|did not stabilize|^\s*$"),
    ("Transient provider failure or account state", r"Internal ?Failure|InternalError|InternalServerError|ServiceUnavailable|"
                                                    r"Could not connect to the endpoint|Connection was closed|No valid credential sources"),
    ("Resource configuration rejected by the provider", r"Resource handler returned message|api error|\w+Exception|[Ii]nvalid|not (a )?valid|"
                                                        r"[Vv]alidation|[Mm]ust|not supported|[Uu]nsupported|cannot|can not|can't|"
                                                        r"required|expected|[Mm]alformed|not allowed|failed to satisfy|[Cc]onflict|"
                                                        r"mismatch|Error running command|[Ee]rror|[Ff]ailed|FAILED"),
]
_ENV = {c for s, c in CATEGORIES if s == "Environment"}
_TF_RX = [(c, re.compile(p)) for c, p in TF_SUMMARY_RULES]
_DEP_RX = [(c, re.compile(p, re.S)) for c, p in DEPLOY_RULES]
_SEC_RX = [(c, re.compile(p, re.I)) for c, p in SECURITY_RULES]
_FAM_RX = [(re.compile(p), c) for p, c in CFN_LINT_FAMILY]


def _tf_summary(text: str):
    for cat, rx in _TF_RX:
        if rx.search(text):
            return cat, f"tf-summary:{rx.pattern[:40]}"
    return None


def security_category(rule_id: str, checks: dict):
    c = checks.get(f"AVD-{rule_id}") or {}
    title = c.get("check_name") or c.get("title") or ""
    for cat, rx in _SEC_RX:
        if rx.search(title):
            return cat, f"title~/{rx.pattern[:30]}/", title
    return UNMAPPED, "no title rule", title


def categorise(lang: str, cls: str, stage: str, key: str, sub: str, msg: str, checks: dict) -> tuple[str, str]:
    msg = msg or ""
    if stage == "yaml":
        return ("Malformed template" if sub in YAML_MALFORMED else "YAML formatting (yamllint)"), f"yamllint rule '{sub}'"
    if stage == "cfn-lint":
        if key in CFN_LINT_ID:
            return CFN_LINT_ID[key], f"cfn-lint id {key}"
        for rx, cat in _FAM_RX:
            if rx.search(key):
                return cat, f"cfn-lint family {rx.pattern}"
        return UNMAPPED, "no cfn-lint rule"
    if stage == "trivy":
        cat, rule, _ = security_category(key, checks)
        return cat, rule
    if stage in ("terraform-validate", "tflint"):
        s = key[len("init: "):] if key.startswith("init: ") else key
        r = _tf_summary(s)
        return r if r else (UNMAPPED, "no terraform rule")
    if lang == "TF":
        summary = key.split(": ", 1)[1] if ":" in key and key.split(":")[0] in ("apply", "plan", "init") else msg.split(" — ")[0]
        r = _tf_summary(summary.strip())
        if r:
            return r
    for cat, rx in _DEP_RX:
        if rx.search(msg):
            if cat in _ENV and cat != "Provider installation" and MODEL_RE.search(msg):
                continue
            return cat, f"deploy reason~/{rx.pattern[:40]}/"
    return UNMAPPED, "no deploy rule"


def rules_table() -> pd.DataFrame:
    rows = [("Syntax", "yaml", "yamllint rule in " + ", ".join(sorted(YAML_MALFORMED)), "Malformed template"),
            ("Syntax", "yaml", "any other yamllint rule", "YAML formatting (yamllint)")]
    rows += [("Schema", "cfn-lint", ", ".join(ids), cat) for cat, ids in CFN_LINT_RULES.items()]
    rows += [("Schema", "cfn-lint (fallback)", p, cat) for p, cat in CFN_LINT_FAMILY]
    rows += [(STAGE_OF.get(cat, ""), "terraform summary", p, cat) for cat, p in TF_SUMMARY_RULES]
    rows += [("Security", "trivy title (security_checks.json)", p, cat) for cat, p in SECURITY_RULES]
    rows += [(STAGE_OF.get(cat, "-"), "deploy reason", p, cat) for cat, p in DEPLOY_RULES]
    return pd.DataFrame(rows, columns=["stage", "applies to", "rule (regex or ids, first match wins)", "category"])
