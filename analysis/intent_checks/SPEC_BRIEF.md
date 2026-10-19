# Intent spec authoring brief

You write **one JSON spec per scenario** at `intent_checks/specs/<lang>/row_NNN.json`
(`NNN` = zero-padded full-benchmark `row_number`). A generator turns it into Rego
(`policies/…`, never edit those) that a shared interpreter (`lib/intent.rego`) evaluates
against a normalised view of a template. The spec is what measures whether a generated
template **does what the prompt asked**, so it must be faithful to the *prompt*, satisfied
by the *ground truth*, and not so loose that anything passes.

All commands run from `analysis/`.

## Workflow per scenario
1. `python3 intent_checks/build.py show <lang> <row>` prints the prompt, the
   `source_hash` values to copy, and every normalised ground-truth resource
   (`id`, `[type]`, `refs`, `values`). Use `--width 3000` to see full values.
2. Write the spec (schema below).
3. `python3 intent_checks/build.py validate --lang <lang> --rows <row>` must print ✅.
   It checks, in order:
   - **structural**: schema, known kinds/ops, each `quote` is a verbatim prompt span,
     `source_hash` matches the current GT/prompt;
   - **positive control**: the ground truth passes every check;
   - **mutation control**: removing/altering exactly what each check targets makes that
     check fail (a survivor means the check is vacuous or over-broad);
   - **empty control**: no core check passes on an empty template;
   - **cross control** (warning only): other scenarios' ground truths that pass all your
     core checks — a long list means the core checks are too generic.
4. Iterate until ✅. Never loosen a check just to make a candidate pass — only the GT matters.

## Principles (most important first)
1. **Check only what the prompt states — resources AND values.** Every check carries
   `quote`, a verbatim span of the prompt (case/whitespace-insensitive) that the check
   operationalises. The quote anchors *which* requirement is checked; the **expected
   resource type, value, count and name must also come from the prompt** (stated, or
   unambiguously implied: "HTTPS" → 443, "any IP" → 0.0.0.0/0, "daily" → a daily schedule).
   Anything only in the ground truth — a literal IP/ARN/name/CIDR/metric name, a count the
   prompt doesn't give, specific AZ names, a naming helper (`random_pet`), a locals trick,
   a provider-version-specific attribute — is *inference space*: most models cannot predict
   it, so **do not check it, not even at `detail` tier**. When the prompt states behaviour
   without the exact value, check the behaviour ("across multiple AZs" → ≥2 subnets with
   different AZs, not `us-east-1a`/`b`). When in doubt, be lenient: a check exists to catch
   a template that fails the prompt, not one that differs from the ground truth.
   `validate` lints for this (`strictness_flags`: literals/counts not found in the prompt);
   each flag must be either removed or justified in `"justify"` on that check.
2. **Match by resource type + attributes, never by logical ID / resource name.** A
   generated template will name things differently. A literal name/value is checked only
   when the prompt states it (e.g. "named PetShopAPI").
3. **Accept every reasonable equivalent shape** with `any_of` (see list below). A correct
   template written differently from the ground truth must pass.
4. **Don't check computed/unknown-at-plan values** (ARNs, IDs, generated names) — link
   resources with `ref` checks instead.
5. **Tiers.** `core` = a primary resource the prompt asks for, or a load-bearing value it
   states explicitly (engine, runtime family, port, CIDR, protocol, exact name/count,
   encryption on/off, public/private). `detail` = secondary stated details (tags,
   descriptions, outputs, retention values, secondary names). Aim for roughly 40-60% core.
6. **Coverage.** Every concrete requirement in the prompt should map to ≥1 check. Typical
   size: L1 4-8 checks, L3 8-14, L5 12-25. Don't pad.
7. **Prompt/GT mismatch.** If the prompt states something the ground truth does not do,
   do NOT write a check the GT fails and do NOT weaken the prompt's meaning — omit it and
   record it in `"notes"` as `PROMPT_GT_MISMATCH: …` so a human can fix prompt or GT.

## Normalised input (what paths point into)
Each resource: `{"id", "cfg", "type", "values", "refs"}`. Paths are dotted into `values`.
`*` matches any list index / object key; a digit segment is a list index.

- **CFN**: `values` = `Properties`, with intrinsics resolved against parameter defaults and
  pseudo-params (`AWS::Region`=us-east-1). `Ref` to a parameter → its default (so a
  candidate that inlines the literal and one that parameterises it both match); `Ref`/`GetAtt`
  to a resource → `{"ref": "<LogicalId>", "attr": …}` and recorded in `refs`; `Fn::Sub`
  rendered to a string (`${Res}` placeholders kept); `Fn::If` resolved with default
  conditions; resources whose `Condition` is false under defaults are **excluded**. SAM
  templates are **expanded** (`AWS::Serverless::Function` → `AWS::Lambda::Function` + role +
  permissions/event sources, `AWS::Serverless::Api` → `AWS::ApiGateway::*` …) — write
  checks against the expanded types; a raw-CFN candidate then matches too.
- **TF**: `values` = the plan's planned `after` values (variables, defaults, `count`/`for_each`
  resolved). Nested blocks are lists (`ingress.*.from_port`, `versioning.0.enabled`), maps
  are objects (`tags.Name`). JSON-string attributes (`policy`, `assume_role_policy`,
  `container_definitions`) are strings — use `contains`/`regex`. Unknown-at-plan values
  are null. `id`/`cfg` are addresses (`module.vpc.aws_subnet.private[0]`); `refs` are config
  addresses resolved through modules, variables and root locals. Data sources have type
  `data.<type>`.
- **Both**: parameters/variables are pseudo-resources `__parameter__` (`values.name`,
  `values.default`); outputs are `__output__` (`values.name`, `values.value`,
  `values.description`, `refs` = resources the output references).
- **CFN resource attributes** (outside `Properties`) are under `values.__resource__`:
  `DeletionPolicy`, `UpdateReplacePolicy`, `UpdatePolicy`, `CreationPolicy`, `Condition`,
  `DependsOn` (always a list), `Metadata` (resolved). CFN outputs also carry `values.export`
  (the resolved `Export.Name`). For Terraform, `lifecycle` is only visible in
  `__declared__.values.properties.lifecycle`; explicit `depends_on` targets are included in
  `refs`.
- Keys containing dots (e.g. tag keys like `kubernetes.io/role/elb`) need a list path:
  `"path": ["tags", "kubernetes.io/role/elb"]`.
- **Both**: every resource (and, for TF, `data`) block the template *declares* is also a `__declared__`
  pseudo-resource (`values.type`, `values.name`, `values.gated` = has `count`/`for_each`/
  `Condition`, `values.gate` = the gating expression, `values.properties` = its configuration:
  resolved Properties for CFN, literal HCL attributes for TF, with `${...}` expressions left
  as strings) — **including ones the defaults do not instantiate** (which are absent from
  the planned/parsed resources above). So a capability that is off by default can still be
  checked for its configuration, e.g. `properties.Threshold` of a prod-only alarm.
  `__declared__` entries also carry `refs` (resources their configuration references) and
  the real logical ID / config address as `cfg`, so `ref` checks work between declared
  entries (e.g. a gated alarm → the gated DLQ it watches) and between declared and
  instantiated resources.
- **CFN IAM policy documents are canonicalised**: `Statement`, `Action`, `NotAction`,
  `Resource`, `NotResource` and `Principal.<type>` are always lists, so
  `Statement.*.Action.*` covers both the string and the list style.

### Default behaviour vs. declared capabilities (module-style scenarios)
Many scenarios are configurable modules: the prompt describes what the module *supports*
("supports replica keys", "optional dead-letter queue", "can create VPC links", "toggle
between creating a new group or using an existing one"), and the ground truth gates those
resources behind variables that are off by default — so the plan only contains 1-2
resources. Split the checks accordingly:
- **What the defaults create** → check the real type (strongest; e.g. `aws_kms_key` exists,
  with the stated default settings).
- **Optional / toggleable / "supports" capabilities** → check the capability is *declared*:
  `{"kind": "exists", "select": {"types": ["__declared__"],
   "where": [{"path": "type", "op": "eq", "value": "aws_kms_replica_key"}]}}`.
  Never match `values.name` (logical names are free). Prefer `any_of` over alternative
  resource types that deliver the same capability.
- **Configuration surface the prompt names explicitly** ("a `create` boolean variable
  defaulting to true", "a `name` variable defaulting to \"x\"") → `__parameter__` with
  `values.name` eq the stated name and `values.default` eq the stated default. Only when the
  prompt *names* the variable; if it only describes the behaviour, don't pin a name.
  Treat these as `detail` unless the prompt makes the variable the point of the scenario.
- Do not use `__declared__` for something the prompt says the defaults must create — use the
  real type so a template that declares it but never instantiates it fails.

## Spec schema
```json
{
  "lang": "tf", "row_number": 3,
  "source_hash": {"gt": "<from show>", "prompt": "<from show>"},
  "selectors": {"alb_sg": {"types": ["aws_security_group"],
                           "where": [{"path": "name", "op": "eq", "value": "alb"}]}},
  "checks": [ … ],
  "notes": "optional free text; PROMPT_GT_MISMATCH: … if any"
}
```
A selector is inline `{"types": [...], "where": [cond…]}` or the name of an entry in
`selectors`. `where` conditions filter resources (all must hold).

### Check kinds
| kind | fields | passes when |
|---|---|---|
| `exists` | `select`, optional `min` (≥1, default 1), `max`, optional `distinct_path` | selected count within [min, max]; with `distinct_path`, the number of *distinct values* at that path across the selected resources (e.g. `{"select": "subnets", "distinct_path": "availability_zone", "min": 2}` for "across two AZs" — never pin AZ names the prompt doesn't give) |
| `attr` | `select`, `cond`, optional `quantifier` (`some` default / `all`) | some (all) selected resource satisfies `cond` |
| `ref` | `from`, `to`, optional `bidirectional` | a `from` resource references a `to` resource |
| `join` | `from`, `from_path`, `to`, `to_path` | an attribute value of a `from` resource equals one of a *different* `to` resource (relationship by literal value — e.g. a metric filter's `LogGroupName` = a log group's name, an alarm's `MetricName` = a filter's metric name). Use in `any_of` with a `ref` when either wiring style is valid. |
| `any_of` | `checks`: list of leaf checks (no id/tier/quote) | any leaf passes |
| `all_of` | `checks`: list of leaf checks | every leaf passes (each is mutation-tested separately) |

Every top-level check has `id` (unique, snake_case), `kind`, `tier`, `quote`, and optionally
`justify` — a one-line reason a value the lint flags is implied by the prompt
(e.g. `"HTTPS implies port 443"`).
`any_of`/`all_of` cannot nest.

### Condition ops — `{"path": "...", "op": "...", "value": ...}`
Comparisons are on the string form, lower-cased (`80` == `"80"`, `true` == `"true"`).
`contains`/`regex` on an object- or list-valued path search its JSON-like text rendering
(OPA `sprintf("%v")`) — deliberately usable for "the policy document mentions X anywhere"
when the same content may be a string in one template and an object in another (SSM
`Content`, IAM `PolicyDocument`). Keep such patterns to distinctive tokens (action names,
service principals), not structure. (Covered by `tests/test_interpreter.py`.)
- `eq`, `neq`, `in` (value is a list), `contains` (substring), `regex` (Go RE2, case-sensitive;
  prefix `(?i)` for insensitive), `gte`/`lte` (numeric)
- `present` (not null/empty), `absent` (nothing non-null at path), `truthy`, `falsy`
- `none_eq` — no value at path equals `value` (for "only"/"exclusively"/"not public" intents,
  e.g. `{"path": "egress.*.cidr_blocks.*", "op": "none_eq", "value": "0.0.0.0/0"}`)
- `len_gte`/`len_eq` (list/object size at path)
- `glob_covers` — the value at path is an IAM-style wildcard pattern that grants `value`:
  `{"path": "Statement.*.Action.*", "op": "glob_covers", "value": "s3:GetObject"}` passes for
  `s3:GetObject`, `s3:Get*`, `s3:*`, `*`. Prefer this over `eq` for "grants/allows X" intents.
- Any non-`match`/`absent`/`none_eq` condition may add `"every": true`: at least one value
  exists at path and **all** of them satisfy the op (e.g. "only HTTPS": every ingress port is 443).
- `has_kv` — CFN tag item: `{"path": "Tags.*", "op": "has_kv", "value": {"key": "Env", "value": "prod"}}`
- `port_covers` — rule object whose from/to port range covers the number (or protocol -1):
  `{"path": "ingress.*", "op": "port_covers", "value": 80}`
- `match` — several sub-conditions that must hold on **one** element at `path`:
  ```json
  {"path": "ingress.*", "op": "match", "value": [
     {"path": "", "op": "port_covers", "value": 80},
     {"path": "cidr_blocks.*", "op": "eq", "value": "0.0.0.0/0"}]}
  ```
  (sub-condition paths are relative; `""` = the element itself; no nested `match`).

### Attribute + relationship in one leaf
A leaf is either an attribute test or a relationship. To require both ("a rule allowing
port 80 **attached to the ALB group**"), put the attribute conditions in the selector's
`where` and make the leaf a `ref`:
```json
{"kind": "ref", "to": "alb_sg",
 "from": {"types": ["aws_security_group_rule"],
          "where": [{"path": "type", "op": "eq", "value": "ingress"},
                    {"path": "", "op": "port_covers", "value": 80},
                    {"path": "cidr_blocks.*", "op": "eq", "value": "0.0.0.0/0"}]}}
```
(`"path": ""` addresses the resource's whole `values` object.)

## Equivalent shapes — use `any_of`
- **Security-group rules**: TF inline `ingress`/`egress` blocks on `aws_security_group`
  vs `aws_security_group_rule` (`type`=ingress) vs `aws_vpc_security_group_ingress_rule`
  (`from_port`/`to_port`/`cidr_ipv4`/`referenced_security_group_id`); CFN inline
  `SecurityGroupIngress` vs `AWS::EC2::SecurityGroupIngress` resources.
- **S3 settings (TF)**: inline blocks on `aws_s3_bucket` (`versioning`, `server_side_encryption_configuration`,
  `lifecycle_rule`, `website`) vs `aws_s3_bucket_versioning` / `_server_side_encryption_configuration` /
  `_lifecycle_configuration` / `_website_configuration` / `_public_access_block` / `_policy`.
- **IAM permissions**: inline policy vs managed policy + attachment (TF `aws_iam_role_policy`,
  `aws_iam_policy` + `aws_iam_role_policy_attachment`, `aws_iam_policy_document` data source;
  CFN `Policies`, `ManagedPolicyArns`, `AWS::IAM::Policy`, `AWS::IAM::ManagedPolicy`).
  Action lists may be a string or a list: `any_of` over `Statement.*.Action` and
  `Statement.*.Action.*`, or `contains` on a JSON string in TF.
- **Relationships by literal name** (e.g. an AppSync resolver's `DataSourceName`, a
  CloudWatch alarm's dimension) — `any_of` a `ref` with an `attr` on the name.
- **Versions**: don't pin exact runtime/engine versions unless the prompt does; use
  `regex` on the family (`^python3\\.`, `^postgres`).
- Case/format variants of enums (`HTTP` vs `http`) are handled by `eq` normalisation.

## Check against real candidates, not only the GT (added 2026-10-03)
Passing GT and mutation validation does not prove a check is lenient enough. A review against
the six ablation conditions' real outputs found about 30 checks that failed correct templates.
After `validate` passes, score the spec against real candidates. If a check fails in at least
3 of 6, look at what the candidates actually wrote before deciding whether to keep it.

**Terraform:**
- **Planned values can be unknown.** `jsonencode(...)` or a policy document that references a
  resource ARN plans as unknown, so the planned `policy` / `assume_role_policy` is null.
  - For IAM or KMS policy text, add an alternative leaf on `__declared__` (`properties` regex).
  - Include `data.aws_iam_policy_document` in the declared types.
- **`locals` are invisible.** A value held in a local is in neither the plan nor
  `__declared__`. When the prompt fixes the value, accept a reference to a local whose name
  states it (e.g. `local.cloudfront_zone_id`), or the variable default (`__parameter__` default).
- **Optional features are declared, not planned.** For a capability that is off by default,
  match the declared block (dynamic/count-gated), not the default-only plan.
- **"Declare default variables with X" means the default lives in a variable.** Accept
  `__parameter__` defaults.
  - A leaf matched by variable name can let a mutated GT survive when the GT has the same
    variable.
  - Match a map/object default by regex instead.
- **Fully data-driven designs.** When triggers and providers come from YAML config, values the
  prompt describes may be built only in locals. Drop checks that no encoding can reach, and
  record that in `notes`.

**Both languages:**
- **Accept every spelling of a service key.** E.g. Cloud WAN `add-to-network-function-group`
  vs `network-function-group`, or `via` vs `send-via`. A `regex` on the parent object works,
  because `%v` prints keys.
- **`%v` sorts object keys alphabetically.** A regex expecting `filter ... expiration` must
  also accept `expiration ... filter`.
- **Regex limits.** Use `(?s)` or `.{0,N}` to span newlines; `[^\n]*` stops at them.
  RE2 rejects repeat counts above 1000: `.{0,1500}` silently evaluates to false.
- **Accept every idiomatic API form.** E.g. Step Functions
  `aws-sdk:apigatewaymanagementapi:postToConnection` as well as `@connections`.
- **Accept a name string wherever a reference is valid.** E.g. a recipe selected by `Name`, a
  dimension holding a function name, a literal hosted-UI domain URL. Accept `Ref X` for an
  ARN output when that is what `Ref` returns.
- **Check the outcome, not the GT's structure.** E.g. "a synthetic always-OK alarm" is any
  `notBreaching` alarm that says so. "SSE applies when no KMS key is given" is satisfied by
  managed SSE on with no key under defaults.
- **Use the lowest count the prompt guarantees.** If it names only "the authenticated role"
  for a second setup, don't require an unauthenticated one too.
- **Deprecated values the prompt names.** E.g. `nodejs16.x` can no longer be used to create
  functions. Accept the family when the old value cannot be created.
- **Keep checks strict when the candidate contradicts the prompt.** Examples:
  - a missing named principal;
  - `aws:approve` instead of Change Manager;
  - an omitted `ActionsEnabled: false`;
  - invented FIS action IDs;
  - a CMK where the prompt asks for SSE-S3.

## What to report back
Per scenario: validation status, number of checks (core/detail), any `PROMPT_GT_MISMATCH`
notes, cross-control warnings, and anything the schema could not express (so the
interpreter can be extended rather than the check silently dropped).
