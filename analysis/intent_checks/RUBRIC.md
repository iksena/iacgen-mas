# Rubric for per-scenario Rego intent checks

Use this rubric to write a new intent check or to review an existing one. It covers the CloudFormation and Terraform checks in `intent_checks/` and the copy in `iacgen-mas/analysis/intent_checks/`.

It is derived from the interpreter (`lib/intent.rego`), the validation harness (`intent_core.py`), the authoring brief (`SPEC_BRIEF.md`) and the first 100 specs. Part 4 records how the current specs measure against it.

**The two copies are one artefact.** Specs, fixtures, validation reports and the manifest are byte-identical. Policies and `lib/intent.rego` differ only in comments. `intent_core.py` differs only in comments, docstrings, path constants and the generated-file header line.

**Scope.** Checks exist for all 500 benchmark rows (250 per language).

## 1. How a check is constructed

| Layer | File | What it does |
|---|---|---|
| Normalised input | `fixtures/`, `cache/candidates/` | Turns a template into `{id, cfg, type, values, refs}` resources, using a plan for Terraform and parsing plus SAM expansion for CloudFormation. |
| Spec | `specs/<lang>/row_NNN.json` | The only hand-written file. States what the prompt requires. |
| Policy | `policies/<lang>/row_NNN.rego` | Generated and holds no logic: `spec := {...}`, `results := lib.evaluate(spec)`, `targets := lib.targets(spec)`. |
| Interpreter | `lib/intent.rego` | The one evaluator for both languages. |
| Harness | `intent_core.validate()` | Runs the controls that decide whether a spec is valid. |

The input also holds three pseudo-resource types:

- `__parameter__`: parameters and variables.
- `__output__`: outputs.
- `__declared__`: every declared block, including ones the defaults do not create.

Each check has these parts:

- `id`, `tier` (`core`, `detail` or `extra`), `quote`, and optionally `justify`. An `extra` check needs no `quote` or `justify`.
- A `kind`, which is one of:
  - `exists`, with optional `min`, `max`, `distinct_path`.
  - `attr`, with optional `quantifier`.
  - `ref`, with optional `bidirectional`, so either resource may reference the other.
  - `join`, where `from_path` of one resource equals `to_path` of a different one.
  - `any_of` / `all_of` over those. These cannot nest.
- Selectors: `types` plus `where` conditions.
- Conditions: `path`, `op`, `value`, and optionally `every`. `SPEC_BRIEF.md` defines each operator.

Intent is a reporting axis and never feeds pass@1. `intent_strict` means every core check passes. `core_score` and `intent_score` are the shares of core checks and of all core and detail checks that pass.

The `extra` tier holds ground-truth resources and settings the prompt does not state. It measures whether a system produces them without being told, and is reported only as `extra_score` and `failed_extra`, so it never changes the scores above.

## 2. Criteria for each check

Score each check Meets, Partial or Fails. Score an `any_of` by its weakest branch, because that branch is enough to pass it.

For an `extra` check, C1, C2 and C9 work differently. Its value comes from the ground truth by design, but anything the prompt states must be `core` or `detail` instead, and it must not test an arbitrary identifier such as a resource name, ARN, account ID, tag value or description. The other criteria apply unchanged.

"Enforced by" shows how far the tooling can be trusted:

- **harness**: a failure makes the spec invalid.
- **lint**: a heuristic flag makes the spec invalid unless the check has a `justify`.
- **review**: nothing automated, so a person must judge it.

| # | Criterion | Meets | Partial | Fails | Enforced by |
|---|---|---|---|---|---|
| C1 | **Anchored in the prompt** | `quote` is a verbatim clause naming this one requirement. | Verbatim, but covers materially more or less than the check tests. A quote over a quarter of the prompt is a prompt to look, not a threshold. | Missing, not verbatim, or unrelated to what the check tests. | harness (verbatim), review (specificity) |
| C2 | **Expected values come from the prompt** | Every resource type, value, count and name is stated, or follows unambiguously ("HTTPS" → 443, "any IP" → 0.0.0.0/0), with `justify` where it is not literal. | Implied, but the inference is arguable, or a count is higher than the prompt guarantees. Includes requiring every example after "such as", unless the prompt makes them a required list. | Found only in the ground truth (literal ID, ARN, CIDR, AZ, name, count, naming helper), or `justify` relies on the ground truth. | lint, review |
| C3 | **Identity by type and attributes** | Resources are matched by type and attributes and linked by relationship. A literal name is tested only if the prompt states it. A name match on an output or parameter is fine as a branch beside a value or `ref` branch, on a word the prompt states. | A name match on an output or parameter is the only route to passing. | A resource is matched by logical ID, config address, or `__declared__.values.name`. | review |
| C4 | **Check shape fits the claim** | The check fails exactly when the claim is violated (see the table below). Linked claims about one resource bind to the same resource, or `notes` says why they can't. | Passes without the claim only in a rare prompt-compliant encoding, or is weaker than the claim, such as `some` where the prompt says "each". | Passes without the claim in a common prompt-compliant encoding, or cannot detect the violation at all. | review |
| C5 | **Path and operator are precise** | Narrowest usable path and the operator built for the value (see below). A whole-document `regex` or `contains` uses distinctive tokens, such as action names or service principals, and is used because the shape varies. | A whole-resource match on a generic word, such as `(?i)monitor`. | The pattern matches almost anything, or an operator quirk makes it pass or fail wrongly (see "Operator traps"). | review |
| C6 | **Equivalent forms are accepted** | `any_of` covers the idiomatic encodings of the requirement (see below). | Covers the common forms and misses a rare valid one. | Rejects a common valid form, or a form the spec's own `notes` accepts. | review |
| C7 | **Value is observable** | The value exists in the normalised input for any correct template. Computed values are replaced by `ref` checks. | Observable for the usual encoding only. | Tests a computed or unknown value (ARN, ID, generated name), or a value that can only sit in a Terraform `local`. | review, candidate review |
| C8 | **Default versus optional is respected** | Real resource type for what the defaults must create. `__declared__` for optional or toggled capabilities, or for reading declared text such as a policy. `__parameter__` only for variables the prompt names. | A named variable is `core` when it is not the point of the scenario. | `__declared__` used to show existence of something the prompt says must be created, or a real type for something off by default. | review |
| C9 | **Tier is right** | `core` is a primary resource or a load-bearing stated value (engine, port, CIDR, protocol, exact name or count, encryption, public or private). `detail` is a secondary stated detail (tags, descriptions, outputs, retention). Parallel requirements share a tier unless `notes` says why. | Debatable either way, or parallel requirements differ with no reason given. | A primary requirement is `detail`, or a cosmetic detail is `core`, changing `intent_strict`. | review |
| C10 | **Check can fail for the right reason** | Altering the target fails the check, and every `any_of` branch has evidence that it can pass: the ground truth, a real candidate, or a documented form. | An `any_of` branch has no such evidence. | Survives its mutation, or is true on nearly any template. | harness (mutation), review (branches) |

Three reading notes for C2:

- Values the adapter supplies for pseudo-parameters (`us-east-1`, `123456789012`) stand in for "this stack's region or account". They are valid only when the prompt asks for those, and only at a path they can't reach by another route.
- A natural attribute path needs no `justify` ("tagged as" → `tags.Name`).
- `justify` is for values and counts.

### Matching the shape to the claim (C4)

| The prompt claims | Use |
|---|---|
| X exists | `exists` |
| N of X, at least N | `exists` with `min` / `max`, using the lowest count the prompt guarantees |
| Across several AZs or other values | `exists` with `distinct_path`, never pinned values |
| X has value V | `attr` |
| Each or all X have V | `attr` with `quantifier: all` |
| Only, exclusively, not public | `none_eq`, or `every: true`, with `quantifier: all` when several resources can match |
| One rule or element meets several conditions | `op: match` |
| X is attached to or uses Y | `ref` |
| X names Y by literal value | `join`, inside `any_of` with a `ref` |
| A requirement has alternative encodings | `any_of` |
| A single quoted clause states several linked parts | `all_of` |
| Attribute and relationship together | Conditions in the selector's `where`, with a `ref` leaf |

### Choosing an operator (C5)

| Value | Use |
|---|---|
| "Grants or allows X" | `glob_covers`, so `s3:*` and `*` also count |
| Security-group or network-rule port | `port_covers`, or `match` with it and a CIDR condition. It reads only `from_port` / `to_port` and `FromPort` / `ToPort` keys, so a CloudFormation NACL's `PortRange.From` / `To` needs paired `lte` and `gte` instead. |
| Engine or runtime version | `regex` on the family, unless the prompt pins the version |
| Choice of enum values | `in` |
| Absence or a forbidden value | `absent`, `none_eq` |
| Policy text that may be a string or an object | Whole-document `regex` or `contains` on distinctive tokens |

### Operator traps (C5)

Each of these was confirmed by running OPA on the interpreter.

Can pass wrongly:

- `lte` and `gte` read a null as 0, because `to_number(null)` is 0. So `lte` passes on null, and so does `gte` with a value of 0 or less. A Terraform unknown is null. Don't use `lte` alone on a value that can be unknown; pair it with a `gte` above 0, as port-range checks do.
- `port_covers` with value 0 passes when both ports are null.
- `len_gte` on a string counts characters.
- `none_eq` and `absent` pass when the path is missing, so a misspelled or wrong-shape path passes silently. The mutation control catches this only for the ground truth's form.
- `neq` with a wildcard path passes if any one value differs. Use `none_eq` for "none of them".
- `eq` with a null value matches a null at the path.
- `present` passes on `false`, so it shows a value is set, not that it is on.
- `contains` or `regex` over a wide path can match a value from an unrelated field, such as a region inside an image URI, or a word every such resource contains, such as "backup" in a backup selection.
- `port_covers` also passes on an all-protocol (`-1`) rule, so a sibling allow-all rule satisfies a port check. Add a `protocol` condition when that matters.
- `present` on a selector with no value condition, or `exists` with an empty `where`, is true for any resource of the type, so it can't test a named claim.
- A planned Terraform default can make a check true when the template sets nothing: a planned `fifo_topic = false` exists whether or not it is declared. Check `__declared__` for "the template sets X".

Can fail wrongly:

- `\b` directly after `\*` never matches before a quote, bracket or end of text, so `s3:\*\b` rejects `"s3:*"`.
- `regex` is case-sensitive unless it starts with `(?i)`. Every other comparison is lower-cased.
- `regex` runs on OPA's `%v` text, which sorts object keys alphabetically. A repeat count above 1000 silently evaluates to false.
- `every: true` fails on an empty or missing path.
- `neq` fails on a missing path, so an omitted setting fails "not X". Use `none_eq`.
- `absent` on a list path fails on an empty list, because `[]` isn't null. Use `path.*` to mean "no items".
- `present` on a value that is unknown at plan fails, so it can't pass on a correct Terraform template.
- `falsy` fails on a null or missing value, so an unknown or omitted setting doesn't count as off.
- `gte` above 0 on a missing or null path fails, so a NACL entry with `Protocol: -1` and no `PortRange` can't satisfy a port-range condition. Give all-protocol entries their own branch.

### Equivalent forms to cover (C6)

- **Security-group rules:** inline blocks, `aws_security_group_rule`, `aws_vpc_security_group_ingress_rule`, and CloudFormation's inline `SecurityGroupIngress` or separate `AWS::EC2::SecurityGroupIngress`.
- **S3 settings in Terraform:** inline blocks or the separate `aws_s3_bucket_*` resources.
- **IAM permissions:** inline policy, managed policy plus attachment, or `aws_iam_policy_document`.
- **Terraform policy text:** planned JSON can be null when it references an ARN, so add a `__declared__` branch.
- **Terraform values held in a variable or local:** `__parameter__` default, or a reference to a local whose name states the value.
- **Relationships:** `ref` or a literal name (`join`, `attr`). ARN strings built from a stated name are common, and a `ref`-only check rejects them.
- **Service keys and API forms:** every spelling, such as `aws-sdk:apigatewaymanagementapi:postToConnection` and `@connections`.

## 3. Criteria for each scenario

| # | Criterion | Meets | Partial | Fails | Enforced by |
|---|---|---|---|---|---|
| S1 | **Traceable** | `source_hash` matches the current prompt and ground truth, the policy regenerates to the same bytes, and it holds no logic beyond `spec`, `results`, `targets`. | | Stale hash, or a hand-edited policy. | harness |
| S2 | **Positive control** | The ground truth passes every check. | | Any check fails on the ground truth. | harness |
| S3 | **Mutation control** | Altering each check's target makes that check fail. | | Any survivor. | harness |
| S4 | **Strictness lint** | No unjustified flags, and each `justify` explains how the prompt implies the value. | A `justify` is thin but plausible. | An unjustified flag, or a `justify` that relies on the ground truth. | lint, review |
| S5 | **Specific to the scenario** | No other scenario's ground truth passes all core checks. | Only near-duplicate or truly overlapping scenarios pass. | Many unrelated scenarios pass, so the core checks are generic. | warning only |
| S6 | **Checked on real outputs** | Scored against real candidates. Every check failing on most of them was inspected, as was any core check failing on even one, because a rare valid form fails only there. The outcome is in `notes` or the spec changed. | Scored, but the outcome of the inspection is not recorded. | Validated only against the ground truth. | review |
| S7 | **Covers the prompt** | Every concrete requirement has at least one check. A concrete requirement is a resource, value, relationship or behaviour a template could visibly violate. What cannot be expressed is in `notes`. | A secondary requirement is unchecked and unexplained. | A primary requirement is unchecked and unexplained. | review |
| S8 | **Mismatches handled** | Where prompt and ground truth disagree, the check is omitted, or keeps only what both guarantee, and `notes` has `PROMPT_GT_MISMATCH: ...`. A mismatch on a primary requirement also flags the row for prompt or ground-truth repair. | Handled correctly but not recorded. | The check rejects a template faithful to the prompt, or passes a template that violates it because of the mismatch. | review |
| S9 | **Balanced** | Check count and core share are inside the middle 50% below, or outside with an evident reason (a long prompt, or a short one where nearly everything is primary). | Outside with no evident reason. | Padded with redundant checks, or too few to reflect the prompt. | review |
| S10 | **Tiers keep the two questions apart** | Everything the prompt states is `core` or `detail`, and `extra` holds only ground-truth resources and behaviour-bearing settings the prompt doesn't state. Every ground-truth resource type has a check. | A resource type has no check, or an `extra` setting adds little. | A stated requirement is only `extra`, or an `extra` check tests an arbitrary identifier. | `build.py extras`, review |

**Norms for S9**, from the 100 current specs:

| Level | Specs | Checks, middle 50% | Median | Range | Core share, middle 50% |
|---|---|---|---|---|---|
| L1 | 6 | 8–10 | 10 | 7–10 | 52–82% |
| L2 | 14 | 9–15 | 13 | 5–18 | 54–72% |
| L3 | 20 | 14–21 | 16 | 8–33 | 48–55% |
| L4 | 26 | 17–23 | 19 | 10–43 | 47–58% |
| L5 | 34 | 16–24 | 21 | 12–39 | 47–59% |

### Accepting a spec

- **Accept** when S1–S4 all Meet and nothing Fails. Partial scores don't block acceptance, but record any you keep on purpose in `notes`.
- **Revise** when anything Fails. Fix the check. Never loosen it only to make one candidate pass, and never add a check the ground truth fails.

C2 and C3 outrank the others. A check that tests a detail only the ground truth contains measures guessing, not intent, however well built it is. When in doubt, be lenient.

## 4. How the current specs measure against this rubric

### All 500 rows

On 2026-11-12 all 500 specs validate. In the replication repo every regenerated policy passes on its own ground truth (see the check run there). The 400 specs added in this round were written by Sonnet agents and reviewed on real templates: up to 5 per CloudFormation row and up to 3 per Terraform row. 13 Terraform rows had no template that could be planned, so they had no such review.

**Validation alone doesn't show a spec meets this rubric, so the new specs were audited and revised.** Two Opus auditors graded a stratified sample of 20 new specs and would have revised 16, with 32 failing checks and 22 stated requirements left uncovered. Those 20 were fixed. The other 380 were then each graded and revised by an Opus agent against the rubric, using the defects below as a checklist. The agents reported 1,100 failing checks fixed, 238 requirements added, 477 over-strict checks relaxed, and 44 specs left unchanged. These counts are the agents' own.

Two measures check the revision independently:

- **Real templates:** on the 368 revised specs that had real templates, the share of templates passing all core checks went from 82.7% to 84.1% for CloudFormation and from 83.7% to 86.8% for Terraform. Revision did not simply tighten everything; it relaxed over-strict checks about as much as it tightened weak ones.
- **Second audit:** two fresh Opus auditors graded a different stratified sample of 20 revised specs. They would have revised 2 of 20, with 3 failing checks and 9 uncovered requirements, down from 16, 32 and 22. Those two specs were fixed (CFN 132 and TF 61).

That is one sample of 20 per round, so it is evidence of a large improvement, not a defect rate for the other 360. The auditors still scored about two Partials per spec, which are not blockers. The defects found most often, and worth checking in any new spec, were:

- A weak `any_of` branch or presence test that passes without the claim.
- Claims of "only" or "exclusively" tested as a positive match, so an added rule still passes.
- Grants not bound to the role the prompt names.
- Valid forms rejected, such as `AWS::Route53::RecordSetGroup` or an omitted setting.
- A "private subnet" test that also counts the public subnet hosting an optional NAT gateway, since that subnet usually leaves `MapPublicIpOnLaunch` unset.
- A stated goal present only in `extra`.
- `notes` calling something inexpressible when it isn't.

The operator-trap sweep that found these in the new specs now counts: `falsy` 51 conditions in 34 specs, `neq` 12 in 6, list-path `absent` 6 in 5, `port_covers` 160 in 23, short generic whole-resource patterns 14 in 12. Each is a prompt to look, not a defect.

Other points to know:

- **Tiers across rows:** the first 100 specs have no `extra` checks, so `extra_score` covers only the 400 new rows.
- **Mismatches:** 64 CloudFormation and 21 Terraform specs record `PROMPT_GT_MISMATCH`. Those prompts or ground truths may deserve repair.
- **Specificity:** 35 of 500 specs have another scenario's ground truth passing all their core checks. None of these have been judged individually.
- **Not scored yet:** no run has been scored on the 400 new specs, so the stored `intent_results` still cover the first 100 rows only.
- **Fixtures:** TF 368's fixture swaps an Ubuntu AMI name LocalStack lacks (`FIXTURE_PATCHES` in `intent_core.py`), and CloudFront managed cache policies are seeded into LocalStack at plan time. Older AWS provider pins plan with `tflocal`'s override trimmed. Running plans needs LocalStack; validation does not.

### The first 100 rows

Measured on 2026-11-09 by re-running validation for the first 100 specs, after the fixes described below.

**Size:** 1,798 checks, of which 953 are core and 845 detail. By kind: `any_of` 513, `exists` 417, `attr` 400, `all_of` 240, `ref` 224, `join` 4.

| Criterion | Evidence | Reading |
|---|---|---|
| C1 | All quotes are verbatim. 10 quotes cover at least 25% of their prompt, 2 cover at least 50%. | Sound, with a few broad anchors. |
| C2 | 402 lint flags, all justified. Of 392 `justify` strings, a pattern search found 1 mentioning the ground truth, and it says the ground truth's shape is not prescribed. | Sound as far as the tooling can see. See finding 2. |
| C4 | Of 34 negative `attr` conditions, 25 use `some`. Only 1 of those (a detail check) selects several ground-truth resources with no `where` narrowing. Across the 8-spec sample, C4 drew the most Partial scores. | See finding 1. |
| C5 | 133 whole-resource `regex` / `contains` conditions, 92 of them in core checks. | Allowed by design. Generic patterns need review. |
| C10 | Every check fails when its target is altered. 315 of 1,274 `any_of` branches have never passed on the ground truth or a real candidate. | See finding 3. |
| S5 | Mean core pass rate on unrelated ground truths is 2.7%. Three specs have an unrelated scenario passing all core checks: CFN 139 (with 186), TF 26 (with 76, 91, 156, 164), TF 114 (with 250). | Strong specificity. TF 26 is a small L1 VPC, so its overlap is expected. |
| S6 | Across 8 conditions (795 evaluated runs): 86% of core and 81% of detail checks never failed. 1 core and 1 detail check failed every time. | See finding 8. |
| S7 | 44 prompt sentences, in 40 specs, have no quote touching them. 33 are generic opening sentences, and most others are list headers whose items are checked. | Few real gaps at sentence level, such as CFN 92's "no additional resources". The sample found narrower unchecked clauses inside quoted sentences. |
| S8 | 11 specs record `PROMPT_GT_MISMATCH`. | Working as intended, and these prompts or ground truths may deserve a fix. CFN 77 is one: its ECR repository, health check and auto-deploy go unmeasured. |

**Blind test.** A reviewer who had not seen this part applied the rubric to 8 specs (127 checks) by reading them. It scored 47 checks Partial and 3 Fails, most of them on C4. The sample was hand-picked across levels and included specs with known flags, so these are not corpus rates. One reviewer gives no inter-rater figure. The items under "Fixes applied" and finding 1 were then checked in OPA or against real runs. The review also led to the clearer wording now in C1, C3, C4, S7, S8, S9 and the acceptance rule.

### Fixes applied on 2026-11-09

Both specs re-validate after these changes, and all 795 stored runs were re-evaluated. Only the rows below changed in the results.

**TF 369**

- `replica1_buckets` and `replica2_buckets` rejected replica names keeping the source bucket's account suffix, although the spec's notes and its `rep` selector accept them and the prompt says "named after the source bucket". They now accept the suffix.
- 5 policy regexes in 3 checks used `\b` after `\*`, which disabled their wildcard alternatives. They now end in `([^A-Za-z0-9_]|$)`. No result changed.
- `replica_reencryption_key` couldn't tell the replica key from the source bucket's own key. It now tests the declared `replica_kms_key_id`. That the key belongs to the destination region is still not expressible. As an `attr` check it now counts towards `attribute_score`, not `relationship_score`.

**CFN 77**

- `env_region_and_account`, `env_email_and_admin` and `env_quicksight_identifiers` searched all of `SourceConfiguration`, so an image URI could satisfy the first with no variables set (confirmed with a synthetic input). They now read `RuntimeEnvironmentVariables`. No result changed.

**Effect on scores:** Terraform `intent_strict` rises from 82.0% to 84.0% for `baseline` and from 83.7% to 85.7% for `no-dense-rag`. In `result/ablation_significance.csv`, only Terraform `intent_strict` and `core_score` rows changed, and every Holm-adjusted p-value for them is still 1.0.

**Updated:** the spec, policy and validation files; `ablation_selection/intent_results/`; `ablation_intent_50rows.csv`; `result/ablation_significance.csv`; `Ablation_Intent_Analysis.ipynb`; and the `H5_quality_intent.csv` and `J_ablation_simple.csv` tables. All were synced to `iacgen-mas` where a copy exists. The previous versions are in `data_analysis/intent_checks/backups/20261109_before_tf369_cfn77/`.

**Still stale:** the stored outputs of `IaCGOD_Repair_Loop_Analysis.ipynb` (cells 43 and 55) and its `H5_size_vs_intent.png` show the old values until that notebook is next re-executed.

### Findings

These are open.

1. **Some checks can pass or fail for the wrong reason, and the mutation control can't see it.** The control only shows that a check depends on what it targets, not that it targets the right thing. Each selector is also matched independently, so two checks can pass on different resources. The harness can't detect any of this, which makes C4 the criterion most in need of human review. One known case remains: `policy_scoped_to_buckets_and_keys` in TF 369 (detail) accepts only `ref` links, so a policy using literal bucket ARNs fails it, as in the `baseline` and `opencode-retriever` runs. Fixing it needs a design choice, because an `all_of` leaf can't hold alternatives.
2. **The strictness lint cannot prove prompt-only values.** It matches word fragments as substrings and accepts a value when half its tokens hit, so `PAY_PER_REQUEST` passes on a prompt saying "the permissions for the request", and `states.amazonaws.com` passes on "the statement". A regex passes if any one token hits. A count passes if the quote holds any digit or number word, whatever the number. Of 1,913 unjustified string literals, 369 pass on token matches alone. A sample of 22 looked like reasonable vocabulary translations, but the rest have not been reviewed. Literal IPs, CIDRs and ARNs are strict and do get flagged. Treat a clean lint as a filter, and keep C2 as a review item.
3. **A quarter of the `any_of` branches have never been exercised.** Of 1,274 branches, 643 are false on the ground truth, so the positive control doesn't reach them and the mutation control has nothing to alter. Real candidates exercised 328 of those, which leaves 315 (25%) that have never passed on anything, in 230 checks across 66 specs. Many are probably valid alternatives no model happened to write, but a defect in one would silently fail a correct candidate, as the `\b` regexes in TF 369 did. All 100 specs were scored against real candidates in the 2026-10-03 review, though only 20 specs' notes record it. The most useful control to add is a lint of branch paths and types against the resource schemas (`cfn-schema/`, the Terraform provider schema).
4. **The empty control cannot fail.** Harness rules guarantee it: `exists` needs `min` of at least 1, and every other kind needs a selected resource. It costs nothing, but it should not be cited as evidence of non-vacuity. The mutation control is the real evidence.
5. **`any_of` passes on its weakest branch, and "no nesting" encourages weak branches.** In the sample, standalone-rule branches often test less than their inline counterparts, because a branch can't combine alternatives. Some specs record this in `notes` (TF 164). Score these under C4.
6. **Interpreter null handling is a latent risk with no measured effect today.** All 36 `lte` / `gte` uses were read. They are mostly port-range pairs, where the matching `gte` above 0 fails on null, plus one retention threshold (a `gte`). The only unpaired `lte` is the detail check `nacl_open_egress` in CFN 176.
7. **Category scores are approximate.** `check_category` looks only at the first branch, and 222 of 753 composite checks mix kinds, so `resource_score`, `attribute_score` and `relationship_score` should be read as rough. An `all_of` also counts as one check however large it is (the largest has 30 leaves), so `intent_score` weights requirements unevenly.
8. **Low failure rates don't prove the checks are too lax.** The eight conditions share one model and most outputs passed deployment, so they are similar to each other. This data can't separate lenient checks from a capable model. Testing that would need outputs from weaker models or deliberately wrong templates. The one core check that failed in all 8 conditions, `association_monitor_type` in CFN 47, is recorded in that spec's notes as a real miss.
9. **`SPEC_BRIEF.md` understates spec size.** It suggests L1 4–8, L3 8–14 and L5 12–25 checks, while specs have medians of 10, 16 and 21 and reach 39 at L5. Use the table in this rubric.
