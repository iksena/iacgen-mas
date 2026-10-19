# IaCGen-MAS

IaCGen-MAS is a multi-agent LLM system that generates deployable Infrastructure-as-Code from a natural-language request. It supports **AWS CloudFormation** (YAML) and **HashiCorp Terraform** (HCL). Every template is linted, scanned for security issues, and deployed (to live AWS or LocalStack) before a run counts as passing. Failed checks drive a retrieval-grounded repair loop.

This repository contains the system's code, prompts, knowledge-base ingestion scripts, benchmark datasets, and the experiment results reported in the thesis.

## Architecture

```
user request
     │
     ▼
 ┌─────────┐   numbered Grounded Objectives
 │ Planner │──────────────────────────────┐
 └─────────┘                              ▼
                                    ┌──────────┐
                     ┌─────────────▶│ Engineer │  writes / repairs the template
                     │              └────┬─────┘
                     │                   ▼
                     │              ┌───────────┐  syntax → security → deploy
                     │              │ Validator │  (each group runs only if the previous passed)
                     │              └────┬──────┘
                     │        pass or    │ fail
                     │     budget used ──┴──▶ END
                     │                   ▼
              ┌────────────┐        ┌───────────┐
              │ Remediator │◀───────│ Retriever │  query rewriting + hybrid retrieval
              └────────────┘        └───────────┘
               root-cause analysis
               + fix objectives
```

The agents are nodes of a LangGraph state machine (`graph.py`) that share one `GraphState` (`state.py`).

| Agent | File | Role |
|---|---|---|
| Planner | `agents/planner.py` | Turns the request into a numbered list of Grounded Objectives, fixed for the whole run. |
| Engineer | `agents/engineer.py` | Writes the first template from the objectives; on later iterations repairs it using the Remediator's fix plan and the validation errors. |
| Validator | `agents/validator.py` | Runs the checks in order. **Syntax**: YAML parsing + cfn-lint (CloudFormation), TFLint + `terraform validate` (Terraform). **Security**: Trivy, failing on critical/high findings. **Deploy**: `create_stack` or `terraform apply` against AWS or LocalStack, always torn down afterwards. |
| Retriever | `agents/retriever.py` | Rewrites validator errors into search queries and gathers context from the knowledge stores. |
| Remediator | `agents/remediator.py` | Produces a root-cause analysis and numbered fix objectives from the errors and retrieved context. |

### Retrieval streams

| Stream | Store | Triggered by | Implementation |
|---|---|---|---|
| Semantic | ChromaDB (`cfn_schema_properties`, `tf_schema_properties`) | syntax / deploy failures | Rewritten queries, top-3 chunks per query, cosine distance ≤ 0.40, restricted to resource types in the template, fused with reciprocal rank fusion (k = 60). |
| Schema | Neo4j | syntax / deploy failures | Cypher lookup of each resource type's description, required and optional properties, nested blocks, and an example. |
| Security | Neo4j | security failures | Trivy rule IDs looked up directly; returns description, remediation, compliant example, and Rego policy source. |

`tools/cfn_hybrid_rag.py`, `tools/tf_hybrid_rag.py`, and `tools/security_hybrid_rag.py` implement the three streams.

## Repository layout

```text
.
├── agents/               Planner, Engineer, Validator, Retriever, Remediator, LLM client
├── prompts/              Prompt templates for each LLM-driven agent (CloudFormation and Terraform)
├── tools/                Validators, deployment and cleanup, template annotation, hybrid RAG
├── tracking/             Per-run recorder (LLM calls, tool calls, iteration snapshots)
├── scripts/
│   ├── graphrag/         CloudFormation knowledge-base ingestion (01–05)
│   │   ├── terraform/    Terraform knowledge-base ingestion (01–05)
│   │   └── security/     Security knowledge-base ingestion (00, 01, 04)
│   └── nuke_vpc_dependencies.py   AWS account cleanup helpers used by the deploy stage
├── baselines/            Zero-shot and OpenCode coding-agent baselines (see Baselines)
├── benchmark/            Multi-DPIaC-Eval: scenarios and reference templates
├── data/                 Benchmark datasets and security-ingestion inputs
├── results/              Experiment results reported in the thesis
├── analysis/             Benchmark construction, audits, and analysis notebooks (see analysis/README.md)
├── examples/             Full trace of the thesis example run (see Example run)
├── main.py               Run one request
├── benchmark.py          Run a dataset of requests
├── graph.py              LangGraph definition and routing
├── state.py              Shared graph state
├── config.py             LLM and deployment configuration
├── docker-compose.yml    Neo4j + ChromaDB
└── localstack-docker-compose.yml   LocalStack Pro (optional deploy target)
```

## Setup

### 1. Python

Python 3.12 or newer (tested with 3.13).

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install --upgrade boto3==1.43.90
```

`requirements.txt` pins `boto3==1.35.49` because checkov requires it. Upgrading boto3 afterwards enables CloudFormation `DescribeEvents`, which the deploy stage uses to report early-validation failures; checkov keeps working with the newer version.

### 2. External tools

These must be on `PATH`:

| Tool | Used for | Version used in the thesis |
|---|---|---|
| `terraform` | `terraform validate` / `apply` / `destroy` | 1.14 (AWS provider 5.100) |
| `tflint` | Terraform linting | 0.61 |
| `trivy` | Security scanning (the check bundle is pinned in `tools/validators.py`) | 0.71.2 |
| `ollama` | Embeddings (`mxbai-embed-large`) | — |
| Docker | Neo4j, ChromaDB, LocalStack | — |

`cfn-lint` (1.48), `checkov`, and `tflocal` (Terraform on LocalStack) are installed by `requirements.txt`.

```bash
ollama pull mxbai-embed-large
```

### 3. Environment

```bash
cp .env.example .env
```

Fill in at least one LLM provider key (`OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `DEEPSEEK_API_KEY`). Keep `EMBEDDING_PROVIDER=ollama` and `EMBEDDING_MODEL=mxbai-embed-large`; the same embedding model must be used to build and to query ChromaDB. For live AWS deployment, configure `AWS_PROFILE` and `AWS_DEFAULT_REGION`. For LocalStack, set `LOCALSTACK_AUTH_TOKEN`.

`config.py` loads `.env` automatically for `main.py` and `benchmark.py`. The ingestion scripts read the environment directly, so export it first:

```bash
set -a && source .env && set +a
```

### 4. Knowledge stores

Start Neo4j and ChromaDB:

```bash
docker compose up -d
```

Run every ingestion script from the repository root, in the order below. `04_import_cfn_to_neo4j.py` clears the whole Neo4j database before importing, so if you rerun it, rerun the Terraform and security imports afterwards. A full build takes about two hours on an Apple-silicon laptop, mostly the documentation scrape (about 35 minutes) and the embedding steps (about 25 minutes for CloudFormation and 40 for Terraform).

**CloudFormation** (downloads the resource specification, scrapes the AWS documentation, merges both, and loads Neo4j and ChromaDB). The specification is AWS's current one, so a new build covers more resource types than the thesis build did:

```bash
python scripts/graphrag/01_download_cfn_spec.py
python scripts/graphrag/02_scrape_cfn_docs.py
python scripts/graphrag/03_parse_and_merge.py
python scripts/graphrag/04_import_cfn_to_neo4j.py
python scripts/graphrag/05_build_chromadb.py
```

**Terraform** (downloads the AWS provider schema and Terraform Registry documentation, merges both, and loads Neo4j and ChromaDB). The provider is pinned to 6.47.0, the version used in the thesis:

```bash
python scripts/graphrag/terraform/01_download_tf_schema.py
python scripts/graphrag/terraform/02_fetch_tf_registry_docs.py
python scripts/graphrag/terraform/03_parse_and_merge_tf.py
python scripts/graphrag/terraform/04_import_tf_to_neo4j.py
python scripts/graphrag/terraform/05_build_tf_chromadb.py
```

**Security** (Aqua AVD checks and Trivy Rego policies into Neo4j). `data/security_checks.json` holds the checks used in the thesis, so importing it is enough:

```bash
python scripts/graphrag/security/04_import_security_to_neo4j.py
```

To refresh the checks from the live AVD first, run the two preparation steps before the import. They overwrite `data/avd_scraped.json`, `data/trivy_enriched.csv`, and `data/security_checks.json`:

```bash
python scripts/graphrag/security/00_scrape_avd_docs.py
python scripts/graphrag/security/01_load_trivy_csv.py
```

The intermediate files these pipelines produce (`cfn_resource_spec.json`, `scraped_html/`, `cfn_knowledge_graph.json`, `tf_schema_raw.json`, `tf_registry_docs.json`, `tf_knowledge_graph.json`) are written to the repository root and ignored by git.

### 5. LocalStack (optional)

```bash
docker compose -f localstack-docker-compose.yml up -d
```

The deploy stage resets all LocalStack state before every deployment, so give IaCGen-MAS a LocalStack instance of its own.

## Usage

### Single request

```bash
python main.py \
  --request "An S3 bucket with versioning enabled and a CloudFront distribution in front of it" \
  --iac-type cloudformation \
  --provider openrouter --model deepseek/deepseek-v4-flash \
  --deploy-target aws \
  --max-iterations 15
```

### Benchmark

```bash
python benchmark.py \
  --iac-type terraform \
  --dataset data/tf_eval_benchmark_real_aws.csv \
  --provider openrouter --model deepseek/deepseek-v4-flash \
  --deploy-target aws \
  --max-iterations 15
```

Useful options:

| Option | Meaning |
|---|---|
| `--iac-type` | `cloudformation` or `terraform` |
| `--provider` / `--model` | `openrouter`, `claude`, `openai`, or `deepseek`, and the model ID |
| `--deploy-target` | `aws`, `localstack`, or `none` |
| `--max-iterations` | Iteration budget (15 in the thesis) |
| `--skip-security` / `--skip-deploy` | Disable the security or deploy stage |
| `--rows`, `--start-row`, `--max-rows` | Run a subset of the dataset (`--rows` takes `row_number` values) |
| `--exclude-completed-csv`, `--retry-errors` | Resume or retry against an earlier `results.csv` |
| `--openrouter-reasoning-effort`, `--openrouter-reasoning-max-tokens`, `--disable-reasoning`, `--max-tokens`, `--no-max-tokens` | Reasoning and output-token settings |

`benchmark.py` writes `results.csv`, `results.jsonl`, `results.json`, and `summary.json` to `benchmark_runs/<iac_type>_<timestamp>/`. Each scenario also gets a folder under `runs/<run_id>/` with `llm_calls.jsonl`, `tool_calls.jsonl`, per-iteration snapshots, and `final_report.json`.

### AWS cleanup

Deployments are torn down after every attempt. The thesis experiments additionally swept the account with [aws-nuke](https://github.com/ekristen/aws-nuke). `nuke-config.yml` is a template; replace the placeholder account and user before use. `scripts/nuke_vpc_dependencies.py` removes VPC dependencies that aws-nuke cannot delete on its own:

```bash
python scripts/nuke_vpc_dependencies.py --profile default --dry-run
```

Both delete real resources. Use them only in a dedicated test account.

## Baselines

`baselines/` holds the two baselines IaCGen-MAS is compared with. Both read the same datasets, score templates with the IaCGen-MAS Validator, and write the same outputs as `benchmark.py`. `--rows`, `--start-row`, `--max-rows`, `--exclude-completed-csv`, `--retry-errors`, and `--deploy-target` work as in `benchmark.py`; `--deploy-target none` runs the static checks only.

| File | Purpose |
|---|---|
| `baselines/zeroshot_baseline.py` | Zero-shot baseline: one LLM call per scenario with IaCGen's first-generation prompt and no repair loop; the template is validated once. |
| `baselines/zeroshot_prompts.py` | IaCGen's prompts, copied verbatim (the Terraform pair is the IaC-Eval prompt IaCGen carries), and IaCGen's template extraction. |
| `baselines/opencode_baseline.py` | Coding-agent baseline: runs OpenCode once per scenario in an isolated workspace, then scores the template it leaves, validating and deploying it again if the agent did not. |
| `baselines/opencode_driver.py` | Writes the OpenCode configuration (model endpoint, MCP server, tool allowlist), parses OpenCode's event stream into token counts and transcripts, and flags sessions that touched files outside their workspace. |
| `baselines/mcp_server.py` | MCP server started by OpenCode, exposing `validate_iac`, `deploy_iac`, and `submit_template`. |
| `baselines/evaluation.py` | State behind the three tools: one `validate_iac` call is one iteration, the iteration cap, deployment only after static validation passed, the Engineer's error format, and per-iteration snapshots. |
| `baselines/prompts/` | OpenCode system prompts for CloudFormation and Terraform. |

### Zero-shot

Takes the LLM options of `benchmark.py` (`--provider`, `--model`, and the reasoning and token flags):

```bash
python -m baselines.zeroshot_baseline \
  --iac-type cloudformation \
  --dataset data/cfn_eval_benchmark_real_aws.csv \
  --provider openrouter --model deepseek/deepseek-v4-flash \
  --deploy-target aws \
  --rows 1
```

The extra column `extraction_method` records whether the model wrapped the template in the requested tags (`iac_template_tags`) or it was recovered by a fallback.

### OpenCode

Needs the [OpenCode](https://opencode.ai) CLI on `PATH` (1.18.30 in the thesis) and `git`. OpenCode reaches the model through an OpenAI-compatible endpoint, OpenRouter by default:

```bash
python -m baselines.opencode_baseline \
  --iac-type terraform \
  --dataset data/tf_eval_benchmark_real_aws.csv \
  --model deepseek/deepseek-v4-flash \
  --deploy-target aws \
  --max-iterations 15 \
  --rows 1
```

For another endpoint, pass `--base-url`, `--api-key-env` (the variable holding its key), and `--provider-name`, e.g. `--base-url https://api.deepseek.com --api-key-env DEEPSEEK_API_KEY --provider-name deepseek-direct --model deepseek-v4-flash`. `--provider-name` must not be a provider OpenCode ships with (`deepseek`, `openai`, ...).

Each scenario runs in `runs/<run_id>/workspace`, which is initialised as its own git repository so that OpenCode denies every path outside it. The agent may only read, write, and edit files and call the three tools; it has no shell. A session that still touches a path outside the workspace is recorded as `status=workspace_escape` and counted as a failure. The extra column `final_verdict_source` records how the final template was scored (`recorded`, `deployed_at_finalize`, `revalidated`, or `no_template_produced`). `--scenario-timeout` (default 1800 s) bounds each session, and `--keep-workspace` keeps the agent's files.

## Datasets

| File | Benchmark | Scenarios |
|---|---|---|
| `data/cfn_eval_benchmark_real_aws.csv` | Multi-DPIaC-Eval, CloudFormation | 250 |
| `data/tf_eval_benchmark_real_aws.csv` | Multi-DPIaC-Eval, Terraform | 250 |
| `data/cfn_eval_benchmark_ablation.csv` | Ablation subset, CloudFormation | 50 |
| `data/tf_eval_benchmark_ablation.csv` | Ablation subset, Terraform | 50 |
| `data/iac_with_difficulty_levels.csv` | DPIaC-Eval (CloudFormation) | 153 |
| `data/iac_eval_benchmark.csv` | IaC-Eval (Terraform) | 458 |

Columns: `row_number`, `ground_truth_path`, `prompt`, and a difficulty level. The system needs only the prompt; the reference templates are used by the analysis.

## Benchmark

`benchmark/` holds Multi-DPIaC-Eval, the 250 CloudFormation and 250 Terraform scenarios whose reference templates all deploy to a fresh AWS account, pass the linter, and have no critical or high Trivy finding.

```text
benchmark/
├── cloudformation/
│   ├── cfn_eval_benchmark_real_aws.csv            row_number, ground_truth_path, prompt, difficulty
│   ├── final_benchmark_real_aws_with_prompts.csv  source repository, licence, size, resource types, check results
│   └── ground_truth/                              one reference template per scenario
└── terraform/
    ├── tf_eval_benchmark_real_aws.csv
    ├── final_benchmark_real_aws_with_prompts.csv  source, size, check results, reference code
    └── ground_truth/                              one folder of .tf files per scenario
```

Paths in these CSVs are relative to the language folder, e.g. `benchmark/cloudformation/ground_truth/cfn_templates/...`. The CSVs in `data/` hold the same scenarios and prompts with the paths used during the experiments: `cfn_templates/...` maps to `benchmark/cloudformation/ground_truth/cfn_templates/...` and `iac_benchmark/scenarios.../` to `benchmark/terraform/ground_truth/scenarios.../`. The ablation subsets in `data/` are subsets of these scenarios. `cfn_templates_greenfield/` and `scenarios_greenfield/` hold references that were minimally fixed to deploy into an empty account.

## Results

`results/` holds one folder per experiment, named `<Language>_<Benchmark>_<System>_<Model>`:

- **Language**: `CFN` (CloudFormation) or `TF` (Terraform)
- **Benchmark**: `RealAWS` (Multi-DPIaC-Eval on live AWS), `DPIaCEval`, `IaCEval`, or `Ablation` (50 scenarios per language on LocalStack); `LintOnly` = IaC-Eval run checked by TFLint and `terraform validate` only
- **System**: no tag = IaCGen-MAS; `OpenCode` = coding-agent baseline; `OneShot` / `ZeroShot` = zero-shot baseline; `IaCGen` = IaCGen baseline. In the ablation, `IaCGOD` is the full IaCGen-MAS and the other tags name the removed or changed component (`NoPlanner`, `NoDenseRAG`, `NoGraphRAG`, `NoQueryRewrite`, `NoRemediator`, `OpenCodeRetriever`, `TrivyAllSeverities`).
- **Model**: `DSV4F` DeepSeek-V4-Flash, `GLM53F` GLM-5.3-Flash, `Gemini38F` Gemini-3.8-Flash, `Opus55` Claude-Opus-5.5, `o3mini` o3-mini
- **Suffix**: `DeployOnly` = deployability-only criterion (no security gate); `L345` = difficulty levels 3–5 only; `PlanOnly` = no deployment and no security gate, a template passes when TFLint, `terraform validate`, and `terraform plan` accept it; `LiveAWS_GLM` = ablation scenarios deployed to live AWS with GLM-5.3-Flash. `FirstAttempt` = the first iteration of the scenarios whose first iteration was blocked by an environment error, run again with one iteration; the repair-loop notebook counts these passes at every passItr@n.

Unless noted, a scenario passes under the joint criterion: no syntax error, no critical or high Trivy finding, and a successful deployment.

Each experiment folder contains:

| File | Content |
|---|---|
| `results_final.csv` | One row per scenario: pass/fail, iterations, token usage, final template, deployment outcome, and per-stage errors. |
| `attempts_all.csv` | Every attempt of every scenario, with a `validity` label (`valid_pass`, `valid_fail`, `superseded`, `invalid_environment`, `invalid_harness`, `invalid_runtime`, `invalid_workspace_escape`) and the reason for invalid ones. |
| `status.json` | Counts of expected, valid, passing, failing, and invalid scenarios. |

Top-level files:

| File | Content |
|---|---|
| `SUMMARY.csv`, `SUMMARY.md` | Pass rates of every experiment. |
| `repair_loop_summary.csv`, `repair_loop_tables/` | passItr@n, iterations, tokens, and per-error-class resolution statistics. |
| `_figures/` | Figures generated from these tables. |
| `_analysis_cache/` | Per-iteration tables parsed from the raw runs, and small extracts (`thesis_*.csv`) of the benchmark construction caches, the prior-benchmark audits, the raw runs, and the Terraform Registry categories, used by the analysis notebooks. |
| `opencode_workspace_audit_*.csv` | Audit of OpenCode runs that read or wrote outside their workspace. |
| `proxy_tool_use_*.csv` | Audit of tool use in the Claude-Opus-5.5 runs. |

## Intent checks

`analysis/intent_checks/` holds the per-scenario intent checks of the 100 ablation scenarios: a JSON spec per scenario (`specs/<lang>/row_NNN.json`, `NNN` = benchmark `row_number`), the Rego policy generated from it (`policies/`), the shared interpreter (`lib/intent.rego`), and the tools that validate specs and score templates with Open Policy Agent. `analysis/README.md` describes the commands and `analysis/intent_checks/SPEC_BRIEF.md` the spec format.

## Example run

`examples/scenario_S/` holds every agent's inputs and outputs for one run: DeepSeek-V4-Flash on Terraform scenario 229, which fails `terraform validate`, then Trivy, and passes in its third iteration. `examples/README.md` says which file holds which agent's inputs and outputs.

## Thesis appendices

| Appendix | Paths |
|---|---|
| Benchmark details | `benchmark/cloudformation/ground_truth/`, `benchmark/terraform/ground_truth/`. CloudFormation scenario 5: `benchmark/cloudformation/ground_truth/cfn_templates/sasmita1005__AWSSAM/sfn-eventbridge/template.yaml`, `analysis/intent_checks/specs/cfn/row_005.json`, `analysis/intent_checks/policies/cfn/row_005.rego`. Terraform scenario 79: `benchmark/terraform/ground_truth/scenarios/terrads_b9c4d791e93e/`, `analysis/intent_checks/specs/tf/row_079.json`, `analysis/intent_checks/policies/tf/row_079.rego`. Shared interpreter: `analysis/intent_checks/lib/intent.rego`. |
| Agent prompts | `prompts/planner_prompt.py`, `prompts/engineer_prompt.py`, `prompts/retriever_prompt.py`, `prompts/remediator_prompt.py` |
| Example run | `examples/scenario_S/` |
| Baseline prompts | `baselines/zeroshot_prompts.py`, `baselines/prompts/cloudformation.md`, `baselines/prompts/terraform.md` |
| Error categories | `analysis/audit/error_categories.py` |

## License

The code, prompts, notebooks, intent-check specifications, and experiment results are released under the [MIT License](LICENSE).

Some bundled data comes from third parties and keeps its original license:

| Data | Source | License |
|---|---|---|
| `data/iac_eval_benchmark.csv`, `data/iac_eval/train.parquet`, `analysis/result/final/rego_reference_ceiling/IaCEval_reference_outputs*.csv` | [IaC-Eval](https://huggingface.co/datasets/autoiac-project/iac-eval) | CC BY 4.0 |
| `data/iac_with_difficulty_levels.csv` | DPIaC-Eval, from [IaCGen](https://github.com/Tianyi2/IaCGen) | Apache-2.0 |
| Rego policy source in `data/trivy_enriched.csv`, `data/trivy_cfn_policy_map.csv`, `data/security_checks.json`, `analysis/Data/trivy_enriched.csv` | [aquasecurity/trivy-checks](https://github.com/aquasecurity/trivy-checks) | MIT |
| Check descriptions in `data/avd_scraped.json` and the files above | [Aqua Vulnerability Database](https://avd.aquasec.com/misconfig/aws/) | Aqua Security's terms |
| `data/cfn_spec.json` | AWS CloudFormation resource specification | AWS's terms |
| `results/_analysis_cache/thesis_tf_registry_subcategories.csv` | Resource categories of the [Terraform AWS provider documentation](https://registry.terraform.io/providers/hashicorp/aws/latest/docs) | MPL-2.0 |
| `benchmark/*/ground_truth/`, `analysis/intent_checks/fixtures/` | Reference templates of the benchmark scenarios (and normalised copies of the ablation subset), from the sources below | License of each source |

The Multi-DPIaC-Eval prompts were written for this benchmark and are MIT-licensed with the rest of the repository. Each reference template keeps the license of the repository it came from:

- **CloudFormation**: the source repository, URL, and SPDX licence of every scenario are in `benchmark/cloudformation/final_benchmark_real_aws_with_prompts.csv` (`source_slug`, `github_url`, `licence_spdx`): Apache-2.0 (114), MIT-0 (68), MIT (61), GPL-3.0 (4), CC0-1.0 (2), BSD-3-Clause (1). The four GPL-3.0 templates are rows 176 ([manpaz/aws](https://github.com/manpaz/aws)), 201 ([kameshsampath/ansible-collection-xks](https://github.com/kameshsampath/ansible-collection-xks)), 253 ([alanwill/aws-tailor](https://github.com/alanwill/aws-tailor)), and 258 ([MederD/AWS_playground](https://github.com/MederD/AWS_playground)); they and `analysis/intent_checks/fixtures/cfn/row_176.input.json` are licensed under GPL-3.0.
- **Terraform**: the source of every scenario is in `benchmark/terraform/final_benchmark_real_aws_with_prompts.csv` (`source`): [TerraDS](https://zenodo.org/records/14217386) (221, CC BY 4.0), [Tianyi2/IRIS](https://github.com/Tianyi2/IRIS) (21, Apache-2.0), [y-miyazaki/terraform-aws-base](https://github.com/y-miyazaki/terraform-aws-base) (2, Apache-2.0), [aws-ia/terraform-aws-guardduty](https://github.com/aws-ia/terraform-aws-guardduty) (Apache-2.0), [clouddrove/terraform-aws-security-group](https://github.com/clouddrove/terraform-aws-security-group) (Apache-2.0), [ValeriiVasianovych/terraform-iac](https://github.com/ValeriiVasianovych/terraform-iac) (MIT), [gabrielPav/aws-security-foundation](https://github.com/gabrielPav/aws-security-foundation) (MIT), [GovWifi/govwifi-terraform](https://github.com/GovWifi/govwifi-terraform) (MIT), and [terraform-module/terraform-aws-enforce-mfa](https://github.com/terraform-module/terraform-aws-enforce-mfa) (MIT).
- Templates in the `*_greenfield/` folders are minimally modified versions of the originals and keep the same licenses.
