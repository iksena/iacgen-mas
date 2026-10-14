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
├── data/                 Benchmark datasets and security-ingestion inputs
├── results/              Experiment results reported in the thesis
├── analysis/             Benchmark construction, audits, and analysis notebooks (see analysis/README.md)
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

Python 3.12+ is recommended.

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

`cfn-lint` (1.48) and `checkov` are installed by `requirements.txt`.

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

Run every ingestion script from the repository root.

**CloudFormation** (downloads the resource specification, scrapes the AWS documentation, merges both, and loads Neo4j and ChromaDB):

```bash
python scripts/graphrag/01_download_cfn_spec.py
python scripts/graphrag/02_scrape_cfn_docs.py
python scripts/graphrag/03_parse_and_merge.py
python scripts/graphrag/04_import_cfn_to_neo4j.py
python scripts/graphrag/05_build_chromadb.py
```

**Terraform** (downloads the AWS provider schema and Terraform Registry documentation, merges both, and loads Neo4j and ChromaDB):

```bash
python scripts/graphrag/terraform/01_download_tf_schema.py
python scripts/graphrag/terraform/02_fetch_tf_registry_docs.py
python scripts/graphrag/terraform/03_parse_and_merge_tf.py
python scripts/graphrag/terraform/04_import_tf_to_neo4j.py
python scripts/graphrag/terraform/05_build_tf_chromadb.py
```

**Security** (Aqua AVD checks and Trivy Rego policies into Neo4j). `data/avd_scraped.json` and `data/security_checks.json` are included, so the first two steps can be skipped:

```bash
python scripts/graphrag/security/00_scrape_avd_docs.py
python scripts/graphrag/security/01_load_trivy_csv.py
python scripts/graphrag/security/04_import_security_to_neo4j.py
```

The intermediate files these pipelines produce (`cfn_resource_spec.json`, `scraped_html/`, `cfn_knowledge_graph.json`, `tf_schema_raw.json`, `tf_registry_docs.json`, `tf_knowledge_graph.json`) are written to the repository root and ignored by git.

### 5. LocalStack (optional)

```bash
docker compose -f localstack-docker-compose.yml up -d
```

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

## Datasets

| File | Benchmark | Scenarios |
|---|---|---|
| `data/cfn_eval_benchmark_real_aws.csv` | Multi-DPIaC-Eval, CloudFormation | 250 |
| `data/tf_eval_benchmark_real_aws.csv` | Multi-DPIaC-Eval, Terraform | 250 |
| `data/cfn_eval_benchmark_ablation.csv` | Ablation subset, CloudFormation | 50 |
| `data/tf_eval_benchmark_ablation.csv` | Ablation subset, Terraform | 50 |
| `data/iac_with_difficulty_levels.csv` | DPIaC-Eval (CloudFormation) | 153 |
| `data/iac_eval_benchmark.csv` | IaC-Eval (Terraform) | 458 |

Columns: `row_number`, `ground_truth_path`, `prompt`, and a difficulty level. `ground_truth_path` points into the benchmark's reference templates, which are not part of this repository and are not needed to run the system.

## Results

`results/` holds one folder per experiment, named `<Language>_<Benchmark>_<System>_<Model>`:

- **Language**: `CFN` (CloudFormation) or `TF` (Terraform)
- **Benchmark**: `RealAWS` (Multi-DPIaC-Eval on live AWS), `DPIaCEval`, `IaCEval`, or `Ablation` (50 scenarios per language on LocalStack); `LintOnly` = IaC-Eval run checked by TFLint and `terraform validate` only
- **System**: no tag = IaCGen-MAS; `OpenCode` = coding-agent baseline; `OneShot` / `ZeroShot` = zero-shot baseline; `IaCGen` = IaCGen baseline. In the ablation, `IaCGOD` is the full IaCGen-MAS and the other tags name the removed or changed component (`NoPlanner`, `NoDenseRAG`, `NoGraphRAG`, `NoQueryRewrite`, `NoRemediator`, `OpenCodeRetriever`, `TrivyAllSeverities`).
- **Model**: `DSV4F` DeepSeek-V4-Flash, `GLM53F` GLM-5.3-Flash, `Gemini38F` Gemini-3.8-Flash, `Opus55` Claude-Opus-5.5, `o3mini` o3-mini
- **Suffix**: `DeployOnly` = deployability-only criterion (no security gate); `L345` = difficulty levels 3–5 only; `PlanOnly` = no deployment and no security gate, a template passes when TFLint, `terraform validate`, and `terraform plan` accept it; `LiveAWS_GLM` = ablation scenarios deployed to live AWS with GLM-5.3-Flash.

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
| `_analysis_cache/` | Per-iteration tables parsed from the raw runs, used by the analysis notebooks. |
| `opencode_workspace_audit_*.csv` | Audit of OpenCode runs that read or wrote outside their workspace. |
| `proxy_tool_use_*.csv` | Audit of tool use in the Claude-Opus-5.5 runs. |
