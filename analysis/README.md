# Analysis

Notebooks and scripts used to build the Multi-DPIaC-Eval benchmark, select the ablation subset, audit the generated templates, and produce the tables and figures of the thesis. Run everything from this folder (`analysis/`); paths resolve against the repository root (`../results`, `../data`, `../runs`).

## Setup

```bash
pip install -r requirements.txt
```

The audits also call `trivy`, `cfn-lint`, `tflint`, `terraform`, and `opa` (intent checks). Rebuilding the per-iteration tables needs the raw run folders under `../runs/`, which are not part of this repository; the parsed copies are in `../results/_analysis_cache/`. After cloning, run `touch ../results/_analysis_cache/*` so the cache is newer than the results and is reused.

## Benchmark construction

| File | Content |
|---|---|
| `CFN_Benchmark_Pipeline.ipynb` | CloudFormation benchmark: repository search, licence filter, collection, size and difficulty levels, deduplication, cfn-lint, Trivy gate, real-AWS deployment, assembly of the final 250 scenarios, analytics. |
| `TF_Benchmark_Pipeline.ipynb` | Terraform benchmark: the same stages over GitHub, IaC-Eval, Multi-IaC-Eval, and TerraDS, with TFLint and `terraform validate`. |
| `generate_cfn_prompts.py`, `generate_llm_prompts.py` | Draft the natural-language prompt of each CloudFormation / Terraform scenario. |
| `Benchmark_Security_Audit.ipynb` | Lint, Trivy, and deployment check of the IaC-Eval and Multi-IaC-Eval references. |
| `DPIaCEval_Security_Audit.ipynb` | cfn-lint and security check of the DPIaC-Eval references. |
| `Ablation_Benchmark_Selector.ipynb` | Selection of the 50 + 50 ablation scenarios (`ablation_selection/`). |

The pipelines read the cloned source repositories and external datasets, which are not included; the resulting benchmark files are in `../data/`.

## Result audits and analysis

| File | Content |
|---|---|
| `IaCGOD_Coverage_Audit_Result.ipynb` | CloudFormation: resource recall and precision, failures, and token usage per experiment. |
| `IaCGOD_TF_Coverage_Audit_Result.ipynb` | The same for Terraform. |
| `IaCGOD_Trivy_Audit_Result.ipynb` | Security audit of every final template at all severities. |
| `IaCGOD_Repair_Loop_Analysis.ipynb` | passItr@n, iterations, error categories and resolution, retrieved context, costs, ablation, baselines. Writes `../results/repair_loop_tables/` and `../results/_figures/`. |
| `Ablation_Intent_Analysis.ipynb` | Intent-check scores of the ablation conditions. |
| `IaCGen_vs_MAS_GLM_Analysis.ipynb` | IaCGen against IaCGen-MAS with GLM-5.3-Flash. |

### Scripts (`audit/`)

| Script | Output |
|---|---|
| `finalize_results.py`, `aggregate_benchmark_run_data.py` | Merge raw benchmark runs into `../results/<experiment>/` and label each attempt's validity. `superseded_runs.csv` and `tainted_runs.csv` list the attempts excluded by hand. |
| `coverage_audit.py`, `tf_coverage_audit.py` | `result/final/Coverage_<experiment>.csv` |
| `trivy_audit.py`, `trivy_audit_cached.py` | `result/final/Trivy_<experiment>.csv` |
| `ablation_intent_audit.py` | `ablation_selection/intent_results/<condition>.csv` |
| `ablation_significance.py` | Paired McNemar tests of each ablation condition. |
| `repair_loop.py`, `error_categories.py`, `opencode_failures.py` | Helpers imported by the repair-loop notebook. |
| `hazard_check.py` | Independent recomputation of the repair hazard table. |
| `invalid_rows_review.py` | Per-iteration review of invalid rows. |
| `opencode_workspace_audit.py` | OpenCode runs that touched files outside their workspace. |
| `proxy_tool_use_audit.py` | Tool use in the Claude-Opus-5.5 runs. |
| `rego_intent_audit.py`, `classify_iac_eval_satisfiability.py` | IaC-Eval Rego intent policies (`result/final/Rego_*`). |

Examples:

```bash
python audit/coverage_audit.py -i ../results/CFN_RealAWS_DSV4F/results_final.csv -b ../data/cfn_eval_benchmark_real_aws.csv -d cfn_benchmark -t cloudformation --output-csv result/final/Coverage_CFN_RealAWS_DSV4F.csv
python audit/trivy_audit_cached.py --input ../results/TF_RealAWS_DSV4F/results_final.csv --type terraform --output-csv result/final/Trivy_TF_RealAWS_DSV4F.csv
python audit/ablation_intent_audit.py --condition no-planner --input ../results/CFN_Ablation_NoPlanner/results_final.csv
```

## Intent checks (`intent_checks/`)

Per-scenario checks of whether a template does what its prompt asked, evaluated as Rego policies with Open Policy Agent on the parsed CloudFormation template or the Terraform plan.

| Path | Content |
|---|---|
| `specs/<lang>/row_NNN.json` | Hand-written checks of one scenario (`NNN` = benchmark `row_number`). |
| `policies/<lang>/row_NNN.rego` | Policy generated from the spec. |
| `lib/intent.rego` | Shared interpreter. |
| `fixtures/<lang>/` | Normalised reference templates. |
| `validation/<lang>/` | Validation report of each spec (positive, mutation, empty, and strictness checks). |
| `intent_core.py`, `build.py` | Adapters, policy generator, OPA runner, and CLI (`sync`, `add`, `pending`, `show`, `validate`, `status`, `explain`). |
| `tests/test_interpreter.py` | Regression tests. |

Terraform scoring runs `tflocal plan` and needs LocalStack on port 4566.

## Data in this folder

| Path | Content |
|---|---|
| `result/final/` | Coverage, Trivy, and Rego audit outputs per experiment. |
| `ablation_selection/` | Ablation scenario lists, selection tables, and intent scores (`intent_results/`). |
| `Data/trivy_enriched.csv` | Trivy check metadata used by the Trivy audit notebook. |
| `plots/` | Figures written by the notebooks. |
