import os
from pathlib import Path
import json
import shutil
import time
import pandas as pd


def _count_stage_errors(stage_record):
    errors = stage_record.get("errors", [])
    if isinstance(errors, list):
        return len([e for e in errors if e])
    if isinstance(errors, str):
        return 1 if errors.strip() else 0

    if not stage_record.get("passed", True):
        return 1
    return 0


def _classify_stage(stage_name):
    stage = (stage_name or "").strip().lower().replace("_", "-")

    
    if stage in {"yaml"}:
        return "yaml"
    
    if stage in {"cfn-lint"}:
        return "cfn-lint"

    if stage in {
        "trivy",
        "checkov",
        "security",
        "security-scan",
        "iac-security",
        "kics",
        "tfsec",
    }:
        return "security"

    if stage in {"deployment", "deploy", "stack-deploy", "cloudformation-deploy"}:
        return "deployment"

    return "other"


def _extract_stage_errors(stage_record):
    errors = stage_record.get("errors", [])
    if isinstance(errors, list):
        return [str(e).strip() for e in errors if str(e).strip()]
    if isinstance(errors, str):
        return [errors.strip()] if errors.strip() else []
    return []


def _normalize_path_inputs(paths):
    if paths is None:
        return []
    if isinstance(paths, (str, os.PathLike)):
        return [paths]
    return list(paths)


def _collect_files_recursive(paths, extension, exclude_filenames=None):
    exclude_filenames = set(exclude_filenames or [])
    collected = []

    for path in _normalize_path_inputs(paths):
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file_name in files:
                    if not file_name.lower().endswith(extension):
                        continue
                    if file_name in exclude_filenames:
                        continue
                    collected.append(os.path.join(root, file_name))
        elif os.path.isfile(path) and path.lower().endswith(extension):
            if os.path.basename(path) not in exclude_filenames:
                collected.append(path)

    return sorted(dict.fromkeys(collected))


def _coerce_bool_series(series):
    def _coerce(value):
        if isinstance(value, bool):
            return value
        if pd.isna(value):
            return None
        text = str(value).strip().lower()
        if text in ("true", "1", "yes"):
            return True
        if text in ("false", "0", "no"):
            return False
        return None
    return series.map(_coerce)


def _load_benchmark_row_keys(benchmark_csv):
    if benchmark_csv is None:
        return None, None
    if not os.path.exists(benchmark_csv):
        raise FileNotFoundError(f"Benchmark CSV not found: {benchmark_csv}")

    df = pd.read_csv(benchmark_csv)
    if "row_number" not in df.columns:
        raise ValueError(f"Column 'row_number' not found in {benchmark_csv}")

    df = df.copy()
    df["row_number"] = pd.to_numeric(df["row_number"], errors="coerce")
    df = df.dropna(subset=["row_number"])
    df["row_number"] = df["row_number"].astype(int)

    valid_row_numbers = set(df["row_number"].tolist())

    ground_truth_to_row_number = None
    if "ground_truth_path" in df.columns:
        keyed = df.assign(ground_truth_path=df["ground_truth_path"].astype(str).str.strip())
        ground_truth_to_row_number = dict(
            zip(keyed["ground_truth_path"], keyed["row_number"])
        )

    return valid_row_numbers, ground_truth_to_row_number


def _assert_output_path_not_in_inputs(output_path, input_paths, file_label):
    if not output_path or not input_paths:
        return

    output_abs = os.path.abspath(output_path)
    for input_path in input_paths:
        if os.path.abspath(input_path) == output_abs:
            raise ValueError(
                f"{file_label} output path '{output_path}' matches an input file. "
                "Use a different output path to avoid modifying originals."
            )


def merge_results_from_paths(
    csv_paths,
    merged_csv_path="results_merged.csv",
    jsonl_paths=None,
    merged_jsonl_path="results_merged.jsonl",
    benchmark_csv=None,
    prefer_final_validation_passed=False,
):
    csv_files = _collect_files_recursive(
        csv_paths,
        ".csv",
        exclude_filenames={os.path.basename(merged_csv_path)},
    )
    jsonl_files = _collect_files_recursive(
        jsonl_paths,
        ".jsonl",
        exclude_filenames={os.path.basename(merged_jsonl_path)},
    )

    if not csv_files and not jsonl_files:
        print("No CSV or JSONL files found to merge.")
        return

    merge_results(
        csv_paths=csv_files,
        merged_csv_path=merged_csv_path,
        jsonl_paths=jsonl_files,
        merged_jsonl_path=merged_jsonl_path,
        benchmark_csv=benchmark_csv,
        prefer_final_validation_passed=prefer_final_validation_passed,
    )


def merge_results_from_directory(
    base_dir,
    merged_csv_path="results_merged.csv",
    merged_jsonl_path="results_merged.jsonl",
    benchmark_csv=None,
    prefer_final_validation_passed=False,
):
    resolved_csv_path = (
        merged_csv_path
        if os.path.isabs(merged_csv_path)
        else os.path.join(base_dir, merged_csv_path)
    )
    resolved_jsonl_path = (
        merged_jsonl_path
        if os.path.isabs(merged_jsonl_path)
        else os.path.join(base_dir, merged_jsonl_path)
    )

    merge_results_from_paths(
        csv_paths=[base_dir],
        merged_csv_path=resolved_csv_path,
        jsonl_paths=[base_dir],
        merged_jsonl_path=resolved_jsonl_path,
        benchmark_csv=benchmark_csv,
        prefer_final_validation_passed=prefer_final_validation_passed,
    )


def filter_runtime_error_rows(
    input_csv,
    output_csv="results_without_runtime_error.csv",
    status_col="status",
):
    if not os.path.exists(input_csv):
        raise FileNotFoundError(f"Input CSV not found: {input_csv}")

    df = pd.read_csv(input_csv)
    if status_col not in df.columns:
        raise ValueError(f"Column '{status_col}' not found in {input_csv}")

    status_values = df[status_col].fillna("").astype(str).str.strip().str.lower()
    filtered_df = df[status_values != "runtime_error"].copy()

    filtered_df.to_csv(output_csv, index=False)
    removed_rows = len(df) - len(filtered_df)
    print(
        f"Filtered {removed_rows} runtime_error row(s) from '{input_csv}' into '{output_csv}'"
    )
    return filtered_df


def find_timeout_retry_candidates(
    input_csv,
    output_csv=None,
    status_col="status",
    cap_reached_col="iteration_cap_reached",
):
    if not os.path.exists(input_csv):
        raise FileNotFoundError(f"Input CSV not found: {input_csv}")

    df = pd.read_csv(input_csv)
    for col in (status_col, cap_reached_col, "row_number"):
        if col not in df.columns:
            raise ValueError(f"Column '{col}' not found in {input_csv}")

    status_values = df[status_col].fillna("").astype(str).str.strip().str.lower()
    cap_reached = (
        df[cap_reached_col].fillna("").astype(str).str.strip().str.lower() == "true"
    )
    candidates = df[(status_values == "harness_timeout") & ~cap_reached].copy()

    row_numbers = sorted(int(float(x)) for x in candidates["row_number"].tolist())
    print(
        f"{len(row_numbers)} harness_timeout row(s) with iteration budget still "
        f"unused (out of {int((status_values == 'harness_timeout').sum())} "
        f"harness_timeout row(s) total) in '{input_csv}':"
    )
    for _, row in candidates.sort_values("row_number").iterrows():
        extra = []
        if "iterations_used" in candidates.columns:
            extra.append(f"iters={row['iterations_used']}")
        if "duration_seconds" in candidates.columns:
            extra.append(f"duration={row['duration_seconds']}")
        print(f"  row {int(float(row['row_number']))}: {', '.join(extra)}")

    print(f"\n--rows \"{','.join(str(n) for n in row_numbers)}\"")

    if output_csv:
        candidates.to_csv(output_csv, index=False)
        print(f"\nWrote {len(candidates)} row(s) to '{output_csv}'")

    return row_numbers


def audit_workspace_escapes(runs_dir, results_csv=None, output_csv=None):
    import re
    from baselines.sandbox_audit import is_inside, tool_calls

    def category(path, repo_root, run_id):
        rel = path[len(repo_root):].lstrip("/") if repo_root and path.startswith(repo_root) else None
        if rel is None:
            return "outside the repository"
        if rel == "":
            return "repository root"
        top = rel.split("/")[0]
        if top == "runs":
            parts = rel.split("/")
            if len(parts) > 1 and parts[1] and parts[1] != run_id:
                return "another run's artifacts"
            return "runs listing / own run directory"
        if rel.endswith(".env") or top == ".env":
            return ".env (credentials)"
        if top in ("final_results", "benchmark_runs"):
            return "prior results"
        if top == "data" or top.startswith(("cfn_templates", "iac_benchmark")):
            return "dataset / ground truth"
        if top in ("tools", "baselines", "agents", "scripts", "prompts", "graph.py", "config.py",
                   "main.py", "benchmark.py", "benchmark_common.py", "state.py"):
            return "harness / validator source"
        return "other repository file"

    rows = []
    for stream_path in sorted(Path(runs_dir).rglob("harness_stream.jsonl")):
        run_id = stream_path.parent.name
        try:
            text = stream_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        harness = "claude_code" if '"claude_code_version"' in text[:4000] else "opencode"
        calls = tool_calls(text, harness)
        marker_re = re.compile(r"^(.*/" + re.escape(run_id) + r"/workspace)(?:/|$)")
        workspace = next(
            (m.group(1) for c in calls for p in c.paths if (m := marker_re.match(p))),
            f"/__no_workspace_seen__/{run_id}/workspace",
        )
        repo_root = workspace.split("/runs/")[0] if "/runs/" in workspace else ""
        hits = [(c, p) for c in calls if c.ok for p in c.paths if not is_inside(p, workspace)]
        if not hits:
            continue
        rows.append({
            "run_id": run_id,
            "harness": harness,
            "escaped_calls": len(hits),
            "wrote_outside": any(c.tool.lower() in ("write", "edit") for c, _ in hits),
            "reached": " | ".join(sorted({category(p, repo_root, run_id) for _, p in hits})),
            "example_paths": " | ".join(sorted({p for _, p in hits})[:4]),
        })

    df = pd.DataFrame(rows, columns=["run_id", "harness", "escaped_calls", "wrote_outside", "reached", "example_paths"])
    if results_csv and len(df):
        res = pd.read_csv(results_csv)
        keep = [c for c in ("run_id", "row_number", "status", "final_validation_passed") if c in res.columns]
        df = df.merge(res[keep], on="run_id", how="left")

    print(f"{len(df)} run(s) with at least one successful out-of-workspace call (scanned '{runs_dir}')")
    if len(df):
        for reached, n in df["reached"].str.split(" \\| ").explode().value_counts().items():
            print(f"  {n:4d}  {reached}")
        print(f"  {int(df['wrote_outside'].sum()):4d}  run(s) also WROTE outside the workspace")
        if "row_number" in df.columns and df["row_number"].notna().any():
            rows_list = sorted(int(float(x)) for x in df["row_number"].dropna().unique())
            print(f"\n--rows \"{','.join(str(r) for r in rows_list)}\"")
    if output_csv:
        df.to_csv(output_csv, index=False)
        print(f"Wrote {output_csv}")
    return df


def merge_results_with_reports(input_csv="results.csv", base_dir="runs", output_csv="results_merged.csv"):
    if not os.path.exists(input_csv):
        print(f"Error: The input CSV '{input_csv}' does not exist.")
        return

    df_results = pd.read_csv(input_csv)

    aggregated_extra_data = {}
    seen_report_paths = {}
    duplicate_run_id_examples = {}

    if os.path.exists(base_dir):
        for root, _dirs, files in os.walk(base_dir):
            if "final_report.json" not in files:
                continue

            run_id = os.path.basename(root)
            report_path = os.path.join(root, "final_report.json")

            with open(report_path, "r", encoding="utf-8") as f:
                try:
                    report = json.load(f)
                except json.JSONDecodeError:
                    print(f"Error reading JSON in {report_path}")
                    continue

            row_extra = {
                "run_id": report.get("run_id", run_id),
                "policy_total_policies": report.get("policy_metrics", {}).get("total_policies", 0),
                "policy_passed_policies": report.get("policy_metrics", {}).get("passed_policies", 0),
                "final_template": report.get("final_template", "None"),
            }

            deploy_res = report.get("deploy_validation_result") or {}
            row_extra["deploy_target"] = deploy_res.get("target", "none")
            row_extra["deploy_passed"] = deploy_res.get("passed", False)
            row_extra["deploy_stack_id"] = deploy_res.get("stack_id", "None")
            row_extra["deploy_error_message"] = deploy_res.get("error_message") or "None"
            row_extra["deploy_logs"] = deploy_res.get("deployment_logs") or "None"
            row_extra["deploy_duration_seconds"] = deploy_res.get("duration_seconds", 0.0)
            
            failed_res = deploy_res.get("failed_resources", [])
            row_extra["deploy_failed_resources"] = json.dumps(failed_res) if failed_res else "None"
            
            completed_res = deploy_res.get("completed_resources", [])
            row_extra["deploy_completed_resources"] = " | ".join(completed_res) if completed_res else "None"

            rem_history = report.get("remediation_history", [])
            val_results = report.get("validation_results", [])
            if rem_history:
                total_yaml_errors = 0
                total_cfn_lint_errors = 0
                total_security_errors = 0
                total_deployment_errors = 0

                all_yaml_errors = []
                all_cfn_lint_errors = []
                all_security_errors = []
                all_deployment_errors = []

                for iteration in rem_history:
                    stage_records = iteration.get("errors", [])

                    yaml_count = 0
                    cfn_lint_count = 0
                    security_count = 0
                    deployment_count = 0

                    for err_stage in stage_records:
                        stage_group = _classify_stage(err_stage.get("stage", "unknown"))
                        stage_error_count = _count_stage_errors(err_stage)
                        stage_errors_list = _extract_stage_errors(err_stage)

                        if stage_group == "yaml":
                            yaml_count += stage_error_count
                            all_yaml_errors.extend(stage_errors_list)
                        elif stage_group == "cfn-lint":
                            cfn_lint_count += stage_error_count
                            all_cfn_lint_errors.extend(stage_errors_list)
                        elif stage_group == "security":
                            security_count += stage_error_count
                            all_security_errors.extend(stage_errors_list)
                        elif stage_group == "deployment":
                            deployment_count += stage_error_count
                            all_deployment_errors.extend(stage_errors_list)

                    if yaml_count > 0:
                        security_count = 0
                        deployment_count = 0
                    elif cfn_lint_count > 0:
                        security_count = 0
                        deployment_count = 0
                    elif security_count > 0:
                        deployment_count = 0

                    total_yaml_errors += yaml_count
                    total_cfn_lint_errors += cfn_lint_count
                    total_security_errors += security_count
                    total_deployment_errors += deployment_count

                row_extra["total_yaml_errors"] = total_yaml_errors
                row_extra["total_cfn_lint_errors"] = total_cfn_lint_errors
                row_extra["total_security_errors"] = total_security_errors

                row_extra["all_yaml_errors"] = " | ".join(all_yaml_errors) if all_yaml_errors else "None"
                row_extra["all_cfn_lint_errors"] = " | ".join(all_cfn_lint_errors) if all_cfn_lint_errors else "None"
                row_extra["all_security_errors"] = " | ".join(all_security_errors) if all_security_errors else "None"

                last_iteration = rem_history[-1]
                for err_stage in last_iteration.get("errors", []):
                    stage_name = err_stage.get("stage", "unknown")
                    stage_errors = err_stage.get("errors", [])
                    
                    if not err_stage.get("passed", True) and stage_errors:
                        row_extra[f"latest_error_{stage_name}"] = " | ".join(stage_errors)
                    else:
                        row_extra[f"latest_error_{stage_name}"] = "None"
            elif val_results:
                yaml_count = cfn_lint_count = security_count = 0
                all_yaml_errors, all_cfn_lint_errors, all_security_errors = [], [], []

                for err_stage in val_results:
                    stage_group = _classify_stage(err_stage.get("stage", "unknown"))
                    stage_error_count = _count_stage_errors(err_stage)
                    stage_errors_list = _extract_stage_errors(err_stage)

                    if stage_group == "yaml":
                        yaml_count += stage_error_count
                        all_yaml_errors.extend(stage_errors_list)
                    elif stage_group == "cfn-lint":
                        cfn_lint_count += stage_error_count
                        all_cfn_lint_errors.extend(stage_errors_list)
                    elif stage_group == "security":
                        security_count += stage_error_count
                        all_security_errors.extend(stage_errors_list)

                    stage_name = err_stage.get("stage", "unknown")
                    stage_errors = err_stage.get("errors", [])
                    if not err_stage.get("passed", True) and stage_errors:
                        row_extra[f"latest_error_{stage_name}"] = " | ".join(str(e) for e in stage_errors)
                    else:
                        row_extra[f"latest_error_{stage_name}"] = "None"

                if yaml_count > 0 or cfn_lint_count > 0:
                    security_count = 0

                row_extra["total_yaml_errors"] = yaml_count
                row_extra["total_cfn_lint_errors"] = cfn_lint_count
                row_extra["total_security_errors"] = security_count
                row_extra["all_yaml_errors"] = " | ".join(all_yaml_errors) if all_yaml_errors else "None"
                row_extra["all_cfn_lint_errors"] = " | ".join(all_cfn_lint_errors) if all_cfn_lint_errors else "None"
                row_extra["all_security_errors"] = " | ".join(all_security_errors) if all_security_errors else "None"

            for stage_res in val_results:
                stage_name = stage_res.get("stage", "unknown")
                row_extra[f"val_stage_{stage_name}_passed"] = stage_res.get("passed", False)

            resolved_run_id = row_extra["run_id"]
            if resolved_run_id in aggregated_extra_data:
                duplicate_run_id_examples.setdefault(
                    resolved_run_id, (seen_report_paths[resolved_run_id], report_path)
                )
            aggregated_extra_data[resolved_run_id] = row_extra
            seen_report_paths[resolved_run_id] = report_path

        if duplicate_run_id_examples:
            n = len(duplicate_run_id_examples)
            example_id, (path_a, path_b) = next(iter(duplicate_run_id_examples.items()))
            print(
                f"Warning: {n} run_id(s) found at more than one path under '{base_dir}' "
                f"(used the later one found for each); e.g. '{example_id}' at both "
                f"'{path_a}' and '{path_b}'."
            )
    else:
        print(f"Warning: The directory '{base_dir}' does not exist. No extra data will be merged.")

    if aggregated_extra_data:
        df_extra = pd.DataFrame(list(aggregated_extra_data.values()))

        df_merged = pd.merge(df_results, df_extra, on="run_id", how="left")
    else:
        print("No extra report data found to merge. Saving a copy of the input CSV.")
        df_merged = df_results.copy()

    df_merged.to_csv(output_csv, index=False)
    print(f"Successfully created merged results at '{output_csv}'")

def merge_results(
    csv_paths,
    merged_csv_path,
    jsonl_paths=None,
    merged_jsonl_path=None,
    benchmark_csv=None,
    prefer_final_validation_passed=False,
):
    if csv_paths:
        _assert_output_path_not_in_inputs(merged_csv_path, csv_paths, "CSV")
        valid_row_numbers, ground_truth_to_row_number = _load_benchmark_row_keys(benchmark_csv)

        dfs = []
        for file_idx, f in enumerate(csv_paths):
            if os.path.exists(f):
                df = pd.read_csv(f)
                df = df.reset_index(drop=True)
                df["_file_order"] = file_idx
                df["_row_order"] = df.index
                dfs.append(df)

        if dfs:
            merged_df = pd.concat(dfs, ignore_index=True)

            if valid_row_numbers is not None:
                before_count = len(merged_df)

                if ground_truth_to_row_number is not None and "ground_truth_path" in merged_df.columns:
                    gt_series = merged_df["ground_truth_path"].astype(str).str.strip()
                    mapped_row_number = gt_series.map(ground_truth_to_row_number)
                    merged_df = merged_df[mapped_row_number.notna()].copy()
                    merged_df["row_number"] = mapped_row_number[mapped_row_number.notna()].astype(int)
                    match_desc = "ground_truth_path is not present"
                elif "row_number" in merged_df.columns:
                    row_number_series = pd.to_numeric(merged_df["row_number"], errors="coerce")
                    merged_df = merged_df[row_number_series.isin(valid_row_numbers)].copy()
                    match_desc = "row_number is not present"
                else:
                    print(
                        "Warning: benchmark_csv given but merged data has neither "
                        "'ground_truth_path' nor 'row_number' to filter on; ignoring the filter."
                    )
                    match_desc = None

                if match_desc is not None:
                    removed = before_count - len(merged_df)
                    if removed > 0:
                        print(
                            f"Filtered {removed} row(s) whose {match_desc} "
                            f"in benchmark CSV '{benchmark_csv}'."
                        )

            if "row_number" in merged_df.columns:
                merged_df["row_number"] = pd.to_numeric(merged_df["row_number"], errors="coerce")

                with_row_number = merged_df[merged_df["row_number"].notna()].copy()
                without_row_number = merged_df[merged_df["row_number"].isna()].copy()
                before_dedup_count = len(with_row_number)

                dedup_subset = ["row_number"]
                sort_columns = ["row_number", "_file_order", "_row_order"]
                using_passed_override = False

                if prefer_final_validation_passed:
                    if "final_validation_passed" not in with_row_number.columns or "ground_truth_path" not in with_row_number.columns:
                        print(
                            "Warning: prefer_final_validation_passed requires "
                            "'final_validation_passed' and 'ground_truth_path' columns; ignoring the flag."
                        )
                    else:
                        using_passed_override = True
                        dedup_subset = ["row_number", "ground_truth_path"]
                        with_row_number["_passed_rank"] = (
                            _coerce_bool_series(with_row_number["final_validation_passed"]) == True
                        ).astype(int)
                        sort_columns = [
                            "row_number", "ground_truth_path", "_passed_rank", "_file_order", "_row_order",
                        ]

                with_row_number = with_row_number.sort_values(by=sort_columns, na_position="last")
                with_row_number = with_row_number.drop_duplicates(subset=dedup_subset, keep="last")
                if using_passed_override:
                    with_row_number = with_row_number.drop(columns=["_passed_rank"])

                replaced_count = before_dedup_count - len(with_row_number)
                if replaced_count > 0:
                    match_desc = "matching row_number/ground_truth_path" if using_passed_override else "matching row_number"
                    print(
                        f"Replaced {replaced_count} earlier row(s) using lower-priority CSV rows with {match_desc}."
                    )

                merged_df = pd.concat([with_row_number, without_row_number], ignore_index=True)
                merged_df = merged_df.sort_values(
                    by=["row_number", "_file_order", "_row_order"],
                    na_position="last",
                ).reset_index(drop=True)
            else:
                merged_df = merged_df.sort_values(by=["_file_order", "_row_order"]).reset_index(drop=True)

            drop_cols = [c for c in ("_file_order", "_row_order") if c in merged_df.columns]
            if drop_cols:
                merged_df = merged_df.drop(columns=drop_cols)

            merged_df.to_csv(merged_csv_path, index=False)
            print(f"Merged {len(dfs)} CSVs into {merged_csv_path}")
        else:
            print("No valid CSV files found to merge.")
    
    if jsonl_paths and merged_jsonl_path:
        _assert_output_path_not_in_inputs(merged_jsonl_path, jsonl_paths, "JSONL")
        valid_jsonls = [f for f in jsonl_paths if os.path.exists(f)]
        if valid_jsonls:
            with open(merged_jsonl_path, 'w', encoding='utf-8') as outfile:
                for fname in valid_jsonls:
                    with open(fname, 'r', encoding='utf-8') as infile:
                        for line in infile:
                            outfile.write(line)
            print(f"Merged {len(valid_jsonls)} JSONLs into {merged_jsonl_path}")


def move_run_folders_from_csv(
    input_csv="results_merged.csv",
    runs_dir="runs",
    target_subfolder_name="moved_runs",
    run_id_col="run_id",
    dry_run=True,
):
    if not os.path.exists(input_csv):
        raise FileNotFoundError(f"Input CSV not found: {input_csv}")

    df = pd.read_csv(input_csv, dtype=str)
    if run_id_col not in df.columns:
        raise ValueError(f"Column '{run_id_col}' not found in {input_csv}")

    run_ids = set(df[run_id_col].dropna().astype(str).str.strip())
    if not run_ids:
        return []

    if not os.path.isdir(runs_dir):
        raise FileNotFoundError(f"Runs directory not found: {runs_dir}")

    target_dir = os.path.join(runs_dir, target_subfolder_name)
    os.makedirs(target_dir, exist_ok=True)

    moved = []

    for root, dirs, files in os.walk(runs_dir):
        if os.path.abspath(root).startswith(os.path.abspath(target_dir)):
            continue

        for d in list(dirs):
            if d in run_ids:
                src = os.path.join(root, d)
                dest = os.path.join(target_dir, d)

                if os.path.abspath(src) == os.path.abspath(dest):
                    dirs.remove(d)
                    continue

                if os.path.exists(dest):
                    dest = dest + f".dup_{int(time.time())}"

                if dry_run:
                    print(f"[DRY RUN] Would move: '{src}' -> '{dest}'")
                else:
                    shutil.move(src, dest)
                    print(f"Moved: '{src}' -> '{dest}'")

                moved.append((src, dest))

                try:
                    dirs.remove(d)
                except ValueError:
                    pass

    return moved


def _truncate(text, width: int) -> str:
    text = "" if text is None or (isinstance(text, float) and pd.isna(text)) else str(text)
    text = text.strip()
    return text if len(text) <= width else text[:width] + "..."


def _format_number(value) -> str:
    if value is None or (isinstance(value, float) and pd.isna(value)):
        return "?"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


def _render_markdown_table(headers: list[str], rows: list[list[str]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        cells = [str(c).replace("|", "\\|").replace("\n", " ") for c in row]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def display_results_table(
    results_csv,
    dataset_csv=None,
    *,
    failed_only: bool = False,
    min_iterations: int | None = None,
    prompt_chars: int = 100,
    print_table: bool = True,
) -> str:
    if not os.path.exists(results_csv):
        raise FileNotFoundError(f"Results CSV not found: {results_csv}")

    df = pd.read_csv(results_csv)
    if "row_number" not in df.columns:
        raise ValueError(f"'row_number' column not found in {results_csv}")

    df = df.copy()
    df["row_number"] = pd.to_numeric(df["row_number"], errors="coerce")
    ground_truth = df["ground_truth_path"].fillna("").astype(str).str.strip() \
        if "ground_truth_path" in df.columns else pd.Series([""] * len(df), index=df.index)
    run_id = df["run_id"].fillna("").astype(str).str.strip() \
        if "run_id" in df.columns else pd.Series([""] * len(df), index=df.index)

    prompt_by_gt: dict = {}
    difficulty_by_gt: dict = {}
    prompt_by_row: dict = {}
    difficulty_by_row: dict = {}
    if dataset_csv is not None:
        if not os.path.exists(dataset_csv):
            raise FileNotFoundError(f"Dataset CSV not found: {dataset_csv}")
        ds = pd.read_csv(dataset_csv)
        for col in ("prompt", "difficulty"):
            if col not in ds.columns:
                raise ValueError(f"'{col}' column not found in {dataset_csv}")

        if "ground_truth_path" in ds.columns:
            ds_gt = ds["ground_truth_path"].astype(str).str.strip()
            prompt_by_gt = dict(zip(ds_gt, ds["prompt"]))
            difficulty_by_gt = dict(zip(ds_gt, ds["difficulty"]))
        if "row_number" in ds.columns:
            ds_row_number = pd.to_numeric(ds["row_number"], errors="coerce")
            prompt_by_row = dict(zip(ds_row_number, ds["prompt"]))
            difficulty_by_row = dict(zip(ds_row_number, ds["difficulty"]))

    passed_bool = (
        _coerce_bool_series(df["final_validation_passed"])
        if "final_validation_passed" in df.columns
        else pd.Series([None] * len(df), index=df.index)
    )
    iterations = (
        pd.to_numeric(df["iterations_used"], errors="coerce")
        if "iterations_used" in df.columns
        else pd.Series([None] * len(df), index=df.index)
    )

    headers = [
        "row_number", "run_id", "ground_truth_path", "prompt",
        "difficulty", "num_iterations", "status",
    ]
    rows = []
    for idx in df.index:
        gt = ground_truth.loc[idx]
        row_number = df.at[idx, "row_number"]

        prompt = prompt_by_gt.get(gt) if gt else None
        difficulty = difficulty_by_gt.get(gt) if gt else None
        if prompt is None and not pd.isna(row_number):
            prompt = prompt_by_row.get(row_number)
        if difficulty is None and not pd.isna(row_number):
            difficulty = difficulty_by_row.get(row_number)

        row_passed = bool(passed_bool.loc[idx]) if passed_bool.loc[idx] is not None else False
        row_iterations = iterations.loc[idx]

        is_failed = not row_passed
        exceeds_min_iterations = (
            pd.notna(row_iterations) and row_iterations > min_iterations
            if min_iterations is not None else None
        )

        if failed_only and min_iterations is not None:
            if not (is_failed or exceeds_min_iterations):
                continue
        elif failed_only:
            if not is_failed:
                continue
        elif min_iterations is not None:
            if not exceeds_min_iterations:
                continue

        rows.append([
            "" if pd.isna(row_number) else int(row_number),
            run_id.loc[idx] or "?",
            gt or "?",
            _truncate(prompt, prompt_chars) if prompt is not None else "?",
            _format_number(difficulty) if isinstance(difficulty, float) else ("?" if difficulty is None else difficulty),
            "" if pd.isna(row_iterations) else int(row_iterations),
            "passed" if row_passed else "failed",
        ])

    table = _render_markdown_table(headers, rows)
    if print_table:
        print(table)
        print(f"\n{len(rows)} row(s) shown (of {len(df)} total).")
    return table


if __name__ == "__main__":

    merge_results_from_directory(
        base_dir="./benchmark_runs/cloudformation_20260922_232123_DPIaCEval_O3Mini",
        benchmark_csv="data/iac_with_difficulty_levels.csv",
        prefer_final_validation_passed=True,
    )
    merge_results_from_directory(
        base_dir="./benchmark_runs/baseline_opencode_cloudformation_20260917_232736_DSV4F_Full",
        benchmark_csv="data/cfn_eval_benchmark_real_aws.csv",
        prefer_final_validation_passed=True,
    )
