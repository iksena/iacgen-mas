from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import shutil
import signal
import subprocess
import time
import traceback
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from baselines.evaluation import STATE_FILENAME, ScenarioConfig, _sha, template_filename
from baselines.opencode_driver import OpenCodeDriver, workspace_escapes
from benchmark_common import (
    CSV_RESULT_FIELDS,
    _append_jsonl,
    _build_summary,
    _extract_iteration_records,
    _extract_policy_metrics,
    _filter_rows_in_failed_csv,
    _filter_rows_not_in_completed_csv,
    _load_iteration_snapshots,
    _row_number_from_csv,
    _row_slice,
    _row_to_csv,
    _safe_int,
)
from config import DeployConfig, DeployTarget
from tools.deploy_cleanup import cleanup_scenario_resources
from tools.deploy_validator import validate_deployment
from tools.validators import run_all_validators
from tracking.recorder import ResearchRecorder

REPO_ROOT = Path(__file__).resolve().parent.parent

BASELINE_CSV_EXTRA = [
    "harness",
    "harness_model",
    "harness_turns",
    "iteration_cap_reached",
    "submitted_by_harness",
    "submitted_matched_validated",
    "final_verdict_source",
    "harness_stalled",
    "harness_stall_retries_used",
    "harness_stalled_attempt_run_ids",
    "thinking_tokens_total",
    "workspace_escapes",
]
BASELINE_CSV_FIELDS = CSV_RESULT_FIELDS + BASELINE_CSV_EXTRA

DEAD_ROW_ABORT_THRESHOLD = 3


@dataclass
class BaselineConfig:
    dataset_path: Path
    output_dir: Path
    runs_dir: Path
    start_row: int
    max_rows: int | None
    rows: list[int] | None
    exclude_completed_csv: Path | None
    retry_errors: bool
    max_iterations: int
    iac_type: str
    deploy_target: str
    model: str
    base_url: str
    api_key_env: str
    provider_name: str
    scenario_timeout: int
    max_stall_retries: int
    sleep_between_rows: float
    keep_workspace: bool

    harness: str = "opencode"
    provider: str = "harness"
    openrouter_provider_only: str | None = None
    openrouter_min_quantization: str | None = None
    openrouter_reasoning_effort: str | None = None
    openrouter_reasoning_max_tokens: int | None = None
    disable_reasoning: bool = False
    max_tokens: int | None = None
    no_max_tokens: bool = False
    skip_security: bool = False


def _terminate_process_group(proc: subprocess.Popen) -> None:
    for sig, grace in ((signal.SIGTERM, 10), (signal.SIGKILL, 5)):
        try:
            os.killpg(os.getpgid(proc.pid), sig)
        except (ProcessLookupError, PermissionError):
            return
        try:
            proc.wait(timeout=grace)
            return
        except subprocess.TimeoutExpired:
            continue


def run_harness(
    config: BaselineConfig,
    scenario: ScenarioConfig,
    prompt: str,
    workdir: Path,
    stream_path: Path,
    driver: OpenCodeDriver,
) -> dict[str, Any]:
    system_prompt = (REPO_ROOT / "baselines" / "prompts" / f"{config.iac_type}.md").read_text()

    state_dir = workdir.parent / f".{driver.name}_state"
    state_dir.mkdir(parents=True, exist_ok=True)

    cmd = driver.build_command(
        config=config,
        scenario=scenario,
        prompt=prompt,
        workdir=workdir,
        system_prompt=system_prompt,
        state_dir=state_dir,
    )

    stderr_path = stream_path.with_suffix(".stderr.txt")
    started = time.time()
    timed_out = False
    resolved_workdir = str(workdir.resolve())
    env = driver.build_env(config, state_dir)
    env["PWD"] = resolved_workdir

    with stream_path.open("w", encoding="utf-8") as out, stderr_path.open(
        "w", encoding="utf-8"
    ) as err:
        proc = subprocess.Popen(
            cmd,
            cwd=resolved_workdir,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=out,
            stderr=err,
            text=True,
            start_new_session=True,
        )
        try:
            returncode = proc.wait(timeout=config.scenario_timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            returncode = -1
            _terminate_process_group(proc)
            err.write(f"\n[Baseline] Timed out after {config.scenario_timeout}s\n")

    stdout = stream_path.read_text(encoding="utf-8", errors="replace")
    if not stderr_path.read_text(encoding="utf-8", errors="replace").strip():
        stderr_path.unlink(missing_ok=True)

    driver.write_debug_transcripts(
        stdout,
        run_id=scenario.run_id,
        system_prompt=system_prompt,
        user_prompt=prompt,
        model=config.model,
        state_dir=state_dir,
        debug_log_path=stream_path.with_name("harness_debug.log"),
        transcript_path=stream_path.with_name("harness_transcript.txt"),
        tool_calls_path=stream_path.with_name("harness_tool_calls.txt"),
    )
    shutil.rmtree(state_dir, ignore_errors=True)

    telemetry = driver.parse_stream(
        stdout,
        returncode=returncode,
        timed_out=timed_out,
        duration=round(time.time() - started, 3),
    )
    telemetry["workspace_escapes"] = workspace_escapes(stdout, workdir)
    return telemetry


def finalize_scenario(
    config: BaselineConfig,
    workdir: Path,
    recorder: ResearchRecorder,
) -> dict[str, Any]:
    state_path = recorder.output_dir / STATE_FILENAME
    state: dict[str, Any] = {}
    if state_path.exists():
        try:
            state = json.loads(state_path.read_text())
        except json.JSONDecodeError:
            state = {}

    submitted = state.get("submitted") or {}
    candidate = Path(submitted["file_path"]) if submitted.get("file_path") else (
        workdir / template_filename(config.iac_type)
    )
    if not candidate.is_absolute():
        candidate = workdir / candidate

    if not candidate.exists() or not candidate.read_text(encoding="utf-8").strip():
        return {
            "template": "",
            "validation_results": [],
            "deploy_result": None,
            "passed": False,
            "verdict_source": "no_template_produced",
            "state": state,
        }

    template = candidate.read_text(encoding="utf-8")
    deploy_required = config.deploy_target != "none"

    matches = _sha(template) == state.get("last_validated_sha")
    static_passed = bool(state.get("last_static_passed")) and matches
    results = state.get("last_validation_results", []) if matches else []
    deploy_result = state.get("last_deploy_result") if matches else None

    verdict_source = "recorded"

    if not matches:
        verdict_source = "revalidated"
        results, _all, _dep = run_all_validators(
            template,
            iac_type=config.iac_type,
            deploy_config=DeployConfig(target=DeployTarget.NONE),
        )
        static_passed = all(r["passed"] for r in results)
        deploy_result = None

    if deploy_required and static_passed and deploy_result is None:
        if verdict_source == "recorded":
            verdict_source = "deployed_at_finalize"
        deploy_result = dict(
            validate_deployment(
                template,
                deploy_config=DeployConfig(target=DeployTarget(config.deploy_target)),
                iac_type=config.iac_type,
            )
        )
        recorder.record_deployment_log(
            iteration=_safe_int(state.get("iteration_count")) + 1,
            iac_type=config.iac_type,
            target=deploy_result.get("target", config.deploy_target),
            deployment_logs=deploy_result.get("deployment_logs", []),
            passed=bool(deploy_result.get("passed")),
            duration_seconds=float(deploy_result.get("duration_seconds", 0.0) or 0.0),
            failed_resources=deploy_result.get("failed_resources", []),
        )

    deploy_ok = True
    if deploy_required:
        deploy_ok = bool(deploy_result and deploy_result.get("passed"))

    return {
        "template": template,
        "validation_results": results,
        "deploy_result": deploy_result,
        "passed": bool(static_passed and deploy_ok),
        "verdict_source": verdict_source,
        "state": state,
    }


def _empty_tokens() -> dict[str, int]:
    return {
        "input_tokens": 0,
        "output_tokens": 0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "all_tokens": 0,
    }


def _run_one_attempt(
    config: BaselineConfig, prompt: str, driver: OpenCodeDriver
) -> tuple[str, ResearchRecorder, Path, dict[str, Any], dict[str, Any]]:
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + str(uuid.uuid4())[:8]
    recorder = ResearchRecorder(run_id=run_id, output_dir=str(config.runs_dir))

    workdir = (recorder.output_dir / "workspace").resolve()
    workdir.mkdir(parents=True, exist_ok=True)

    scenario = ScenarioConfig(
        run_id=run_id,
        iac_type=config.iac_type,
        workdir=workdir,
        runs_dir=config.runs_dir,
        max_iterations=config.max_iterations,
        deploy_target=config.deploy_target,
        user_request=prompt,
    )

    telemetry = run_harness(
        config,
        scenario,
        prompt,
        workdir,
        recorder.output_dir / "harness_stream.jsonl",
        driver,
    )
    final = finalize_scenario(config, workdir, recorder)
    return run_id, recorder, workdir, telemetry, final


def run_scenario(
    config: BaselineConfig,
    row: dict[str, str],
    row_number: int,
    prompt: str,
    driver: OpenCodeDriver,
) -> dict[str, Any]:
    started = time.time()

    stalled_run_ids: list[str] = []
    attempt = 1
    while True:
        run_id, recorder, workdir, telemetry, final = _run_one_attempt(config, prompt, driver)
        if final["passed"] or not telemetry["stalled"] or attempt > config.max_stall_retries:
            break
        stalled_run_ids.append(run_id)
        print(f"[Baseline] row {row_number}: attempt {attempt} stalled, retrying")
        attempt += 1

    state = final["state"]
    iterations_used = _safe_int(state.get("iteration_count"))

    recorder.save_final_report(
        {
            "run_id": run_id,
            "user_request": prompt,
            "current_iteration": iterations_used,
            "validation_passed": final["passed"],
            "objectives": [],
            "final_template": final["template"],
            "remediation_history": [],
            "llm_call_log": telemetry["llm_call_log"],
            "validation_results": final["validation_results"],
            "deploy_validation_result": final["deploy_result"],
        }
    )
    iteration_records = _extract_iteration_records(
        _load_iteration_snapshots(recorder.output_dir)
    )

    if not config.keep_workspace:
        shutil.rmtree(workdir, ignore_errors=True)

    status = "ok"
    error_message = None
    escapes = telemetry.get("workspace_escapes") or []
    if escapes:
        status = "workspace_escape"
        error_message = (
            "Harness session accessed paths outside its workspace, so the result is "
            "not a clean measurement and is scored as a failure: "
            + "; ".join(escapes[:5])
        )
    elif telemetry["timed_out"]:
        status, error_message = "harness_timeout", "Harness exceeded --scenario-timeout"
    elif telemetry["stalled"] and not final["passed"]:
        status = "harness_stalled"
        error_message = (
            f"Harness produced no text or tool call in {len(stalled_run_ids) + 1} attempt(s)."
        )
    elif telemetry["is_error"]:
        status = "harness_error"
        error_message = f"Harness exited rc={telemetry['returncode']} subtype={telemetry['subtype']}"

    submitted = state.get("submitted") or {}
    return {
        "row_number": row_number,
        "ground_truth_path": row.get("ground_truth_path"),
        "prompt": prompt,
        "run_id": run_id,
        "status": status,
        "error_message": error_message,
        "error_traceback": None,
        "final_validation_passed": bool(final["passed"]) and not escapes,
        "iterations_used": iterations_used,
        "llm_calls_total": len(telemetry["llm_call_log"]),
        "token_usage": telemetry["token_usage"],
        "iteration_records": iteration_records,
        "validation_results_final": final["validation_results"],
        "remediation_history": [],
        "policy_metrics": _extract_policy_metrics(final["validation_results"]),
        "duration_seconds": round(time.time() - started, 3),
        "harness": config.harness,
        "harness_model": config.model,
        "harness_turns": telemetry["num_turns"],
        "token_usage_source": telemetry["token_usage_source"],
        "iteration_cap_reached": bool(state.get("cap_reached")),
        "submitted_by_harness": bool(submitted),
        "submitted_matched_validated": bool(submitted.get("matches_last_validated")),
        "final_verdict_source": final["verdict_source"],
        "harness_stalled": bool(telemetry["stalled"]),
        "harness_stall_retries_used": len(stalled_run_ids),
        "harness_stalled_attempt_run_ids": ",".join(stalled_run_ids) or None,
        "thinking_tokens_total": telemetry["thinking_tokens_total"],
        "workspace_escapes": "; ".join(escapes) or None,
    }


def _append_baseline_csv(path: Path, payload: dict[str, Any]) -> None:
    row = _row_to_csv(payload)
    for key in BASELINE_CSV_EXTRA:
        row[key] = payload.get(key)
    with path.open("a", encoding="utf-8", newline="") as fh:
        csv.DictWriter(fh, fieldnames=BASELINE_CSV_FIELDS).writerow(row)


def run_baseline(config: BaselineConfig) -> dict[str, Any]:
    driver = OpenCodeDriver()

    config.output_dir.mkdir(parents=True, exist_ok=True)
    config.runs_dir.mkdir(parents=True, exist_ok=True)
    summary_path = config.output_dir / "summary.json"
    jsonl_path = config.output_dir / "results.jsonl"
    csv_path = config.output_dir / "results.csv"

    jsonl_path.write_text("", encoding="utf-8")
    with csv_path.open("w", encoding="utf-8", newline="") as fh:
        csv.DictWriter(fh, fieldnames=BASELINE_CSV_FIELDS).writeheader()

    with config.dataset_path.open(newline="", encoding="utf-8") as fh:
        all_rows = list(csv.DictReader(fh))

    if config.rows:
        requested = set(config.rows)
        selected = [
            r
            for r in all_rows
            if (n := _row_number_from_csv(r)) is not None and n in requested
        ]
    else:
        selected = _row_slice(all_rows, config.start_row, config.max_rows)

    selected_row_count = len(selected)
    filtered_row_count = 0
    if config.exclude_completed_csv is not None:
        if config.retry_errors:
            selected, filtered_row_count = _filter_rows_in_failed_csv(
                selected, config.exclude_completed_csv,
                match_ground_truth_path=not bool(config.rows),
            )
        else:
            selected, filtered_row_count = _filter_rows_not_in_completed_csv(
                selected, config.exclude_completed_csv,
                match_ground_truth_path=not bool(config.rows),
            )

    started_at = datetime.now().isoformat()
    started_ts = time.time()

    rows_out: list[dict[str, Any]] = []
    consecutive_dead_rows = 0
    pass_count = pass_at_1_count = 0
    total_iterations = total_llm_calls = 0
    total_policy = total_passed_policy = total_failed_policy = total_filtered_failed = 0
    scenario_ppr_sum = scenario_unfiltered_sum = 0.0
    scenario_ppr_count = runtime_error_runs = 0
    stalled_count = 0
    aggregate_tokens = _empty_tokens()

    print(f"\n{'=' * 80}")
    print(
        f"OpenCode baseline | model={config.model} | iac_type={config.iac_type} "
        f"| rows={len(selected)} | deploy={config.deploy_target}"
    )
    print(f"{'=' * 80}")

    def write_summary(attempted: int) -> dict[str, Any]:
        summary = _build_summary(
            config=config,
            selected_row_count=selected_row_count,
            filtered_row_count=filtered_row_count,
            attempted=attempted,
            pass_count=pass_count,
            pass_at_1_count=pass_at_1_count,
            total_iterations=total_iterations,
            total_llm_calls=total_llm_calls,
            aggregate_tokens=aggregate_tokens,
            total_policy_count=total_policy,
            total_passed_policy_count=total_passed_policy,
            total_failed_policy_count=total_failed_policy,
            total_filtered_failed_policy_count=total_filtered_failed,
            scenario_ppr_sum=scenario_ppr_sum,
            scenario_unfiltered_compliance_sum=scenario_unfiltered_sum,
            scenario_ppr_count=scenario_ppr_count,
            runtime_error_runs=runtime_error_runs,
            started_at=started_at,
            completed_at=datetime.now().isoformat(),
            elapsed=round(time.time() - started_ts, 3),
        )
        evaluated = summary.get("rows_evaluated", 0)
        non_stalled = max(evaluated - stalled_count, 0)
        summary.update(
            {
                "harness": config.harness,
                "harness_model": config.model,
                "base_url": config.base_url,
                "runs_dir": str(config.runs_dir),
                "rows_stalled": stalled_count,
                "pass_rate_excl_stalled": (pass_count / non_stalled) if non_stalled else None,
            }
        )
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return summary

    write_summary(0)

    for i, row in enumerate(selected, start=1):
        row_number = _safe_int(row.get("row_number"), config.start_row + i - 1)
        prompt = (row.get("prompt") or "").strip()
        print(f"\n[Baseline] ({i}/{len(selected)}) row {row_number} [{config.iac_type}]")

        if not prompt:
            payload: dict[str, Any] = {
                "row_number": row_number,
                "ground_truth_path": row.get("ground_truth_path"),
                "prompt": prompt,
                "run_id": None,
                "status": "skipped_empty_prompt",
                "error_message": "Prompt is empty",
                "final_validation_passed": False,
                "iterations_used": 0,
                "llm_calls_total": 0,
                "token_usage": _empty_tokens(),
                "iteration_records": [],
                "validation_results_final": [],
                "remediation_history": [],
                "policy_metrics": _extract_policy_metrics([]),
                "duration_seconds": 0.0,
            }
        else:
            row_started = time.time()
            try:
                payload = run_scenario(config, row, row_number, prompt, driver)
            except Exception as exc:
                runtime_error_runs += 1
                payload = {
                    "row_number": row_number,
                    "ground_truth_path": row.get("ground_truth_path"),
                    "prompt": prompt,
                    "status": "runtime_error",
                    "error_message": str(exc),
                    "error_traceback": traceback.format_exc(),
                    "duration_seconds": round(time.time() - row_started, 3),
                }
                print(f"[Baseline] Row {row_number} failed: {exc}")
                print(traceback.format_exc())
            finally:
                try:
                    cleanup_scenario_resources(
                        DeployConfig(target=DeployTarget(config.deploy_target))
                    )
                except Exception as cleanup_exc:
                    print(
                        f"[Baseline] Warning: scenario-finished cleanup for row "
                        f"{row_number} failed unexpectedly: {cleanup_exc}"
                    )

        if payload.get("run_id") and payload.get("status") != "runtime_error":
            if payload.get("status") == "harness_stalled":
                stalled_count += 1
            if payload.get("final_validation_passed"):
                pass_count += 1
                if _safe_int(payload.get("iterations_used")) == 1:
                    pass_at_1_count += 1
            total_iterations += _safe_int(payload.get("iterations_used"))
            total_llm_calls += _safe_int(payload.get("llm_calls_total"))
            for key in aggregate_tokens:
                aggregate_tokens[key] += _safe_int((payload.get("token_usage") or {}).get(key))
            pm = payload.get("policy_metrics") or {}
            total_policy += _safe_int(pm.get("total_policies"))
            total_passed_policy += _safe_int(pm.get("passed_policies"))
            total_failed_policy += _safe_int(pm.get("failed_policies_all_severity"))
            total_filtered_failed += _safe_int(pm.get("filtered_failed_policies"))
            scenario_ppr_sum += float(pm.get("scenario_policy_pass_rate", 0.0) or 0.0)
            scenario_unfiltered_sum += float(pm.get("unfiltered_compliance_rate", 0.0) or 0.0)
            scenario_ppr_count += 1

            if payload.get("status") == "harness_stalled":
                outcome = "STALLED"
            elif payload.get("final_validation_passed"):
                outcome = "PASS"
            else:
                outcome = "FAIL"
            print(
                f"[Baseline] row {row_number}: {outcome} "
                f"| iters={payload.get('iterations_used')} "
                f"| calls={payload.get('llm_calls_total')} "
                f"| verdict={payload.get('final_verdict_source')}"
            )

        harness_never_ran = (
            _safe_int(payload.get("llm_calls_total")) == 0
            and payload.get("final_verdict_source") == "no_template_produced"
            and payload.get("status") != "skipped_empty_prompt"
        )
        consecutive_dead_rows = consecutive_dead_rows + 1 if harness_never_ran else 0

        rows_out.append(payload)
        _append_jsonl(jsonl_path, payload)
        _append_baseline_csv(csv_path, payload)
        write_summary(len(rows_out))

        if consecutive_dead_rows >= DEAD_ROW_ABORT_THRESHOLD:
            stderr_hint = ""
            if payload.get("run_id"):
                stderr_hint = (
                    f"\nInspect: {config.runs_dir / payload['run_id'] / 'harness_stream.stderr.txt'}"
                )
            raise SystemExit(
                f"\n[Baseline] Aborting: {consecutive_dead_rows} consecutive scenarios "
                f"made zero LLM calls and produced no template. The harness is not "
                f"running; this is a setup problem, not a benchmark result."
                f"{stderr_hint}\n"
                f"Last error: {payload.get('error_message')}\n"
                f"Partial results kept in {config.output_dir}"
            )

        if config.sleep_between_rows and i < len(selected):
            time.sleep(config.sleep_between_rows)

    summary = write_summary(len(rows_out))
    (config.output_dir / "results.json").write_text(
        json.dumps({"summary": summary, "rows": rows_out}, indent=2), encoding="utf-8"
    )

    print(f"\n[Baseline] Finished in {summary['duration_seconds']}s -> {config.output_dir}")
    print(f"[Baseline] pass_rate={summary['pass_rate']:.3f} pass@1={summary['pass_at_1']:.3f}")
    if stalled_count:
        print(
            f"[Baseline] {stalled_count} row(s) stalled. "
            f"pass_rate_excl_stalled={summary.get('pass_rate_excl_stalled')}"
        )
    return {"summary": summary, "rows": rows_out}


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Coding-agent baseline: OpenCode writes and repairs the template, "
        "calling the IaCGen-MAS Validator through an MCP server."
    )
    p.add_argument("--iac-type", choices=["cloudformation", "terraform"], default="cloudformation")
    p.add_argument("--dataset", type=Path, default=None)
    p.add_argument("--output-dir", type=Path, default=None)
    p.add_argument("--runs-dir", type=Path, default=Path("runs"))
    p.add_argument("--start-row", type=int, default=0)
    p.add_argument("--max-rows", type=int, default=None)
    p.add_argument("--rows", type=str, default=None,
                   help="Comma-separated row_number values to run (e.g. 1,6,7)")
    p.add_argument("--exclude-completed-csv", type=Path, default=None)
    p.add_argument("--retry-errors", action="store_true",
                   help="With --exclude-completed-csv, run only the rows that did not pass there.")
    p.add_argument("--max-iterations", type=int, default=15)
    p.add_argument("--deploy-target", choices=["none", "localstack", "aws"], default="aws")
    p.add_argument("--model", type=str, required=True,
                   help="Model id at the endpoint, e.g. deepseek/deepseek-v4-flash on OpenRouter")
    p.add_argument("--base-url", type=str, default="https://openrouter.ai/api",
                   help="OpenAI-compatible endpoint; /v1 is appended if missing")
    p.add_argument("--api-key-env", type=str, default="OPENROUTER_API_KEY",
                   help="Environment variable holding the endpoint's API key")
    p.add_argument("--provider-name", type=str, default="openrouter",
                   help="Provider id declared in opencode.json. Must not be one of "
                        "OpenCode's built-in providers (e.g. use deepseek-direct, not deepseek).")
    p.add_argument("--scenario-timeout", type=int, default=1800,
                   help="Seconds before a scenario's OpenCode process is killed")
    p.add_argument("--max-stall-retries", type=int, default=1,
                   help="Fresh attempts when a session produces no text or tool call")
    p.add_argument("--sleep-between-rows", type=float, default=0.0)
    p.add_argument("--keep-workspace", action="store_true",
                   help="Keep runs/<run_id>/workspace instead of deleting it after scoring")

    args = p.parse_args()
    if args.retry_errors and args.exclude_completed_csv is None:
        p.error("--retry-errors requires --exclude-completed-csv")
    return args


def main() -> None:
    args = parse_args()

    if args.dataset is not None:
        dataset_path = args.dataset
    elif args.iac_type == "terraform":
        dataset_path = Path("data") / "tf_eval_benchmark_real_aws.csv"
    else:
        dataset_path = Path("data") / "cfn_eval_benchmark_real_aws.csv"

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output_dir or Path("benchmark_runs") / f"opencode_{args.iac_type}_{ts}"

    rows = None
    if args.rows:
        rows = [int(r.strip()) for r in args.rows.split(",") if r.strip().isdigit()]

    if shutil.which("opencode") is None:
        raise SystemExit("The `opencode` CLI was not found on PATH.")

    config = BaselineConfig(
        dataset_path=dataset_path,
        output_dir=output_dir.resolve(),
        runs_dir=args.runs_dir.resolve(),
        start_row=args.start_row,
        max_rows=args.max_rows,
        rows=rows,
        exclude_completed_csv=args.exclude_completed_csv,
        retry_errors=args.retry_errors,
        max_iterations=args.max_iterations,
        iac_type=args.iac_type,
        deploy_target=args.deploy_target,
        model=args.model,
        base_url=args.base_url,
        api_key_env=args.api_key_env,
        provider_name=args.provider_name,
        scenario_timeout=args.scenario_timeout,
        max_stall_retries=args.max_stall_retries,
        sleep_between_rows=args.sleep_between_rows,
        keep_workspace=args.keep_workspace,
    )
    run_baseline(config)


if __name__ == "__main__":
    logging.getLogger("neo4j").setLevel(logging.ERROR)
    main()
