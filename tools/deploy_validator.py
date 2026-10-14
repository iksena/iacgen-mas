import re
import os
import copy
import time
import uuid
import fcntl
import getpass
import datetime
import contextlib
import subprocess
import tempfile
from pathlib import Path
from botocore.exceptions import ClientError
from config import DeployConfig, DeployTarget
from state import DeployValidationResult
from tools.cfn_utils import build_cfn_client, format_failed_resources, wait_for_stack_deletion
from tools.deploy_cleanup import (
    reset_target_state,
    check_vpc_quota,
    EVAL_TAG_KEY,
    EVAL_TAG_VALUE,
)


def _current_user_slug() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown-user"


_TF_PLUGIN_CACHE_DIR = Path(tempfile.gettempdir()) / f"iac-god-tf-plugin-cache-{_current_user_slug()}"
_TF_PLUGIN_CACHE_DIR.mkdir(parents=True, exist_ok=True)

_TF_INIT_LOCK_PATH = _TF_PLUGIN_CACHE_DIR / ".init.lock"
_TF_INIT_MAX_ATTEMPTS = 3
_TF_INIT_RETRY_BACKOFF_SECONDS = 3.0


@contextlib.contextmanager
def tf_init_lock():
    with open(_TF_INIT_LOCK_PATH, "w") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file, fcntl.LOCK_UN)


def _required_parameter_keys(cfn_client, template: str) -> tuple[list[str], str | None]:
    try:
        response = cfn_client.validate_template(TemplateBody=template)
    except ClientError as e:
        return [], f"validate_template failed: {e}"

    required: list[str] = []
    for param in response.get("Parameters", []):
        key = param.get("ParameterKey")
        has_default = "DefaultValue" in param
        if key and not has_default:
            required.append(key)
    return required, None


def _drain_stack_events(
    cfn_client,
    stack_id: str,
    seen_events: set[str],
    last_timestamp: datetime.datetime,
    failed_resources: list[dict],
    completed_resources: list[str],
    deploy_logs: list[str],
) -> None:
    try:
        events = cfn_client.describe_stack_events(StackName=stack_id)["StackEvents"]
    except Exception:
        return

    for event in sorted(events, key=lambda x: x["Timestamp"]):
        if event["EventId"] in seen_events or event["Timestamp"] <= last_timestamp:
            continue
        seen_events.add(event["EventId"])
        rid = event["LogicalResourceId"]
        status = event["ResourceStatus"]
        reason = event.get("ResourceStatusReason", "N/A")
        print(f"  [Deploy] {rid}: {status} — {reason}")
        deploy_logs.append(f"{rid}: {status} - {reason}")
        if status == "CREATE_FAILED":
            failed_resources.append({"logical_name": rid, "status_reason": reason})
        elif status == "CREATE_COMPLETE":
            completed_resources.append(rid)


def _fetch_early_validation_failures(cfn_client, stack_id: str) -> list[dict]:
    if not hasattr(cfn_client, "describe_events"):
        return []

    try:
        response = cfn_client.describe_events(
            StackName=stack_id,
            Filters={"FailedEvents": True},
        )
    except Exception as e:
        print(f"  [Deploy] describe_events enrichment failed (non-fatal): {e}")
        return []

    enriched: list[dict] = []
    for event in response.get("OperationEvents", []):
        rid = event.get("LogicalResourceId") or "stack"
        reason = (
            event.get("ValidationStatusReason")
            or event.get("HookStatusReason")
            or event.get("ResourceStatusReason")
        )
        if not reason:
            continue
        path = event.get("ValidationPath")
        if path:
            reason = f"{reason} (at {path})"
        entry = {"logical_name": rid, "status_reason": reason}
        print(f"  [Deploy] early-validation detail — {rid}: {reason}")
        enriched.append(entry)

    return enriched


def _get_resource_type(cfn_client, stack_id: str, logical_id: str) -> str:
    try:
        resp = cfn_client.describe_stack_resource(
            StackName=stack_id, LogicalResourceId=logical_id
        )
        return resp["StackResourceDetail"].get("ResourceType", "")
    except Exception:
        return ""


def _terraform_bin(deploy_config: DeployConfig) -> str:
    if deploy_config.target == DeployTarget.LOCALSTACK:
        return "tflocal"
    return "terraform"


def _validate_terraform_deployment(
    template: str,
    deploy_config: DeployConfig,
    start_time: float,
) -> DeployValidationResult:
    target_name = deploy_config.target.value
    deploy_logs: list[str] = []
    tf_bin = _terraform_bin(deploy_config)

    run_env = copy.copy(os.environ)
    if deploy_config.target == DeployTarget.LOCALSTACK:
        run_env.update({
            "AWS_ACCESS_KEY_ID":     "test",
            "AWS_SECRET_ACCESS_KEY": "test",
            "AWS_DEFAULT_REGION":    "us-east-1",
        })
    elif deploy_config.target == DeployTarget.AWS:
        run_env.setdefault("AWS_REGION", deploy_config.aws_region)
        run_env.setdefault("AWS_DEFAULT_REGION", deploy_config.aws_region)

    run_env["TF_PLUGIN_CACHE_DIR"] = str(_TF_PLUGIN_CACHE_DIR)

    with tempfile.TemporaryDirectory() as tmpdir:
        tf_path = Path(tmpdir) / "main.tf"
        tf_path.write_text(template, encoding="utf-8")

        print(f"[Deploy] Running {tf_bin} init in {tmpdir}...")
        init_result = None
        for init_attempt in range(1, _TF_INIT_MAX_ATTEMPTS + 1):
            try:
                with tf_init_lock():
                    init_result = subprocess.run(
                        [tf_bin, "init", "-backend=false", "-input=false", "-no-color"],
                        cwd=tmpdir, capture_output=True, text=True, timeout=120, env=run_env,
                    )
            except subprocess.TimeoutExpired:
                timeout_msg = f"{tf_bin} init timed out after 120s — provider download stalled"
                deploy_logs.append(timeout_msg)
                return DeployValidationResult(
                    target=target_name, passed=False, stack_id=None,
                    completed_resources=[],
                    failed_resources=[{"logical_name": "init", "status_reason": timeout_msg}],
                    error_message=timeout_msg,
                    duration_seconds=round(time.time() - start_time, 2),
                    deployment_logs=deploy_logs,
                )

            if init_result.returncode == 0:
                break

            init_err = (init_result.stderr or init_result.stdout or "")
            if "text file busy" in init_err.lower() and init_attempt < _TF_INIT_MAX_ATTEMPTS:
                print(
                    f"[Deploy] {tf_bin} init hit a transient plugin-cache race (text file busy) "
                    f"on attempt {init_attempt}/{_TF_INIT_MAX_ATTEMPTS}, "
                    f"retrying in {_TF_INIT_RETRY_BACKOFF_SECONDS:.0f}s..."
                )
                deploy_logs.append(
                    f"{tf_bin} init: transient plugin-cache race on attempt "
                    f"{init_attempt}/{_TF_INIT_MAX_ATTEMPTS}, retrying"
                )
                time.sleep(_TF_INIT_RETRY_BACKOFF_SECONDS)
                continue

            break

        if init_result.returncode != 0:
            err = (init_result.stderr or init_result.stdout).strip()
            deploy_logs.append(f"{tf_bin} init failed: {err}")
            return DeployValidationResult(
                target=target_name, passed=False, stack_id=None,
                completed_resources=[], failed_resources=[{"logical_name": "init", "status_reason": err}],
                error_message=f"init: {err}",
                duration_seconds=round(time.time() - start_time, 2),
                deployment_logs=deploy_logs,
            )

        timeout = deploy_config.stack_creation_timeout
        print(f"[Deploy] Running {tf_bin} apply (timeout={timeout}s)...")
        try:
            apply_result = subprocess.run(
                [tf_bin, "apply", "-auto-approve", "-input=false", "-no-color"],
                cwd=tmpdir, capture_output=True, text=True, timeout=timeout, env=run_env,
            )
        except subprocess.TimeoutExpired:
            timeout_msg = f"{tf_bin} apply timed out after {timeout}s"
            deploy_logs.append(timeout_msg)
            return DeployValidationResult(
                target=target_name, passed=False, stack_id=None,
                completed_resources=[], failed_resources=[{"logical_name": "apply", "status_reason": timeout_msg}],
                error_message=timeout_msg,
                duration_seconds=round(time.time() - start_time, 2),
                deployment_logs=deploy_logs,
            )

        apply_output = (apply_result.stdout or "") + (apply_result.stderr or "")
        deploy_logs.extend(apply_output.splitlines())

        if apply_result.returncode == 0:
            completed: list[str] = re.findall(
                r'^([^\s:]+):\s+Creation complete', apply_output, re.MULTILINE
            )
            print(f"[Deploy] ✅ {tf_bin} apply succeeded ({len(completed)} resources created)")

            print(f"[Deploy] Cleaning up with {tf_bin} destroy...")
            try:
                subprocess.run(
                    [tf_bin, "destroy", "-auto-approve", "-input=false", "-no-color"],
                    cwd=tmpdir, capture_output=True, text=True,
                    timeout=deploy_config.stack_deletion_timeout, env=run_env,
                )
            except subprocess.TimeoutExpired:
                timeout_msg = (
                    f"{tf_bin} destroy timed out after {deploy_config.stack_deletion_timeout}s "
                    f"— resources may still be running in {target_name}; manual cleanup may be required"
                )
                print(f"[Deploy] ⚠️  {timeout_msg}")
                deploy_logs.append(timeout_msg)

            if len(completed) == 0:
                zero_msg = (
                    "apply succeeded but created 0 resources — template's "
                    "resources are likely gated off by a default boolean/"
                    "count flag; not counted as a deployability pass"
                )
                deploy_logs.append(zero_msg)
                print(f"[Deploy] ⚠️  {tf_bin} apply created 0 resources — not counting as PASS")
                return DeployValidationResult(
                    target=target_name, passed=False, stack_id=None,
                    completed_resources=[],
                    failed_resources=[{"logical_name": "apply", "status_reason": zero_msg}],
                    error_message=zero_msg,
                    duration_seconds=round(time.time() - start_time, 2),
                    deployment_logs=deploy_logs,
                )

            return DeployValidationResult(
                target=target_name, passed=True, stack_id=None,
                completed_resources=completed, failed_resources=[],
                error_message=None,
                duration_seconds=round(time.time() - start_time, 2),
                deployment_logs=deploy_logs,
            )

        failed_resources: list[dict] = []
        error_blocks = re.split(r'(?m)^│?\s*Error:', apply_output)
        resource_re = re.compile(
            r'on \S+\.tf line (\d+), in resource "([^"]+)"\s+"([^"]+)"'
        )
        for block in error_blocks[1:]:
            lines = block.strip().splitlines()
            summary = lines[0].strip() if lines else "unknown error"
            resource_addr = "apply"
            for line in lines[1:6]:
                m = resource_re.search(line)
                if m:
                    resource_addr = f"{m.group(2)}.{m.group(3)}"
                    break
            detail_lines = [
                l.strip() for l in lines
                if l.strip()
                and not l.strip().startswith("on ")
                and l.strip() != summary
                and not re.match(r'^\d+:', l.strip())
            ]
            detail = " ".join(detail_lines[:3])
            status_reason = f"{summary}" + (f" — {detail}" if detail else "")
            failed_resources.append({"logical_name": resource_addr, "status_reason": status_reason})

        if not failed_resources:
            raw_err = (apply_result.stderr or apply_result.stdout or "unknown apply error").strip()
            failed_resources = [{"logical_name": "apply", "status_reason": raw_err[:500]}]

        error_msg = format_failed_resources(failed_resources)
        print(f"[Deploy] ❌ {tf_bin} apply failed: {error_msg}")

        print(f"[Deploy] Cleaning up with {tf_bin} destroy...")
        try:
            subprocess.run(
                [tf_bin, "destroy", "-auto-approve", "-input=false", "-no-color"],
                cwd=tmpdir, capture_output=True, text=True,
                timeout=deploy_config.stack_deletion_timeout, env=run_env,
            )
        except subprocess.TimeoutExpired:
            timeout_msg = (
                f"{tf_bin} destroy timed out after {deploy_config.stack_deletion_timeout}s "
                f"— resources may still be running in {target_name}; manual cleanup may be required"
            )
            print(f"[Deploy] ⚠️  {timeout_msg}")
            deploy_logs.append(timeout_msg)

        return DeployValidationResult(
                target=target_name, passed=False, stack_id=None,
                completed_resources=[], failed_resources=failed_resources,
                error_message=error_msg,
                duration_seconds=round(time.time() - start_time, 2),
                deployment_logs=deploy_logs,
        )


def validate_deployment(
    template: str,
    deploy_config: DeployConfig,
    iac_type: str = "cloudformation",
) -> DeployValidationResult:
    if deploy_config.target == DeployTarget.NONE:
        return DeployValidationResult(
            target="skipped",
            passed=True,
            stack_id=None,
            completed_resources=[],
            failed_resources=[],
            error_message=None,
            duration_seconds=0.0,
            deployment_logs=[],
        )

    start_time = time.time()

    if iac_type == "terraform":
        reset_target_state(deploy_config)
        return _validate_terraform_deployment(template, deploy_config, start_time)

    target_name = deploy_config.target.value
    deploy_logs: list[str] = []

    reset_target_state(deploy_config)

    vpc_error = check_vpc_quota(deploy_config)
    if vpc_error:
        deploy_logs.append(vpc_error)
        failed = [{"logical_name": "VPC", "status_reason": vpc_error}]
        return DeployValidationResult(
            target=target_name,
            passed=False,
            stack_id=None,
            completed_resources=[],
            failed_resources=failed,
            error_message=format_failed_resources(failed),
            duration_seconds=round(time.time() - start_time, 2),
            deployment_logs=deploy_logs,
        )

    cfn_client = build_cfn_client(deploy_config)
    stack_name = f"iac-god-eval-{uuid.uuid4().hex[:8]}"

    try:
        required_params, param_error = _required_parameter_keys(cfn_client, template)
        if param_error:
            deploy_logs.append(param_error)
            return DeployValidationResult(
                target=target_name, passed=False, stack_id=None,
                completed_resources=[],
                failed_resources=[{"logical_name": "template", "status_reason": param_error}],
                error_message=f"template: {param_error}",
                duration_seconds=round(time.time() - start_time, 2),
                deployment_logs=deploy_logs,
            )

        if required_params:
            failed = [
                {"logical_name": name, "status_reason": "Required parameter has no Default value"}
                for name in required_params
            ]
            error_msg = format_failed_resources(failed)
            deploy_logs.append(error_msg)
            return DeployValidationResult(
                target=target_name, passed=False, stack_id=None,
                completed_resources=[], failed_resources=failed,
                error_message=error_msg,
                duration_seconds=round(time.time() - start_time, 2),
                deployment_logs=deploy_logs,
            )

        print(f"[Deploy] Creating stack '{stack_name}' on {target_name}...")
        deploy_logs.append(f"Creating stack '{stack_name}' on {target_name}")
        create_response = cfn_client.create_stack(
            StackName=stack_name,
            TemplateBody=template,
            OnFailure="DELETE",
            Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
            Tags=[{"Key": EVAL_TAG_KEY, "Value": EVAL_TAG_VALUE}],
        )
        stack_id = create_response["StackId"]

        seen_events: set[str] = set()
        last_timestamp = (
            datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
        )
        failed_resources: list[dict] = []
        completed_resources: list[str] = []
        deadline = time.time() + deploy_config.stack_creation_timeout

        STALL_TIMEOUT = 15 * 60
        last_event_time = time.time()
        last_active_resource: str | None = None
        prev_seen_count = 0

        while time.time() < deadline:
            _drain_stack_events(
                cfn_client, stack_id, seen_events, last_timestamp,
                failed_resources, completed_resources, deploy_logs,
            )

            if len(seen_events) > prev_seen_count:
                last_event_time = time.time()
                prev_seen_count = len(seen_events)
                if deploy_logs:
                    last_log = deploy_logs[-1]
                    colon_idx = last_log.find(":")
                    if colon_idx > 0:
                        last_active_resource = last_log[:colon_idx].strip()

            stack = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]
            stack_status = stack["StackStatus"]

            if stack_status == "CREATE_COMPLETE":
                real_completed = [r for r in completed_resources if r != stack_name]
                print(
                    f"[Deploy] ✅ Stack deployed successfully "
                    f"({len(real_completed)} resources)"
                )
                cfn_client.delete_stack(StackName=stack_id)
                if deploy_config.target == DeployTarget.AWS:
                    wait_for_stack_deletion(
                        cfn_client, stack_id, stack_name,
                        deploy_config.stack_deletion_timeout,
                    )

                if len(real_completed) == 0:
                    zero_msg = (
                        "stack reached CREATE_COMPLETE but created 0 resources "
                        "— template's resources are likely gated off by a "
                        "false Condition; not counted as a deployability pass"
                    )
                    deploy_logs.append(zero_msg)
                    print(f"[Deploy] ⚠️  Stack created 0 resources — not counting as PASS")
                    return DeployValidationResult(
                        target=target_name, passed=False, stack_id=stack_id,
                        completed_resources=[],
                        failed_resources=[{"logical_name": "stack", "status_reason": zero_msg}],
                        error_message=zero_msg,
                        duration_seconds=round(time.time() - start_time, 2),
                        deployment_logs=deploy_logs,
                    )

                return DeployValidationResult(
                    target=target_name, passed=True, stack_id=stack_id,
                    completed_resources=real_completed, failed_resources=[],
                    error_message=None,
                    duration_seconds=round(time.time() - start_time, 2),
                    deployment_logs=deploy_logs,
                )

            if stack_status in (
                "CREATE_FAILED", "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED", "DELETE_COMPLETE",
            ):
                time.sleep(1)
                _drain_stack_events(
                    cfn_client, stack_id, seen_events, last_timestamp,
                    failed_resources, completed_resources, deploy_logs,
                )

                if not failed_resources or all(
                    "describeevents" in (r.get("status_reason") or "").lower()
                    for r in failed_resources
                ):
                    enriched = _fetch_early_validation_failures(cfn_client, stack_id)
                    if enriched:
                        failed_resources = enriched

                error_msg = format_failed_resources(failed_resources)
                if not failed_resources:
                    error_msg = f"Stack entered terminal status: {stack_status}"

                print(f"[Deploy] ❌ Deployment failed: {error_msg}")
                wait_for_stack_deletion(
                    cfn_client, stack_id, stack_name,
                    deploy_config.stack_deletion_timeout,
                )
                return DeployValidationResult(
                    target=target_name, passed=False, stack_id=stack_id,
                    completed_resources=completed_resources, failed_resources=failed_resources,
                    error_message=error_msg,
                    duration_seconds=round(time.time() - start_time, 2),
                    deployment_logs=deploy_logs,
                )

            stall_elapsed = time.time() - last_event_time
            if (
                last_active_resource
                and stall_elapsed > STALL_TIMEOUT
                and stack_status == "CREATE_IN_PROGRESS"
            ):
                resource_type = _get_resource_type(cfn_client, stack_id, last_active_resource)
                is_custom = bool(
                    re.match(r"^Custom::|^AWS::CloudFormation::CustomResource$", resource_type)
                )
                stall_reason = (
                    f"Stalled in CREATE_IN_PROGRESS for >{int(stall_elapsed)}s"
                    + (
                        " — Lambda-backed custom resource likely failed to send cfn-response "
                        "(add ServiceTimeout, ensure Lambda can reach the CloudFormation "
                        "response URL, or replace with a native CloudFormation resource)"
                        if is_custom
                        else " — resource has not progressed; possible dependency or quota issue"
                    )
                )
                stall_failed = [{"logical_name": last_active_resource, "status_reason": stall_reason}]
                stall_msg = format_failed_resources(stall_failed)
                deploy_logs.append(f"STALL_DETECTED: {stall_msg}")
                print(f"[Deploy] ⚠️  Stall detected: {stall_msg}")

                try:
                    cfn_client.delete_stack(StackName=stack_id)
                    print(f"[Deploy] Cancellation requested for stalled stack '{stack_name}'")
                    if deploy_config.target == DeployTarget.AWS:
                        wait_for_stack_deletion(
                            cfn_client, stack_id, stack_name,
                            deploy_config.stack_deletion_timeout,
                        )
                except Exception as e:
                    print(f"[Deploy] Could not cancel stalled stack: {e}")

                return DeployValidationResult(
                    target=target_name, passed=False, stack_id=stack_id,
                    completed_resources=completed_resources, failed_resources=stall_failed,
                    error_message=stall_msg,
                    duration_seconds=round(time.time() - start_time, 2),
                    deployment_logs=deploy_logs,
                )

            time.sleep(2)

        stall_elapsed = round(time.time() - last_event_time)
        stall_context = (
            f" | Last active resource: {last_active_resource} "
            f"(no new events for {stall_elapsed}s)"
            if last_active_resource else ""
        )
        timeout_msg = (
            f"Stack creation timed out after {deploy_config.stack_creation_timeout}s "
            f"({round(time.time() - start_time, 2)}s elapsed)" + stall_context
        )
        deploy_logs.append(timeout_msg)

        timeout_failed: list[dict] = list(failed_resources)
        if last_active_resource and not any(
            r["logical_name"] == last_active_resource for r in timeout_failed
        ):
            resource_type = _get_resource_type(cfn_client, stack_id, last_active_resource)
            is_custom = bool(
                re.match(r"^Custom::|^AWS::CloudFormation::CustomResource$", resource_type)
            )
            timeout_reason = (
                f"Stack creation timed out — resource stalled in CREATE_IN_PROGRESS "
                f"for {stall_elapsed}s"
                + (" (custom resource — add ServiceTimeout or replace with native resource)" if is_custom else "")
            )
            timeout_failed.append({"logical_name": last_active_resource, "status_reason": timeout_reason})

        print(f"[Deploy] ❌ {timeout_msg}")

        try:
            cfn_client.delete_stack(StackName=stack_id)
            print(f"[Deploy] Cancellation requested for timed-out stack '{stack_name}'")
            if deploy_config.target == DeployTarget.AWS:
                wait_for_stack_deletion(
                    cfn_client, stack_id, stack_name,
                    deploy_config.stack_deletion_timeout,
                )
        except Exception as e:
            print(f"[Deploy] Could not cancel timed-out stack: {e}")

        return DeployValidationResult(
            target=target_name, passed=False, stack_id=stack_id,
            completed_resources=completed_resources, failed_resources=timeout_failed,
            error_message=format_failed_resources(timeout_failed) if timeout_failed else timeout_msg,
            duration_seconds=round(time.time() - start_time, 2),
            deployment_logs=deploy_logs,
        )

    except ClientError as e:
        msg = str(e)
        deploy_logs.append(msg)
        return DeployValidationResult(
            target=target_name, passed=False, stack_id=None,
            completed_resources=[],
            failed_resources=[{"logical_name": "stack", "status_reason": msg}],
            error_message=f"stack: {msg}",
            duration_seconds=round(time.time() - start_time, 2),
            deployment_logs=deploy_logs,
        )
    except Exception as e:
        msg = f"Unexpected error: {e}"
        deploy_logs.append(msg)
        return DeployValidationResult(
            target=target_name, passed=False, stack_id=None,
            completed_resources=[],
            failed_resources=[{"logical_name": "stack", "status_reason": msg}],
            error_message=f"stack: {msg}",
            duration_seconds=round(time.time() - start_time, 2),
            deployment_logs=deploy_logs,
        )
