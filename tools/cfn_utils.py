import time
import boto3
from botocore.exceptions import ClientError
from config import DeployConfig, DeployTarget


def build_cfn_client(deploy_config: DeployConfig):
    if deploy_config.target == DeployTarget.LOCALSTACK:
        return boto3.client(
            "cloudformation",
            endpoint_url=deploy_config.localstack_endpoint,
            region_name="us-east-1",
            aws_access_key_id="test",
            aws_secret_access_key="test",
        )
    else:
        session = boto3.Session(profile_name=deploy_config.aws_profile)
        return session.client("cloudformation", region_name=deploy_config.aws_region)


def format_failed_resources(failed_resources: list[dict]) -> str:
    if not failed_resources:
        return "Deployment failed (no resource-level detail available)"
    parts = [
        f"{r['logical_name']}: {r['status_reason']}"
        for r in failed_resources
        if r.get("logical_name") and r.get("status_reason")
    ]
    return " | ".join(parts) if parts else "Deployment failed (unknown reason)"


def _failed_resource_ids(cfn_client, stack_id: str) -> list[str]:
    ids: list[str] = []
    try:
        for page in cfn_client.get_paginator("list_stack_resources").paginate(StackName=stack_id):
            ids += [r["LogicalResourceId"] for r in page["StackResourceSummaries"]
                    if r["ResourceStatus"] == "DELETE_FAILED"]
    except ClientError:
        pass
    return ids


def wait_for_stack_deletion(cfn_client, stack_id: str, stack_name: str, timeout: int):
    start = time.time()
    retain_attempts = 0
    reissued_plain_delete = False
    while time.time() - start < timeout:
        try:
            stack = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]
            status = stack["StackStatus"]
            if status == "DELETE_COMPLETE":
                return
            if status == "DELETE_FAILED" and retain_attempts < 3:
                retain_attempts += 1
                failed = _failed_resource_ids(cfn_client, stack_id)
                print(f"[Deploy] Stack '{stack_name}' DELETE_FAILED on {failed or 'unknown resource(s)'} "
                      f"-- retrying with those retained")
                try:
                    cfn_client.delete_stack(StackName=stack_id, RetainResources=failed)
                except ClientError as e:
                    print(f"[Deploy] Retain-delete of '{stack_name}' failed: {e}")
            elif status in ("ROLLBACK_COMPLETE", "CREATE_FAILED") and not reissued_plain_delete:
                reissued_plain_delete = True
                try:
                    cfn_client.delete_stack(StackName=stack_name)
                except Exception:
                    pass
        except ClientError as e:
            if "does not exist" in str(e):
                return
            raise
        time.sleep(3)

    print(f"[Deploy] ⚠️  Stack deletion timed out after {timeout}s")
    try:
        current_status = cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        print(f"[Deploy] Stack '{stack_name}' left in status: {current_status}")
        if current_status == "DELETE_FAILED":
            cfn_client.delete_stack(StackName=stack_id, RetainResources=_failed_resource_ids(cfn_client, stack_id))
            print(f"[Deploy] Issued force-delete for '{stack_name}'")
    except ClientError as e:
        if "does not exist" in str(e):
            return
        print(f"[Deploy] Could not force-delete '{stack_name}': {e}")
