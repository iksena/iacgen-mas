from typing import TypedDict, Optional, NotRequired, Literal


class PolicyStats(TypedDict):
    total_policies: int
    passed_policies: int
    failed_policies: int
    filtered_failed_policies: int


class ValidationResult(TypedDict):
    stage: str
    passed: bool
    errors: list[str]
    raw_output: str
    policy_stats: NotRequired[PolicyStats]
    scenario_policy_pass_rate: NotRequired[float]
    filtered_compliance_rate: NotRequired[float]


class FailedResource(TypedDict):
    logical_name: str
    status_reason: str


class DeployValidationResult(TypedDict):
    target: str
    passed: bool
    stack_id: Optional[str]
    completed_resources: list[str]
    failed_resources: list[FailedResource]
    error_message: Optional[str]
    duration_seconds: float
    deployment_logs: list[str]


class RemediationHistory(TypedDict):
    iteration: int
    errors: list[ValidationResult]
    flat_errors: list[str]
    formatted_errors: str
    suggestion: str
    timestamp: str
    retriever_context: str
    retrieval_queries: list[str]


class LLMCallRecord(TypedDict):
    agent: str
    iteration: int
    model: str
    prompt: str
    response: str
    timestamp: str
    token_usage: Optional[dict]


class Message(TypedDict):
    role: str
    content: str


STAGE_GROUPS: dict[str, set[str]] = {
    "syntax":   {"yaml", "cfn-lint", "tflint", "terraform-validate"},
    "security": {"checkov", "trivy"},
    "deploy":   {"deploy"},
}


def classify_failing_stages(
    validation_results: list["ValidationResult"],
    deploy_validation_result: Optional["DeployValidationResult"],
) -> set[str]:
    failing: set[str] = set()

    failed_static = {
        r["stage"]
        for r in validation_results
        if not r.get("passed", True)
    }

    for group, members in STAGE_GROUPS.items():
        if group == "deploy":
            continue
        if failed_static & members:
            failing.add(group)

    if (
        deploy_validation_result
        and not deploy_validation_result.get("passed", True)
        and deploy_validation_result.get("target") != "skipped"
    ):
        failing.add("deploy")

    return failing


def any_stage_in_moderate_mode(
    stage_error_counts: dict[str, int],
    failing_stages: set[str],
    threshold: int,
) -> bool:
    return any(
        stage_error_counts.get(stage, 0) >= threshold
        for stage in failing_stages
    )


def compact_message_history(history: list[Message]) -> list[Message]:
    compacted: list[Message] = []
    for message in history:
        if compacted and compacted[-1] == message:
            continue
        compacted.append(message)
    return compacted


MAX_HISTORY_PAIRS = 15


def append_and_cap(
    history: list[Message],
    user_msg: Message,
    assistant_msg: Message,
) -> list[Message]:
    updated = history + [user_msg, assistant_msg]
    return updated[-MAX_HISTORY_PAIRS * 2:]


class GraphState(TypedDict):
    iac_type: Literal["cloudformation", "terraform"]

    user_request: str

    objectives: list[str]
    iac_template: str

    validation_results: list[ValidationResult]
    validation_passed: bool
    deploy_validation_result: Optional[DeployValidationResult]

    stage_error_counts: dict[str, int]

    smell_report: NotRequired[list[dict]]

    remediation_history: list[RemediationHistory]

    current_iteration: int
    max_iterations: int

    llm_call_log: list[LLMCallRecord]

    planner_history:    list[Message]
    engineer_history:   list[Message]
    remediator_history: list[Message]
    retriever_history:  list[Message]

    retriever_context: str
    retriever_queries: list[str]

    final_template: Optional[str]
    run_id: str
