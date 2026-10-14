from __future__ import annotations

import re

from state import GraphState, RemediationHistory, Message, append_and_cap
from agents.llm_client import _build_client, _call_llm_with_history, build_session_id
from prompts.retriever_prompt import get_query_gen_system
from tools.template_annotator import (
    TemplateAnnotation,
    annotate_template,
    attach_smells,
    render_annotated_template,
    render_annotated_terraform,
    extract_resource_types,
)
from tools.cfn_hybrid_rag import execute_hybrid_retrieval
from tools.retriever_helpers import extract_errors, parse_query_response
from tracking.recorder import ResearchRecorder


_WORD_LINE_RE  = re.compile(r"\bline\s+\d+\b", re.IGNORECASE)
_COLON_LINE_RE = re.compile(r":\d+(:\d+)?")
_DICT_LINE_RE  = re.compile(r"'LineNumber'\s*:\s*\d+")


_CFN_LINT_RESOURCE_RE = re.compile(r"Resource:\s*([\w-]+)", re.IGNORECASE)

_TF_VALIDATE_RESOURCE_RE = re.compile(
    r'in\s+(?P<block_type>data|resource)\s+"(?P<type>[a-z][a-z0-9_]*)"\s+"(?P<name>[^"]+)"',
    re.IGNORECASE,
)

_TF_ADDRESS_RE = re.compile(
    r'\b(?P<type>(?:data\.)?(?:aws|google|azurerm|random|local|null|archive|tls)_[a-z][a-z0-9_]*)\.(?P<name>[a-z][a-z0-9_-]*)\b',
    re.IGNORECASE,
)

_TF_BRACKET_RE = re.compile(
    r'\[(?P<type>(?:data\.)?(?:aws|google|azurerm|random|local|null|archive|tls)_[a-z][a-z0-9_]*)\.(?P<name>[a-z][a-z0-9_-]*)\]',
    re.IGNORECASE,
)

_TF_FORMATTED_ERROR_RE = re.compile(
    r'(?:A\s+)?(?P<block_type>data|managed|resource)\s+resource\s+'
    r'"(?P<type>[a-z][a-z0-9_]*)"\s+"(?P<name>[^"]+)"',
    re.IGNORECASE,
)


def _errors_have_line_numbers(errors: list[str]) -> bool:
    for e in errors:
        if _WORD_LINE_RE.search(e) or _COLON_LINE_RE.search(e) or _DICT_LINE_RE.search(e):
            return True
    return False


def _extract_error_resources(
    errors: list[str],
    annotation: TemplateAnnotation | None,
    deploy_validation_result: dict | None,
) -> set[str]:
    if not annotation:
        return set()

    error_resource_types: set[str] = set()

    logical_to_type: dict[str, str] = {
        r.resource_id: r.resource_type
        for r in annotation.resources
        if r.resource_id and r.resource_type
    }

    error_logical_ids: set[str] = set()

    for error_str in errors:
        m = _CFN_LINT_RESOURCE_RE.search(error_str)
        if m:
            error_logical_ids.add(m.group(1).strip())

    if deploy_validation_result and not deploy_validation_result.get("passed"):
        for fr in deploy_validation_result.get("failed_resources", []):
            logical_id = fr.get("logical_name") or ""
            if logical_id:
                error_logical_ids.add(logical_id.strip())

    for logical_id in error_logical_ids:
        resource_type = logical_to_type.get(logical_id)
        if resource_type:
            error_resource_types.add(resource_type)

    known_tf_types: set[str] = set()
    for r in annotation.resources:
        if not r.resource_type:
            continue
        if r.resource_id and r.resource_id.startswith("data."):
            known_tf_types.add(f"data.{r.resource_type}")
        else:
            known_tf_types.add(r.resource_type)

    if known_tf_types and not any(t.startswith("AWS::") for t in known_tf_types):
        for error_str in errors:
            for m in _TF_VALIDATE_RESOURCE_RE.finditer(error_str):
                rtype = m.group("type").lower()
                if m.group("block_type").lower() == "data":
                    rtype = f"data.{rtype}"
                if rtype in known_tf_types:
                    error_resource_types.add(rtype)

            for m in _TF_ADDRESS_RE.finditer(error_str):
                rtype = m.group("type").lower()
                if rtype in known_tf_types:
                    error_resource_types.add(rtype)

            for m in _TF_BRACKET_RE.finditer(error_str):
                rtype = m.group("type").lower()
                if rtype in known_tf_types:
                    error_resource_types.add(rtype)

            for m in _TF_FORMATTED_ERROR_RE.finditer(error_str):
                rtype = m.group("type").lower()
                block_type = m.group("block_type").lower()
                if block_type == "data":
                    rtype = f"data.{rtype}"
                if rtype in known_tf_types:
                    error_resource_types.add(rtype)

    if error_resource_types:
        print(
            f"[Retriever] Error resources scoped to: {sorted(error_resource_types)}"
        )
    else:
        print("[Retriever] No error resources resolved — Neo4j will use full seed set.")

    return error_resource_types


def _annotate_safely(
    template: str,
    smell_report: list[dict] | None,
    iac_type: str = "cloudformation",
) -> TemplateAnnotation | None:
    if not template:
        return None
    try:
        file_path_hint = "<in-memory>.tf" if iac_type == "terraform" else "<in-memory>.yaml"
        annotation = annotate_template(file_path=file_path_hint, content=template)
        if smell_report:
            annotation = attach_smells(annotation, smell_report)
        print(f"[Retriever] Annotation: {len(annotation.resources)} resources parsed.")
        return annotation
    except Exception as exc:
        print(f"[Retriever] Annotation failed (non-fatal): {exc}")
        return None


def _build_retrieval_annotated_template(
    template: str,
    errors: list[str],
    stage_errors: dict[str, list[str]],
    iac_type: str,
) -> str:
    if iac_type == "terraform":
        return render_annotated_terraform(
            template_hcl=template,
            stage_errors=stage_errors,
        )
    return render_annotated_template(
        template_yaml=template,
        errors=errors,
    )


def build_retrieval_prompt(
    errors: list[str],
    template: str | None,
    annotation: TemplateAnnotation | None,
    remediation_history: list[RemediationHistory],
    iac_type: str = "cloudformation",
    stage_errors: dict[str, list[str]] | None = None,
) -> str:
    parts: list[str] = [
        "## Validation Errors\n" + "\n".join(f"- {e}" for e in errors)
    ]

    if template and _errors_have_line_numbers(errors):
        annotated = _build_retrieval_annotated_template(
            template=template,
            errors=errors,
            stage_errors=stage_errors or {},
            iac_type=iac_type,
        )
        parts.append(
            "## IaC Template (errors annotated at reported lines)\n"
            "Lines prefixed with `# ERROR:` mark the exact location the validator\n"
            "reported a violation. Use the resource name and rule description\n"
            "from the error list above as the primary signal for schema retrieval.\n"
            f"```\n{annotated}\n```"
        )
    elif template:
        parts.append(
            "## IaC Template\n"
            "No line-number annotations available — use the error messages\n"
            "above to identify which resource types and attributes need schema retrieval.\n"
            f"```\n{template}\n```"
        )

    history_lines: list[str] = []
    for entry in remediation_history:
        if not entry.get("retrieval_queries"):
            continue
        queries_str = "\n".join(f"  - {q}" for q in entry["retrieval_queries"])
        history_lines.append(f"### Iteration {entry['iteration']} queries used:\n{queries_str}")

    if history_lines:
        parts.append(
            "## Prior Retrieval Queries\n"
            "These queries were already used in previous iterations.\n"
            "Generate DIFFERENT queries targeting unexplored resource.attribute combinations.\n"
            "\n" + "\n\n".join(history_lines)
        )

    return "\n\n".join(parts)


def _get_active_error_types(state: GraphState) -> tuple[bool, bool]:
    has_schema = False
    has_security = False

    latest_by_stage: dict[str, dict] = {}
    for result in state.get("validation_results", []):
        stage = str(result.get("stage") or "").strip()
        if stage:
            latest_by_stage[stage] = result

    if not latest_by_stage.get("cfn-lint", {}).get("passed", True):
        has_schema = True
    if not latest_by_stage.get("tflint", {}).get("passed", True):
        has_schema = True
    if not latest_by_stage.get("terraform-validate", {}).get("passed", True):
        has_schema = True

    deploy = state.get("deploy_validation_result")
    if deploy and not deploy.get("passed") and deploy.get("target") != "skipped":
        has_schema = True

    if not latest_by_stage.get("checkov", {}).get("passed", True):
        has_security = True
    if not latest_by_stage.get("trivy", {}).get("passed", True):
        has_security = True

    if not has_schema and not has_security:
        has_schema, has_security = True, True

    return has_schema, has_security


def _call_query_generator(
    user_content: str,
    system_prompt: str,
    session_id: str | None = None,
) -> tuple[str, str, dict | None]:
    client, model = _build_client()
    raw_response, usage = _call_llm_with_history(
        client,
        model,
        system=system_prompt,
        messages=[{"role": "user", "content": user_content}],
        session_id=session_id,
    )
    return model, raw_response, usage


def _build_tf_seed_resources(annotation: TemplateAnnotation | None) -> set[str]:
    if not annotation:
        return set()
    seed: set[str] = set()
    for r in annotation.resources:
        if not r.resource_type:
            continue
        if r.resource_id and r.resource_id.startswith("data."):
            seed.add(f"data.{r.resource_type}")
        else:
            seed.add(r.resource_type)
    return seed


def retriever_agent(state: GraphState, recorder: ResearchRecorder) -> GraphState:
    iteration = state["current_iteration"]
    iac_type = state.get("iac_type", "cloudformation")
    print(f"\n[Retriever] Building context (iteration {iteration}, iac_type={iac_type})...")

    deploy_validation_result = state.get("deploy_validation_result")

    errors = extract_errors(
        state.get("validation_results", []),
        deploy_validation_result,
    )

    stage_errors: dict[str, list[str]] = {}
    for result in state.get("validation_results", []):
        stage = str(result.get("stage") or "").strip()
        if not stage:
            continue
        errs = [str(e) for e in result.get("errors", []) if str(e).strip()]
        if errs:
            stage_errors[stage] = errs

    template = state.get("iac_template", "")
    annotation = _annotate_safely(
        template=template,
        smell_report=state.get("smell_report"),
        iac_type=iac_type,
    )

    has_schema, has_security = _get_active_error_types(state)
    print(f"[Retriever] Routing -> Schema: {has_schema} | Security: {has_security}")

    schema_queries: list[str] = []
    iac_context = ""
    llm_record = None

    if has_schema:
        has_line_numbers = _errors_have_line_numbers(errors)
        print(
            f"[Retriever] {'Line numbers detected — annotated template' : <45} "
            f"{'included' if has_line_numbers else 'NOT included (plain template used)'}."
        )

        query_gen_system = get_query_gen_system(iac_type)

        user_content = build_retrieval_prompt(
            errors=errors,
            template=template,
            annotation=annotation,
            remediation_history=state.get("remediation_history", []),
            iac_type=iac_type,
            stage_errors=stage_errors,
        )

        model, raw_response, usage = _call_query_generator(
            user_content=user_content,
            system_prompt=query_gen_system,
            session_id=build_session_id(state, "retriever"),
        )
        parsed_queries = parse_query_response(raw_response)
        schema_queries = parsed_queries.get("schema_queries", [])

        if not schema_queries:
            schema_queries = errors[:8]

        llm_record = recorder.record_llm_call(
            state=state,
            agent="retriever",
            model=usage.get("reported_model") or model,
            prompt=f"SYSTEM:\n{query_gen_system}\n\nUSER:\n{user_content}",
            response=raw_response,
            token_usage=usage,
        )

        if iac_type == "terraform":
            seed_resources = _build_tf_seed_resources(annotation)
        else:
            seed_resources = extract_resource_types(annotation)

        print(f"[Retriever] seed_resources ({len(seed_resources)}): {sorted(seed_resources)}")

        error_resources = _extract_error_resources(
            errors=errors,
            annotation=annotation,
            deploy_validation_result=deploy_validation_result,
        ) or None

        if iac_type == "terraform":
            from tools.tf_hybrid_rag import execute_terraform_retrieval
            iac_context = execute_terraform_retrieval(
                retrieval_queries=schema_queries,
                seed_resources=seed_resources,
                error_resources=error_resources,
            )
        else:
            iac_context = execute_hybrid_retrieval(
                retrieval_queries=schema_queries,
                seed_resources=seed_resources,
                error_resources=error_resources,
            )
    else:
        user_content = ""
        raw_response = ""
        model = ""
        usage = None

    security_context = ""
    security_ids: list[str] = []

    if has_security:
        from tools.security_hybrid_rag import execute_security_retrieval, extract_trivy_check_ids
        security_ids = extract_trivy_check_ids(errors)
        security_context = execute_security_retrieval(
            raw_errors=errors,
            iac_type=iac_type,
        )

    unified_context = "\n\n".join(
        part for part in (iac_context, security_context) if part.strip()
    )

    retrieval_queries = schema_queries + security_ids

    query_gen_system = get_query_gen_system(iac_type)

    user_msg: Message = {"role": "user", "content": user_content if has_schema else ""}
    assistant_msg: Message = {"role": "assistant", "content": raw_response if has_schema else ""}

    recorder.append_retriever_history_entry(
        iteration=iteration,
        prompt=f"SYSTEM:\n{query_gen_system}\n\nUSER:\n{user_content if has_schema else ''}",
        response=raw_response if has_schema else "",
        retrieval_queries=retrieval_queries,
        context_chars=len(unified_context),
        retrieved_context=unified_context,
    )

    print(
        f"[Retriever] Context: {len(unified_context)} char(s) | "
        f"{len(schema_queries)} schema quer(y/ies) | "
        f"{len(security_ids)} security ID(s) resolved."
    )

    return {
        "retriever_context":  unified_context,
        "retriever_queries":  retrieval_queries,
        "llm_call_log":       state["llm_call_log"] + ([llm_record] if llm_record else []),
        "retriever_history":  append_and_cap(
            state.get("retriever_history", []), user_msg, assistant_msg
        ),
    }
