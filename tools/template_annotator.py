from __future__ import annotations

import itertools
import json
import re
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


class _CFNTag:

    def __init__(self, tag: str, value: Any) -> None:
        self.tag = tag
        self.value = value

    def __repr__(self) -> str:
        return f"CFNTag({self.tag!r}, {self.value!r})"

    def to_dict(self) -> dict:
        short = self.tag.lstrip("!")
        return {short: self.value}


def _cfn_constructor(loader: yaml.Loader, tag_suffix: str, node: yaml.Node) -> _CFNTag:
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    elif isinstance(node, yaml.MappingNode):
        value = loader.construct_mapping(node, deep=True)
    else:
        value = loader.construct_scalar(node)
    return _CFNTag(tag=tag_suffix, value=value)


def _build_cfn_loader() -> type[yaml.Loader]:
    class CFNLoader(yaml.SafeLoader):
        pass

    yaml.add_multi_constructor("!", _cfn_constructor, Loader=CFNLoader)

    _known_cfn_tags = [
        "!Ref", "!Sub", "!GetAtt", "!If", "!Not", "!And", "!Or",
        "!Equals", "!Select", "!Join", "!Split", "!FindInMap",
        "!Base64", "!Cidr", "!ImportValue", "!Transform",
        "!Condition", "!GetAZs",
    ]
    for tag in _known_cfn_tags:
        yaml.add_constructor(tag, lambda l, n, t=tag: _cfn_constructor(l, t, n), Loader=CFNLoader)

    return CFNLoader


CFN_LOADER = _build_cfn_loader()


def load_cfn_yaml(content: str) -> dict:
    return yaml.load(content, Loader=CFN_LOADER)


@dataclass
class ResourceAnnotation:
    resource_id: str
    resource_type: str
    start_line: int
    end_line: int | None
    raw: dict
    smells: list[dict] = field(default_factory=list)


@dataclass
class TemplateAnnotation:
    file_path: str
    template_type: str
    raw: dict
    resources: list[ResourceAnnotation] = field(default_factory=list)
    parse_error: str | None = None


def _yaml_with_line_numbers(content: str) -> dict[str, int]:
    line_map: dict[str, int] = {}
    in_resources = False
    resource_indent: int | None = None

    for lineno, line in enumerate(content.splitlines(), start=1):
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        if re.match(r"^Resources\s*:", line):
            in_resources = True
            resource_indent = None
            continue

        if in_resources:
            if stripped and not stripped.startswith("#"):
                if resource_indent is None:
                    resource_indent = indent
                if indent == resource_indent and stripped.endswith(":"):
                    resource_id = stripped.rstrip(":")
                    line_map[resource_id] = lineno
                elif indent < resource_indent:
                    in_resources = False

    return line_map


def _hcl2_unwrap(value: Any) -> Any:
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


def _hcl2_lookup(raw: dict, rtype: str, rname: str) -> dict:
    try:
        resources_outer = _hcl2_unwrap(raw.get("resource", []))
        if not isinstance(resources_outer, dict):
            return {}
        type_outer = _hcl2_unwrap(resources_outer.get(rtype, []))
        if not isinstance(type_outer, dict):
            return {}
        name_val = _hcl2_unwrap(type_outer.get(rname, {}))
        return name_val if isinstance(name_val, dict) else {}
    except Exception:
        return {}


def _hcl2_data_lookup(raw: dict, dtype: str, dname: str) -> dict:
    try:
        data_outer = _hcl2_unwrap(raw.get("data", []))
        if not isinstance(data_outer, dict):
            return {}
        type_outer = _hcl2_unwrap(data_outer.get(dtype, []))
        if not isinstance(type_outer, dict):
            return {}
        name_val = _hcl2_unwrap(type_outer.get(dname, {}))
        return name_val if isinstance(name_val, dict) else {}
    except Exception:
        return {}


def _parse_cloudformation(content: str, file_path: str) -> TemplateAnnotation:
    try:
        raw = load_cfn_yaml(content)
        line_map = _yaml_with_line_numbers(content)
    except Exception as exc:
        logger.warning("Failed to parse CloudFormation template %s: %s", file_path, exc)
        return TemplateAnnotation(
            file_path=file_path,
            template_type="cloudformation",
            raw={},
            parse_error=str(exc),
        )

    resources: list[ResourceAnnotation] = []
    for logical_id, resource_body in (raw.get("Resources") or {}).items():
        if not isinstance(resource_body, dict):
            continue

        rtype = resource_body.get("Type", "")
        if isinstance(rtype, _CFNTag):
            rtype = str(rtype.value)

        resources.append(ResourceAnnotation(
            resource_id=logical_id,
            resource_type=rtype,
            start_line=line_map.get(logical_id, 0),
            end_line=None,
            raw=resource_body,
        ))

    return TemplateAnnotation(
        file_path=file_path,
        template_type="cloudformation",
        raw=raw,
        resources=resources,
    )


def _parse_terraform(content: str, file_path: str) -> TemplateAnnotation:
    resources: list[ResourceAnnotation] = []

    raw: dict = {}
    try:
        import hcl2
        import io
        raw = hcl2.load(io.StringIO(content))
    except ImportError:
        logger.debug("python-hcl2 not installed; using regex fallback for %s", file_path)
    except Exception as exc:
        logger.warning("hcl2 parse error for %s: %s", file_path, exc)

    resource_pattern = re.compile(
        r'^resource\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{',
        re.MULTILINE,
    )
    data_pattern = re.compile(
        r'^data\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{',
        re.MULTILINE,
    )

    block_iter = itertools.chain(
        ((m, False) for m in resource_pattern.finditer(content)),
        ((m, True)  for m in data_pattern.finditer(content)),
    )

    for match, is_data in block_iter:
        rtype = match.group("type")
        rname = match.group("name")
        start_line = content[: match.start()].count("\n") + 1

        resource_id = f"data.{rtype}.{rname}" if is_data else f"{rtype}.{rname}"

        raw_block = (
            _hcl2_data_lookup(raw, rtype, rname)
            if is_data
            else _hcl2_lookup(raw, rtype, rname)
        )

        resources.append(ResourceAnnotation(
            resource_id=resource_id,
            resource_type=rtype,
            start_line=start_line,
            end_line=None,
            raw=raw_block,
        ))

    return TemplateAnnotation(
        file_path=file_path,
        template_type="terraform",
        raw=raw,
        resources=resources,
    )


_CFN_MARKERS = {"AWSTemplateFormatVersion", "Resources", "Outputs", "Parameters"}


def _detect_template_type(content: str, file_path: str) -> str:
    if Path(file_path).suffix.lower() in (".tf",):
        return "terraform"
    if any(marker in content for marker in _CFN_MARKERS):
        return "cloudformation"
    if Path(file_path).suffix.lower() in (".json",):
        try:
            doc = json.loads(content)
            if isinstance(doc, dict) and "Resources" in doc:
                return "cloudformation"
        except json.JSONDecodeError:
            pass
    return "unknown"


def annotate_template(file_path: str, content: str | None = None) -> TemplateAnnotation:
    if content is None:
        content = Path(file_path).read_text(encoding="utf-8")

    template_type = _detect_template_type(content, file_path)
    logger.debug("Detected template type '%s' for %s", template_type, file_path)

    if template_type == "cloudformation":
        return _parse_cloudformation(content, file_path)
    elif template_type == "terraform":
        return _parse_terraform(content, file_path)
    else:
        return TemplateAnnotation(
            file_path=file_path,
            template_type="unknown",
            raw={},
            parse_error=f"Unrecognised template format for file: {file_path}",
        )


def attach_smells(
    annotation: TemplateAnnotation,
    smell_report: list[dict],
) -> TemplateAnnotation:
    resource_index = {r.resource_id: r for r in annotation.resources}
    for smell in smell_report:
        rid = smell.get("resource_id", "")
        if rid in resource_index:
            resource_index[rid].smells.append(smell)
        else:
            logger.debug(
                "Smell %s could not be mapped to a resource (resource_id=%r)",
                smell.get("rule_id"), rid,
            )
    return annotation


def extract_resource_types(annotation: TemplateAnnotation | None) -> set[str]:
    if not annotation or not annotation.resources:
        return set()
    return {r.resource_type for r in annotation.resources if r.resource_type}


_DICT_LINENO_RE = re.compile(r"'LineNumber'\s*:\s*(\d+)")

_COLON_LINENO_RE = re.compile(r":(\d+)(?::\d+)?")

_PROSE_LINENO_RE = re.compile(r"(?<!\w)line\s+(\d+)", re.IGNORECASE)


def _extract_line_number(error: str) -> int | None:
    m = _DICT_LINENO_RE.search(error)
    if m:
        return int(m.group(1))
    m = _COLON_LINENO_RE.search(error)
    if m:
        return int(m.group(1))
    m = _PROSE_LINENO_RE.search(error)
    if m:
        return int(m.group(1))
    return None


def render_annotated_template(
    template_yaml: str,
    errors: list[str],
) -> str:
    if not template_yaml:
        return "# No template available.\n" + "\n".join(f"# ERROR: {e}" for e in errors)

    errors_by_line: dict[int, list[str]] = defaultdict(list)
    for err in errors:
        lineno = _extract_line_number(err)
        errors_by_line[lineno if lineno is not None else 0].append(err)

    source_lines = template_yaml.splitlines()
    output: list[str] = []

    if errors_by_line.get(0):
        output.append("# --- Errors without line numbers (deploy failures) ---")
        for err in errors_by_line[0]:
            output.append(f"# ERROR: {err}")
        output.append("")

    for lineno, line in enumerate(source_lines, start=1):
        for err in errors_by_line.get(lineno, []):
            indent = len(line) - len(line.lstrip())
            output.append(" " * indent + f"# ERROR: {err}")
        output.append(line)

    return "\n".join(output)


_TF_ANNOTATABLE_STAGES = ("tflint", "terraform-validate", "terraform validate")

_TF_PROSE_LINE_RE = re.compile(r"(?<!\w)line\s+(\d+)", re.IGNORECASE)

_TF_COMPACT_RE = re.compile(r"(?:main\.tf|\S+\.tf):(\d+):\d+")

_TF_COLON_RE = re.compile(r":(\d+)(?::\d+)?")


def _extract_tf_line_number(error: str) -> int | None:
    m = _TF_PROSE_LINE_RE.search(error)
    if m:
        return int(m.group(1))
    m = _TF_COMPACT_RE.search(error)
    if m:
        return int(m.group(1))
    m = _TF_COLON_RE.search(error)
    if m:
        return int(m.group(1))
    return None


def _collapse_to_one_line(error: str) -> str:
    return re.sub(r"\s+", " ", error).strip()


def render_annotated_terraform(
    template_hcl: str,
    stage_errors: dict[str, list[str]],
) -> str:
    if not template_hcl:
        return "# No template available.\n"

    qualifying_errors: list[str] = []
    for stage_name, errs in stage_errors.items():
        stage_lower = stage_name.lower()
        if any(marker in stage_lower for marker in _TF_ANNOTATABLE_STAGES):
            qualifying_errors.extend(errs)

    if not qualifying_errors:
        return template_hcl

    errors_by_line: dict[int, list[str]] = defaultdict(list)
    for err in qualifying_errors:
        lineno = _extract_tf_line_number(err)
        if lineno is not None:
            errors_by_line[lineno].append(_collapse_to_one_line(err))

    if not errors_by_line:
        return template_hcl

    source_lines = template_hcl.splitlines()
    output: list[str] = []

    for lineno, line in enumerate(source_lines, start=1):
        for err in errors_by_line.get(lineno, []):
            indent = len(line) - len(line.lstrip())
            output.append(" " * indent + f"# ERROR: {err}")
        output.append(line)

    return "\n".join(output)
