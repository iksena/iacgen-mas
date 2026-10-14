from __future__ import annotations

import os
import re
from collections import defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field

import chromadb
from langchain_chroma import Chroma
from neo4j import GraphDatabase

from tools.embedding_provider import (
    get_embeddings,
    CHROMA_COLLECTION_METADATA,
    DEFAULT_DISTANCE_THRESHOLD,
)

NEO4J_URI      = os.getenv("NEO4J_URI",      "bolt://localhost:7687")
NEO4J_USER     = os.getenv("NEO4J_USER",     "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))

CHROMA_DISTANCE_THRESHOLD: float = DEFAULT_DISTANCE_THRESHOLD

_CONTEXT_MODE: str = os.getenv("CHROMA_CONTEXT_MODE", "compact").lower().strip()

_MAX_OPTIONAL_ATTRS = 10

_RRF_K = 60

_TF_COLLECTION_NAME = "tf_schema_properties"

_DOC_LINK_RE = re.compile(r"https?://registry\.terraform\.io\S*", re.IGNORECASE)

_SEE_ALSO_RE = re.compile(r"\s+see[^.]+\.", re.IGNORECASE)

_DESC_FIELD_RE = re.compile(
    r"(?:^|\n)(?:Argument |Attribute )?Description:\s*.+?(?=\n[A-Z]|\Z)",
    re.DOTALL,
)


@dataclass
class _AttributeChunk:
    resource_name: str = ""
    resource_description: str = ""
    attribute_name: str = ""
    attribute_type: str = ""
    required: str = ""
    force_new: str = ""
    is_example: bool = False
    raw_text: str = ""
    attr_key: str = ""
    rrf_score: float = 0.0


_FIELD_RE = re.compile(
    r"^(?P<key>Resource|Resource Description|Attribute|Type|Required|Force New)"
    r":\s*(?P<value>.+)$",
    re.MULTILINE,
)


def _parse_chunk(content: str, meta: dict) -> _AttributeChunk:
    if content.lstrip().startswith("Terraform example for"):
        resource = meta.get("resource_name", "") or ""
        return _AttributeChunk(resource_name=resource, is_example=True, raw_text=content)

    fields: dict[str, str] = {}
    for m in _FIELD_RE.finditer(content):
        fields[m.group("key")] = m.group("value").strip()

    if not fields.get("Attribute"):
        return _AttributeChunk(
            resource_name=meta.get("resource_name", ""),
            raw_text=_DOC_LINK_RE.sub("", content).strip(),
        )

    return _AttributeChunk(
        resource_name=fields.get("Resource", meta.get("resource_name", "")),
        resource_description=fields.get("Resource Description", ""),
        attribute_name=fields.get("Attribute", ""),
        attribute_type=fields.get("Type", ""),
        required=fields.get("Required", ""),
        force_new=fields.get("Force New", ""),
    )


@dataclass
class _ResourceChunks:
    name: str
    description: str = ""
    attributes: list[_AttributeChunk] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)
    raw_chunks: list[str] = field(default_factory=list)
    rrf_score: float = 0.0


def _format_resource_block_compact(rc: _ResourceChunks) -> str:
    lines: list[str] = []
    header = f"#### {rc.name}" if rc.name and rc.name != "_unknown" \
        else "#### (resource type unknown)"
    lines.append(header)

    desc = _DOC_LINK_RE.sub("", rc.description).strip()
    desc = _SEE_ALSO_RE.sub(".", desc)
    desc = re.sub(r"\s{2,}", " ", desc).strip()
    if desc:
        lines.append(f"> {desc}")

    for a in rc.attributes:
        parts = [a.attribute_name]
        type_info = ""
        if a.attribute_type:
            type_info = a.attribute_type
            if a.force_new and a.force_new.lower() not in ("false", ""):
                type_info += ", Force New"
        if type_info:
            parts.append(f"({type_info})")
        req_flag = "  [required]" if str(a.required).lower() == "true" else ""
        lines.append(f"- {'  '.join(parts)}{req_flag}")

    for raw in rc.raw_chunks:
        lines.append(raw)

    return "\n".join(lines)


def _format_resource_block_raw(chunks: list[str]) -> str:
    return "\n---\n".join(chunks)


def query_knowledge_graph(driver, resource_name: str) -> dict:
    CYPHER_QUERY = """
        MATCH (r:TFResource {name: $resource_name})

        OPTIONAL MATCH (r)-[:HAS_ATTRIBUTE]->(req_attr:TFAttribute)
        WHERE req_attr.required = true
        WITH r, collect(DISTINCT {
            name:        req_attr.name,
            type:        req_attr.type,
            description: req_attr.description
        }) AS required_properties

        OPTIONAL MATCH (r)-[:HAS_ATTRIBUTE]->(opt_attr:TFAttribute)
        WHERE opt_attr.required = false
        WITH r, required_properties,
             collect(DISTINCT {
                 name:        opt_attr.name,
                 type:        opt_attr.type,
                 description: opt_attr.description
             }) AS optional_properties

        OPTIONAL MATCH (r)-[:HAS_BLOCK]->(b:TFBlock)
        WITH r, required_properties, optional_properties,
             collect(DISTINCT {
                 name:         b.name,
                 nesting_mode: b.nesting_mode,
                 min_items:    b.min_items,
                 required:     (b.min_items IS NOT NULL AND b.min_items > 0)
             }) AS nested_types

        OPTIONAL MATCH (r)-[:HAS_EXAMPLE]->(e:TFExample)
        WITH r, required_properties, optional_properties, nested_types,
             collect(e.code)[0] AS example_code

        RETURN r.name         AS resource_name,
               r.description  AS resource_description,
               required_properties,
               optional_properties,
               nested_types,
               { code: example_code } AS example
    """
    with driver.session() as session:
        result = session.run(CYPHER_QUERY, resource_name=resource_name).single()
        if not result:
            return {"error": f"TFResource '{resource_name}' not found in Knowledge Graph."}
        return {
            "name":                result["resource_name"],
            "description":        result["resource_description"],
            "required_properties": result["required_properties"],
            "optional_properties": result["optional_properties"],
            "nested_types":        result["nested_types"],
            "example":             result["example"],
        }


def format_prompt_from_neo4j_result(
    resource_data: dict,
    include_example: bool = True,
) -> str:
    if "error" in resource_data:
        print(f"[TF RAG] ⚠ Neo4j: {resource_data['error']}")
        return ""

    req    = resource_data.get("required_properties") or []
    opt    = resource_data.get("optional_properties") or []
    nested = resource_data.get("nested_types") or []

    if not req and not opt and not nested:
        print(
            f"[TF RAG] ⚠ {resource_data['name']}: node exists in Neo4j but has "
            f"no attributes/blocks. Index may be stale — rerun TF ingestion pipeline."
        )
        return ""

    lines = [f"### {resource_data['name']}"]

    if resource_data.get("description"):
        desc = _DOC_LINK_RE.sub("", resource_data["description"]).strip()
        if desc:
            lines.append(f"> {desc}")

    def _fmt_attr(a: dict) -> str:
        base = f"{a['name']}({a.get('type', '?')})"
        desc = (a.get("description") or "").strip()
        return f"{base} — {desc}" if desc else base

    if req:
        lines.append("Required: " + ", ".join(_fmt_attr(a) for a in req))
    if opt:
        shown = opt[:_MAX_OPTIONAL_ATTRS]
        lines.append("Optional: " + ", ".join(_fmt_attr(a) for a in shown))
        if len(opt) > _MAX_OPTIONAL_ATTRS:
            lines.append(f"  ... and {len(opt) - _MAX_OPTIONAL_ATTRS} more optional attributes")

    if nested:
        nt_list = ", ".join(
            f"{nt['name']}({'req' if nt.get('required') else 'opt'})"
            for nt in nested
            if nt.get("name")
        )
        if nt_list:
            lines.append(f"NestedTypes: {nt_list}")

    if include_example and resource_data.get("example") and resource_data["example"].get("code"):
        lines.append(f"Example:\n```hcl\n{resource_data['example']['code']}\n```")

    return "\n".join(lines)


@contextmanager
def _neo4j_driver():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    try:
        yield driver
    finally:
        driver.close()


def _semantic_search(
    retrieval_queries: list[str],
    resource_filter: set[str] | None = None,
) -> tuple[dict[str, _ResourceChunks], set[str]]:
    resource_chunks: dict[str, _ResourceChunks] = defaultdict(
        lambda: _ResourceChunks(name="")
    )
    found_resources: set[str] = set()

    if not retrieval_queries:
        return dict(resource_chunks), found_resources

    try:
        chroma_client = chromadb.HttpClient(host=CHROMA_HOST, port=CHROMA_PORT)
        vectorstore = Chroma(
            client=chroma_client,
            collection_name=_TF_COLLECTION_NAME,
            embedding_function=get_embeddings(),
            collection_metadata=CHROMA_COLLECTION_METADATA,
        )

        seen_attr_keys: set[str] = set()
        rrf_scores: dict[str, float] = defaultdict(float)
        kept = 0
        dropped = 0
        filtered_out = 0

        for query in retrieval_queries:
            scored_chunks = vectorstore.similarity_search_with_score(query, k=3)

            survivors: list[tuple] = []
            for chunk, score in scored_chunks:
                if score > CHROMA_DISTANCE_THRESHOLD:
                    dropped += 1
                    continue

                meta = chunk.metadata
                res  = meta.get("resource_name", "") or "_unknown"

                if resource_filter and res not in resource_filter:
                    filtered_out += 1
                    continue

                survivors.append((chunk, meta, res))

            for rank, (chunk, meta, res) in enumerate(survivors, start=1):
                rrf_contribution = 1.0 / (_RRF_K + rank)

                attr = meta.get("attribute_name", "") or meta.get("attribute_path", "")
                attr_key = (
                    f"{res}.{attr}" if attr
                    else f"{res}::content::{hash(chunk.page_content)}"
                )
                rrf_scores[attr_key] += rrf_contribution

                rc = resource_chunks[res]
                rc.name = rc.name or res
                rc.rrf_score = max(rc.rrf_score, rrf_contribution)

                if attr_key in seen_attr_keys:
                    continue
                seen_attr_keys.add(attr_key)

                if _CONTEXT_MODE == "compact":
                    parsed = _parse_chunk(chunk.page_content, meta)
                    parsed.attr_key = attr_key
                    if parsed.is_example:
                        rc.examples.append(parsed.raw_text)
                    elif parsed.attribute_name:
                        if not rc.description and parsed.resource_description:
                            rc.description = parsed.resource_description
                        rc.attributes.append(parsed)
                    else:
                        rc.raw_chunks.append(parsed.raw_text)
                else:
                    cleaned = _clean_chunk_raw(chunk.page_content)
                    if cleaned:
                        rc.raw_chunks.append(cleaned)

                kept += 1
                if res and res != "_unknown":
                    found_resources.add(res)

        for rc in resource_chunks.values():
            for a in rc.attributes:
                a.rrf_score = rrf_scores.get(a.attr_key, 0.0)
            rc.attributes.sort(
                key=lambda a: (
                    0 if str(a.required).lower() == "true" else 1,
                    -a.rrf_score,
                    a.attribute_name,
                )
            )

        print(
            f"[TF RAG] Stage 1: {kept + dropped + filtered_out} chunks retrieved, "
            f"{dropped} dropped (distance > {CHROMA_DISTANCE_THRESHOLD}), "
            f"{filtered_out} filtered (not in template), "
            f"{kept} kept  [mode={_CONTEXT_MODE}]."
        )

    except Exception as exc:
        print(f"[TF RAG] Warning: ChromaDB Semantic Search failed. {exc}")

    return dict(resource_chunks), found_resources


def _clean_chunk_raw(content: str) -> str:
    content = _DOC_LINK_RE.sub("", content)
    content = _DESC_FIELD_RE.sub("", content)
    return re.sub(r"\n{3,}", "\n\n", content).strip()


def _graph_schema_lookup(
    resources: set[str],
    chroma_covered: set[str],
    error_resources: set[str] | None = None,
) -> list[str]:
    schema_blocks: list[str] = []

    if not resources:
        return schema_blocks

    if error_resources:
        target_resources = error_resources | (resources & chroma_covered)
        print(
            f"[TF RAG] Stage 2: Scoped to {len(target_resources)} error/chroma resources "
            f"(skipping {len(resources) - len(target_resources)} non-erroring resources)."
        )
    else:
        target_resources = resources
        print(f"[TF RAG] Stage 2: Querying Neo4j for {len(target_resources)} TF resources...")

    try:
        with _neo4j_driver() as driver:
            seen: set[str] = set()
            for resource in sorted(target_resources):
                if resource in seen:
                    continue
                seen.add(resource)
                res_data = query_knowledge_graph(driver, resource)
                include_ex = not (
                    _CONTEXT_MODE == "compact" and resource in chroma_covered
                )
                block = format_prompt_from_neo4j_result(res_data, include_example=include_ex)
                if block:
                    schema_blocks.append(block)
    except Exception as exc:
        print(f"[TF RAG] Warning: Neo4j retrieval failed. {exc}")

    return schema_blocks


def _assemble_retrieval_context(
    resource_chunks: dict[str, _ResourceChunks],
    schema_blocks: list[str],
) -> str:
    final_blocks: list[str] = ["## Official Terraform Provider Schema Context\n"]

    if resource_chunks:
        resource_sections: list[str] = []
        for resource_name, rc in sorted(
            resource_chunks.items(),
            key=lambda item: (-item[1].rrf_score, item[0]),
        ):
            if _CONTEXT_MODE == "compact":
                block = _format_resource_block_compact(rc)
            else:
                header = (
                    f"#### {resource_name}" if resource_name != "_unknown"
                    else "#### (resource type unknown)"
                )
                block = header + "\n" + _format_resource_block_raw(rc.raw_chunks)
            resource_sections.append(block)

        final_blocks.append(
            "### Semantically Matched Attributes\n"
            + "\n\n".join(resource_sections)
        )

    final_blocks.extend(schema_blocks)
    return "\n\n".join(final_blocks)


def execute_terraform_retrieval(
    retrieval_queries: list[str],
    seed_resources: set[str],
    error_resources: set[str] | None = None,
) -> str:
    resource_chunks, chroma_resources = _semantic_search(
        retrieval_queries,
        resource_filter=seed_resources,
    )

    identified_resources = seed_resources | chroma_resources

    if not identified_resources:
        return "No specific Terraform resources identified in template or retrieval context."

    schema_blocks = _graph_schema_lookup(
        identified_resources,
        chroma_covered=chroma_resources,
        error_resources=error_resources,
    )

    if not schema_blocks and not resource_chunks:
        return "Failed to connect to Terraform Knowledge Graph."

    return _assemble_retrieval_context(resource_chunks, schema_blocks)
