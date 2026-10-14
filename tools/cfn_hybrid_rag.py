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

from prompts.retriever_prompt import QUERY_GEN_SYSTEM

NEO4J_URI      = os.getenv("NEO4J_URI",      "bolt://localhost:7687")
NEO4J_USER     = os.getenv("NEO4J_USER",     "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

CHROMA_HOST = os.getenv("CHROMA_HOST", "localhost")
CHROMA_PORT = int(os.getenv("CHROMA_PORT", "8000"))


CHROMA_DISTANCE_THRESHOLD: float = DEFAULT_DISTANCE_THRESHOLD

_CONTEXT_MODE: str = os.getenv("CHROMA_CONTEXT_MODE", "compact").lower().strip()

_MAX_OPTIONAL_PROPS = 10

_RRF_K = 60


@dataclass
class _PropertyChunk:
    resource_name: str = ""
    resource_description: str = ""
    property_name: str = ""
    property_type: str = ""
    required: str = ""
    update_type: str = ""
    is_example: bool = False
    raw_text: str = ""
    prop_key: str = ""
    rrf_score: float = 0.0


_FIELD_RE = re.compile(
    r"^(?P<key>Resource|Resource Description|Property|Type|Required|Update Type)"
    r":\s*(?P<value>.+)$",
    re.MULTILINE,
)
_DOC_LINK_RE = re.compile(r"https?://docs\.aws\.amazon\.com\S*", re.IGNORECASE)


def _parse_chunk(content: str, meta: dict) -> _PropertyChunk:
    if content.lstrip().startswith("CloudFormation example for"):
        resource = meta.get("resource_name", "") or ""
        return _PropertyChunk(resource_name=resource, is_example=True, raw_text=content)

    fields: dict[str, str] = {}
    for m in _FIELD_RE.finditer(content):
        fields[m.group("key")] = m.group("value").strip()

    if not fields.get("Property"):
        return _PropertyChunk(
            resource_name=meta.get("resource_name", ""),
            raw_text=_DOC_LINK_RE.sub("", content).strip(),
        )

    return _PropertyChunk(
        resource_name=fields.get("Resource", meta.get("resource_name", "")),
        resource_description=fields.get("Resource Description", ""),
        property_name=fields.get("Property", ""),
        property_type=fields.get("Type", ""),
        required=fields.get("Required", ""),
        update_type=fields.get("Update Type", ""),
    )


@dataclass
class _ResourceChunks:
    name: str
    description: str = ""
    properties: list[_PropertyChunk] = field(default_factory=list)
    examples: list[str] = field(default_factory=list)
    raw_chunks: list[str] = field(default_factory=list)
    rrf_score: float = 0.0


def _format_resource_block_compact(rc: _ResourceChunks) -> str:
    lines: list[str] = []
    header = f"#### {rc.name}" if rc.name and rc.name != "_unknown" \
        else "#### (resource type unknown)"
    lines.append(header)

    desc = _DOC_LINK_RE.sub("", rc.description).strip()
    desc = re.sub(r"\s+see[^.]+\.", ".", desc, flags=re.IGNORECASE)
    desc = re.sub(r"\s{2,}", " ", desc).strip()
    if desc:
        lines.append(f"> {desc}")

    for p in rc.properties:
        parts = [p.property_name]
        type_update = ""
        if p.property_type:
            type_update = p.property_type
            if p.update_type and p.update_type.lower() not in ("unknown", ""):
                type_update += f", {p.update_type}"
        if type_update:
            parts.append(f"({type_update})")
        req_flag = "  [required]" if str(p.required).lower() == "true" else ""
        lines.append(f"- {'  '.join(parts)}{req_flag}")

    for raw in rc.raw_chunks:
        lines.append(raw)

    return "\n".join(lines)


def _format_resource_block_raw(chunks: list[str]) -> str:
    return "\n---\n".join(chunks)


def format_prompt_from_neo4j_result(
    resource_data: dict,
    include_example: bool = True,
) -> str:
    if "error" in resource_data:
        print(f"[RAG Tool] ⚠ Neo4j: {resource_data['error']}")
        return ""

    req    = resource_data.get("required_properties") or []
    opt    = resource_data.get("optional_properties") or []
    nested = resource_data.get("nested_types") or []

    if not req and not opt and not nested:
        print(
            f"[RAG Tool] ⚠ {resource_data['name']}: node exists in Neo4j but has "
            f"no properties/nested types. Index may be stale — rerun 03→05 pipeline."
        )
        return ""

    lines = [f"### {resource_data['name']}"]

    if resource_data.get("description"):
        desc = _DOC_LINK_RE.sub("", resource_data["description"]).strip()
        if desc:
            lines.append(f"> {desc}")

    def _fmt_prop(p: dict) -> str:
        base = f"{p['name']}({p['type']})"
        desc = (p.get("description") or "").strip()
        return f"{base} — {desc}" if desc else base

    if req:
        lines.append("Required: " + ", ".join(_fmt_prop(p) for p in req))
    if opt:
        shown = opt[:_MAX_OPTIONAL_PROPS]
        lines.append("Optional: " + ", ".join(_fmt_prop(p) for p in shown))
        if len(opt) > _MAX_OPTIONAL_PROPS:
            lines.append(f"  ... and {len(opt) - _MAX_OPTIONAL_PROPS} more optional properties")

    if nested:
        nt_list = ", ".join(
            f"{nt['name']}({'req' if nt['required'] else 'opt'})"
            for nt in nested
        )
        lines.append(f"NestedTypes: {nt_list}")

    if include_example and resource_data.get("example"):
        lines.append(f"Example:\n```yaml\n{resource_data['example']['code']}\n```")

    return "\n".join(lines)


def query_knowledge_graph(driver, resource_name: str) -> dict:
    CYPHER_QUERY = """
        MATCH (r:Resource {name: $resource_name})

        OPTIONAL MATCH (r)-[:HAS_PROPERTY]->(prop:Property)
        WHERE prop.required = true
        WITH r, collect(DISTINCT {
            name: prop.name,
            type: prop.type,
            description: prop.description
        }) AS required_properties

        OPTIONAL MATCH (r)-[:HAS_PROPERTY]->(opt_prop:Property)
        WHERE opt_prop.required = false
        WITH r, required_properties,
             collect(DISTINCT {
                 name: opt_prop.name,
                 type: opt_prop.type,
                 description: opt_prop.description
             }) AS optional_properties

        OPTIONAL MATCH (r)-[:HAS_NESTED_TYPE]->(nt:NestedType)
        WITH r, required_properties, optional_properties,
             collect(DISTINCT {name: nt.name, type: nt.type, required: nt.required}) AS nested_types

        OPTIONAL MATCH (r)-[:HAS_EXAMPLE]->(e:Example)
        WHERE e.index = 0

        RETURN r.name AS resource_name,
               r.description AS resource_description,
               required_properties,
               optional_properties,
               nested_types,
               { code: e.code } AS example
    """
    with driver.session() as session:
        result = session.run(CYPHER_QUERY, resource_name=resource_name).single()
        if not result:
            return {"error": f"Resource '{resource_name}' not found in Knowledge Graph."}
        return {
            "name":                result["resource_name"],
            "description":        result["resource_description"],
            "required_properties": result["required_properties"],
            "optional_properties": result["optional_properties"],
            "nested_types":        result["nested_types"],
            "example":             result["example"],
        }


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
            collection_name="cfn_schema_properties",
            embedding_function=get_embeddings(),
            collection_metadata=CHROMA_COLLECTION_METADATA,
        )

        seen_prop_keys: set[str] = set()
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

                prop = meta.get("property_name", "") or meta.get("property_path", "")
                prop_key = (
                    f"{res}.{prop}" if prop
                    else f"{res}::content::{hash(chunk.page_content)}"
                )
                rrf_scores[prop_key] += rrf_contribution

                rc = resource_chunks[res]
                rc.name = rc.name or res
                rc.rrf_score = max(rc.rrf_score, rrf_contribution)

                if prop_key in seen_prop_keys:
                    continue
                seen_prop_keys.add(prop_key)

                if _CONTEXT_MODE == "compact":
                    parsed = _parse_chunk(chunk.page_content, meta)
                    parsed.prop_key = prop_key
                    if parsed.is_example:
                        rc.examples.append(parsed.raw_text)
                    elif parsed.property_name:
                        if not rc.description and parsed.resource_description:
                            rc.description = parsed.resource_description
                        rc.properties.append(parsed)
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
            for p in rc.properties:
                p.rrf_score = rrf_scores.get(p.prop_key, 0.0)
            rc.properties.sort(
                key=lambda p: (
                    0 if str(p.required).lower() == "true" else 1,
                    -p.rrf_score,
                    p.property_name,
                )
            )

        print(
            f"[RAG Tool] Stage 1: {kept + dropped + filtered_out} chunks retrieved, "
            f"{dropped} dropped (distance > {CHROMA_DISTANCE_THRESHOLD}), "
            f"{filtered_out} filtered (not in template), "
            f"{kept} kept  [mode={_CONTEXT_MODE}]."
        )

    except Exception as exc:
        print(f"[RAG Tool] Warning: ChromaDB Semantic Search failed. {exc}")

    return dict(resource_chunks), found_resources


def _clean_chunk_raw(content: str) -> str:
    content = _DOC_LINK_RE.sub("", content)
    content = re.sub(r"(?:^|\n)Description:\s*.+?(?=\n[A-Z]|\Z)", "", content, flags=re.DOTALL)
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
            f"[RAG Tool] Stage 2: Scoped to {len(target_resources)} error/chroma resources "
            f"(skipping {len(resources) - len(target_resources)} non-erroring resources)."
        )
    else:
        target_resources = resources
        print(f"[RAG Tool] Stage 2: Querying Neo4j for {len(target_resources)} resources...")

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
        print(f"[RAG Tool] Warning: Neo4j retrieval failed. {exc}")

    return schema_blocks


def _assemble_retrieval_context(
    resource_chunks: dict[str, _ResourceChunks],
    schema_blocks: list[str],
) -> str:
    final_blocks: list[str] = ["## Official AWS CloudFormation Schema Context\n"]

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
            "### Semantically Matched Properties\n"
            + "\n\n".join(resource_sections)
        )

    final_blocks.extend(schema_blocks)
    return "\n\n".join(final_blocks)


def execute_hybrid_retrieval(
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
        return "No specific AWS resources identified in template or retrieval context."

    schema_blocks = _graph_schema_lookup(
        identified_resources,
        chroma_covered=chroma_resources,
        error_resources=error_resources,
    )
    if not schema_blocks and not resource_chunks:
        return "Failed to connect to Knowledge Graph."

    return _assemble_retrieval_context(resource_chunks, schema_blocks)
