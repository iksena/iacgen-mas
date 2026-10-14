from __future__ import annotations

import json
from pathlib import Path


SCHEMA_FILE   = Path("tf_schema_raw.json")
DOCS_FILE     = Path("tf_registry_docs.json")
OUTPUT_FILE   = Path("tf_knowledge_graph.json")


def _type_str(type_expr) -> str:
    if isinstance(type_expr, str):
        return type_expr
    if isinstance(type_expr, list) and type_expr:
        outer = type_expr[0]
        if len(type_expr) == 1:
            return outer
        inner = _type_str(type_expr[1])
        return f"{outer}({inner})"
    return str(type_expr)


def _parse_attributes(attrs: dict) -> dict:
    result: dict[str, dict] = {}
    for attr_name, attr_data in attrs.items():
        result[attr_name] = {
            "type":      _type_str(attr_data.get("type", "unknown")),
            "optional":  bool(attr_data.get("optional", False)),
            "required":  bool(attr_data.get("required", False)),
            "computed":  bool(attr_data.get("computed", False)),
            "sensitive": bool(attr_data.get("sensitive", False)),
            "description": attr_data.get("description", ""),
        }
    return result


def _parse_block_types(block_types: dict) -> dict:
    result: dict[str, dict] = {}
    for block_name, block_data in block_types.items():
        nesting = block_data.get("nesting_mode", "single")
        inner   = block_data.get("block", {})
        result[block_name] = {
            "nesting_mode": nesting,
            "min_items":    block_data.get("min_items", 0),
            "max_items":    block_data.get("max_items", 0),
            "attributes":   _parse_attributes(inner.get("attributes", {})),
            "block_types":  _parse_block_types(inner.get("block_types", {})),
        }
    return result


def _process_schema_dict(
    schema_dict: dict,
    registry_docs: dict,
    kg: dict,
    is_data_source: bool,
) -> tuple[int, int, list[str]]:
    enriched_count = 0
    examples_count = 0
    missing_docs:  list[str] = []

    for resource_name, resource_schema in schema_dict.items():
        graph_key = f"data.{resource_name}" if is_data_source else resource_name

        doc = registry_docs.get(resource_name, {})

        if doc:
            enriched_count += 1
        else:
            missing_docs.append(resource_name)

        block       = resource_schema.get("block", {})
        attributes  = _parse_attributes(block.get("attributes", {}))
        block_types = _parse_block_types(block.get("block_types", {}))

        doc_content = doc.get("content", "")
        for attr_name, attr_data in attributes.items():
            if not attr_data["description"] and doc_content:
                marker = f"* `{attr_name}` -"
                idx    = doc_content.find(marker)
                if idx != -1:
                    end     = doc_content.find("\n", idx)
                    snippet = doc_content[idx + len(marker): end].strip()
                    if snippet:
                        attr_data["description"] = snippet

        examples = doc.get("hcl_examples", [])
        examples_count += len(examples)

        kg[graph_key] = {
            "name":           graph_key,
            "is_data_source": is_data_source,
            "description":    doc.get("description") or "",
            "subcategory":    doc.get("subcategory") or "",
            "attributes":     attributes,
            "block_types":    block_types,
            "examples":       examples,
        }

    return enriched_count, examples_count, missing_docs


def build_knowledge_graph() -> None:
    print("[03] Loading tf_schema_raw.json ...")
    raw_schema = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))

    provider_schemas: dict = raw_schema.get("provider_schemas", {})
    provider_keys = sorted(provider_schemas.keys())
    print(f"[03] Found {len(provider_keys)} provider(s) in schema: {provider_keys}")

    print("[03] Loading tf_registry_docs.json ...")
    registry_docs: dict = json.loads(DOCS_FILE.read_text(encoding="utf-8"))
    print(f"[03] Found {len(registry_docs):,} registry doc entries.")

    kg: dict[str, dict] = {}
    total_resource_schemas = 0
    total_data_source_schemas = 0
    total_enriched = 0
    total_missing: list[str] = []
    total_examples = 0

    for provider_key in provider_keys:
        provider_block = provider_schemas.get(provider_key, {})
        resource_schemas:    dict = provider_block.get("resource_schemas", {})
        data_source_schemas: dict = provider_block.get("data_source_schemas", {})
        print(f"\n[03] --- Provider: {provider_key} ---")
        print(f"[03] Found {len(resource_schemas):,} managed resource types in schema.")
        print(f"[03] Found {len(data_source_schemas):,} data source types in schema.")

        total_resource_schemas    += len(resource_schemas)
        total_data_source_schemas += len(data_source_schemas)

        r_enriched, r_examples, r_missing = _process_schema_dict(
            resource_schemas, registry_docs, kg, is_data_source=False
        )

        d_enriched, d_examples, d_missing = _process_schema_dict(
            data_source_schemas, registry_docs, kg, is_data_source=True
        )

        total_enriched += r_enriched + d_enriched
        total_missing  += r_missing + d_missing
        total_examples += r_examples + d_examples

    OUTPUT_FILE.write_text(json.dumps(kg, indent=2), encoding="utf-8")

    print(f"\n[03] Knowledge Graph built (across {len(provider_keys)} provider(s)):")
    print(f"     Total managed resources    : {total_resource_schemas:,}")
    print(f"     Total data sources         : {total_data_source_schemas:,}")
    print(f"     Total KG nodes             : {len(kg):,}")
    print(f"     Total with Registry docs   : {total_enriched:,}")
    print(f"     Total schema-only (no docs): {len(total_missing):,}")
    print(f"     Total HCL examples         : {total_examples:,}")
    print(f"     Saved to                   : {OUTPUT_FILE}")

    all_resource_keys: set[str] = set()
    all_data_keys: set[str] = set()
    for provider_key in provider_keys:
        provider_block = provider_schemas.get(provider_key, {})
        all_resource_keys |= set(provider_block.get("resource_schemas", {}).keys())
        all_data_keys     |= {f"data.{n}" for n in provider_block.get("data_source_schemas", {}).keys()}
    overlap = all_resource_keys & all_data_keys
    if overlap:
        print(f"\n[03] WARNING: unexpected key overlap ({len(overlap)}): {sorted(overlap)[:5]}")
    else:
        print("\n[03] Collision check passed — no managed resource keys overlap with data. keys.")

    if total_missing:
        print(f"\n[03] Nodes with no Registry doc ({len(total_missing)}):")
        for r in total_missing[:20]:
            print(f"       - {r}")
        if len(total_missing) > 20:
            print(f"       ... and {len(total_missing) - 20} more.")

    docker_present = "docker_container" in kg and "docker_image" in kg
    print(f"\n[03] Sanity check docker_container & docker_image present in KG: {docker_present}")


if __name__ == "__main__":
    build_knowledge_graph()
