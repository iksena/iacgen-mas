from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import httpx


PROVIDERS = [
    {"namespace": "hashicorp",  "name": "aws",    "version": "6.47.0", "resource_prefix": "aws_"},
    {"namespace": "kreuzwerker", "name": "docker", "version": "4.5.0",  "resource_prefix": "docker_"},
]
OUTPUT_FILE        = Path("tf_registry_docs.json")

CATEGORIES = ["resources", "data-sources"]

_BASE      = "https://registry.terraform.io"
_PAGE_SIZE = 100
_SLEEP     = 0.2
_WORKERS   = 10
_TIMEOUT   = 30

_HCL_FENCES = {"terraform", "hcl"}


def _resolve_version_id(client: httpx.Client, provider: dict) -> str:
    namespace, name, version = provider["namespace"], provider["name"], provider["version"]
    url = f"{_BASE}/v2/providers/{namespace}/{name}?include=provider-versions"
    r = client.get(url)
    r.raise_for_status()
    for item in r.json().get("included", []):
        if item.get("attributes", {}).get("version") == version:
            ver_id = str(item["id"])
            print(f"[02] Resolved {namespace}/{name}@{version} → version ID {ver_id}")
            return ver_id
    raise RuntimeError(f"Version {version} not found in Registry response for {namespace}/{name}.")


def _fetch_doc_stubs(
    client: httpx.Client,
    version_id: str,
    category: str,
) -> list[dict]:
    stubs: list[dict] = []
    page = 0

    while True:
        page += 1
        print(f"[02] [{category}] List page {page} … ", end="", flush=True)

        r = client.get(
            f"{_BASE}/v2/provider-docs",
            params={
                "filter[provider-version]": version_id,
                "filter[category]":        category,
                "filter[language]":        "hcl",
                "page[size]":              _PAGE_SIZE,
                "page[number]":            page,
            },
        )
        r.raise_for_status()
        items = r.json().get("data", [])

        for item in items:
            attrs = item["attributes"]
            stubs.append({
                "id":             item["id"],
                "slug":           attrs.get("slug", ""),
                "title":          attrs.get("title", ""),
                "subcategory":    attrs.get("subcategory") or "",
                "path":           attrs.get("path", ""),
                "is_data_source": category == "data-sources",
            })

        print(f"{len(items)} stubs (total this category: {len(stubs)})")

        if len(items) < _PAGE_SIZE:
            break

        time.sleep(_SLEEP)

    return stubs


def _fetch_one(doc_id: str) -> str:
    url = f"{_BASE}/v2/provider-docs/{doc_id}"
    with httpx.Client(follow_redirects=True, timeout=_TIMEOUT) as c:
        r = c.get(url, headers={"Accept": "application/json"})
        r.raise_for_status()
        return r.json()["data"]["attributes"].get("content", "")


def _fetch_all_contents(stubs: list[dict]) -> dict[str, str]:
    results: dict[str, str] = {}
    total = len(stubs)
    done  = 0

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        futures = {pool.submit(_fetch_one, s["id"]): s for s in stubs}
        for future in as_completed(futures):
            stub = futures[future]
            try:
                results[stub["id"]] = future.result()
            except Exception as exc:
                print(f"\n[02] WARNING: failed doc {stub['id']} ({stub['slug']}): {exc}")
                results[stub["id"]] = ""
            done += 1
            if done % 100 == 0 or done == total:
                print(f"[02] Content fetched: {done}/{total}", flush=True)

    return results


def _slug_to_tf_name(slug: str, resource_prefix: str) -> str:
    return slug if slug.startswith(resource_prefix) else f"{resource_prefix}{slug}"


def extract_hcl_examples(markdown: str) -> list[str]:
    examples: list[str] = []
    in_block = False
    current:  list[str] = []

    for line in markdown.splitlines():
        stripped = line.strip()
        if not in_block:
            if stripped.startswith("```"):
                lang = stripped[3:].strip().lower()
                if lang in _HCL_FENCES:
                    in_block = True
                    current  = []
        else:
            if stripped == "```":
                in_block = False
                block    = "\n".join(current).strip()
                if block:
                    examples.append(block)
            else:
                current.append(line)

    return examples


if __name__ == "__main__":
    all_stubs: list[dict] = []
    with httpx.Client(follow_redirects=True, timeout=_TIMEOUT) as client:
        for provider in PROVIDERS:
            print(f"\n[02] ##### Provider: {provider['namespace']}/{provider['name']}@{provider['version']} #####")
            version_id = _resolve_version_id(client, provider)

            for category in CATEGORIES:
                print(f"\n[02] === Fetching category: {category} ===")
                category_stubs = _fetch_doc_stubs(client, version_id, category)
                for stub in category_stubs:
                    stub["resource_prefix"] = provider["resource_prefix"]
                all_stubs.extend(category_stubs)
                print(f"[02] {len(category_stubs)} stubs collected for '{category}'")

    print(f"\n[02] {len(all_stubs)} total stubs collected across {len(PROVIDERS)} provider(s). "
          f"Fetching full content …\n")
    contents = _fetch_all_contents(all_stubs)

    docs: dict[str, dict] = {}
    for stub in all_stubs:
        tf_name = _slug_to_tf_name(stub["slug"], stub["resource_prefix"])
        content = contents.get(stub["id"], "")
        docs[tf_name] = {
            "title":          stub["title"],
            "subcategory":    stub["subcategory"],
            "is_data_source": stub["is_data_source"],
            "content":        content,
            "hcl_examples":   extract_hcl_examples(content),
        }

    OUTPUT_FILE.write_text(json.dumps(docs, indent=2), encoding="utf-8")

    resource_count     = sum(1 for d in docs.values() if not d["is_data_source"])
    data_source_count  = sum(1 for d in docs.values() if d["is_data_source"])
    print(f"\n[02] Saved {len(docs)} total docs → {OUTPUT_FILE}")
    print(f"     Managed resources : {resource_count}")
    print(f"     Data sources      : {data_source_count}")

    s3 = docs.get("aws_s3_bucket", {})
    print(f"[02] Sanity aws_s3_bucket   : {len(s3.get('hcl_examples', []))} HCL examples, "
          f"{len(s3.get('content', ''))} content chars")
    ebs = docs.get("aws_elastic_beanstalk_solution_stack", {})
    print(f"[02] Sanity aws_elastic_beanstalk_solution_stack: "
          f"is_data_source={ebs.get('is_data_source')}, "
          f"{len(ebs.get('hcl_examples', []))} HCL examples")

    docker_container = docs.get("docker_container", {})
    print(f"[02] Sanity docker_container: present={'docker_container' in docs}, "
          f"{len(docker_container.get('hcl_examples', []))} HCL examples")
    docker_image = docs.get("docker_image", {})
    print(f"[02] Sanity docker_image    : present={'docker_image' in docs}, "
          f"{len(docker_image.get('hcl_examples', []))} HCL examples")
