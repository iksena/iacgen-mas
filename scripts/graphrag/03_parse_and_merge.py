import os
import json
from bs4 import BeautifulSoup

SPEC_FILE      = "cfn_resource_spec.json"
HTML_DIR       = "scraped_html"
OUTPUT_KG_FILE = "cfn_knowledge_graph.json"


def parse_html_for_resource(html_path: str, resource_name: str) -> dict:
    with open(html_path, "r", encoding="utf-8") as f:
        soup = BeautifulSoup(f.read(), "html.parser")

    result = {"description": "", "property_descriptions": {}, "examples": []}

    main_body = soup.find("div", id="main-col-body")
    if main_body:
        paras = main_body.find_all("p", recursive=False)
        result["description"] = " ".join(p.get_text(strip=True) for p in paras[:3])

    prefix = "cfn-" + resource_name.lower().replace("::", "-") + "-"
    for dt in soup.find_all("dt"):
        anchor = dt.get("id", "")
        if not anchor.startswith(prefix):
            continue
        raw_prop = anchor[len(prefix):]
        dd = dt.find_next_sibling("dd")
        if dd:
            desc = " ".join(p.get_text(strip=True) for p in dd.find_all("p")[:2])
            if desc:
                result["property_descriptions"][raw_prop.lower()] = desc

    for block in soup.find_all("code"):
        text = block.get_text()
        if "Type: AWS::" in text and "{" not in text:
            result["examples"].append(text.strip())

    return result


def build_knowledge_graph_data():
    print("Loading CloudFormation spec...")
    with open(SPEC_FILE, "r") as f:
        spec = json.load(f)

    html_index: dict[str, str] = {}
    if os.path.isdir(HTML_DIR):
        for fname in os.listdir(HTML_DIR):
            if fname.endswith(".html"):
                rname = fname.replace(".html", "").replace("_", "::").lower()
                html_index[rname] = os.path.join(HTML_DIR, fname)
    print(f"Found {len(html_index)} scraped HTML files in '{HTML_DIR}/'.")

    kg_data: dict = {}
    resource_types = spec.get("ResourceTypes", {})
    scraped_count = 0
    prop_enriched_count = 0

    for resource_name, structure in resource_types.items():
        html_path = html_index.get(resource_name.lower())

        if html_path:
            semantics = parse_html_for_resource(html_path, resource_name)
            scraped_count += 1
        else:
            semantics = {"description": "", "property_descriptions": {}, "examples": []}

        merged_properties: dict = {}
        prop_desc_index = semantics["property_descriptions"]

        for prop_name, prop_data in structure.get("Properties", {}).items():
            enriched = dict(prop_data)
            html_desc = prop_desc_index.get(prop_name.lower(), "")
            if html_desc:
                enriched["Description"] = html_desc
                prop_enriched_count += 1
            merged_properties[prop_name] = enriched

        kg_data[resource_name] = {
            "name":        resource_name,
            "description": semantics["description"],
            "properties":  merged_properties,
            "examples":    semantics["examples"],
        }

    with open(OUTPUT_KG_FILE, "w") as f:
        json.dump(kg_data, f, indent=4)

    spec_only = len(kg_data) - scraped_count
    print(f"\nKnowledge Graph built:")
    print(f"  Total resources          : {len(kg_data)}")
    print(f"  With HTML docs           : {scraped_count}")
    print(f"  Spec-only (no HTML)      : {spec_only}")
    print(f"  Properties with HTML desc: {prop_enriched_count}")
    print(f"  Saved to                 : {OUTPUT_KG_FILE}")


if __name__ == "__main__":
    build_knowledge_graph_data()
