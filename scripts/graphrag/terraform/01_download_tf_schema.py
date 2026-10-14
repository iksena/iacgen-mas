from __future__ import annotations

import io, json, os, platform, shutil, stat, subprocess, sys, tempfile, zipfile
from pathlib import Path

import httpx

PROVIDERS = [
    {
        "source":  "hashicorp/aws",
        "version": "6.47.0",
        "local_name": "aws",
        "provider_block": """
provider "aws" {
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
  access_key                  = "mock"
  secret_key                  = "mock"
}
""",
    },
    {
        "source":  "kreuzwerker/docker",
        "version": "4.5.0",
        "local_name": "docker",
        "provider_block": """
provider "docker" {
}
""",
    },
]

PROVIDER_KEYS = [
    f"registry.terraform.io/{p['source']}" for p in PROVIDERS
]
_AWS_PROVIDER_KEY = "registry.terraform.io/hashicorp/aws"
TERRAFORM_VERSION  = "1.15.5"
OUTPUT_FILE        = "tf_schema_raw.json"


def _build_main_tf() -> str:
    required_providers_lines = "\n".join(
        f'    {p["local_name"]} = {{ source = "{p["source"]}", version = "{p["version"]}" }}'
        for p in PROVIDERS
    )
    provider_blocks = "\n".join(p["provider_block"] for p in PROVIDERS)
    return f"""
terraform {{
  required_providers {{
{required_providers_lines}
  }}
}}
{provider_blocks}
"""


def _run_terraform_schema(tf_bin: str) -> dict | None:
    main_tf = _build_main_tf()
    with tempfile.TemporaryDirectory() as tmp:
        tf_file = Path(tmp) / "main.tf"
        tf_file.write_text(main_tf)

        print(f"[01] Running terraform init ({len(PROVIDERS)} provider(s)) ...")
        init = subprocess.run(
            [tf_bin, "init", "-no-color"],
            cwd=tmp, capture_output=True, text=True, timeout=300
        )
        if init.returncode != 0:
            print(f"[01] terraform init failed:\n{init.stderr[-1000:]}")
            return None

        print("[01] Running terraform providers schema -json ...")
        schema_proc = subprocess.run(
            [tf_bin, "providers", "schema", "-json", "-no-color"],
            cwd=tmp, capture_output=True, text=True, timeout=120
        )
        if schema_proc.returncode != 0:
            print(f"[01] terraform providers schema failed:\n{schema_proc.stderr[-500:]}")
            return None

        schema = json.loads(schema_proc.stdout)
        provider_schemas = schema.get("provider_schemas", {})
        total = 0
        for key in PROVIDER_KEYS:
            n = len(provider_schemas.get(key, {}).get("resource_schemas", {}))
            total += n
            print(f"[01] terraform CLI: {key} → {n:,} resources")
        if total == 0:
            print("[01] terraform CLI returned 0 resources across all providers")
            return None
        return schema


def _install_terraform() -> str | None:
    os_name = {"Linux": "linux", "Darwin": "darwin", "Windows": "windows"}.get(
        platform.system(), "linux"
    )
    machine = platform.machine().lower()
    arch = "amd64" if machine in ("x86_64", "amd64") else \
           "arm64"  if machine in ("aarch64", "arm64") else "amd64"

    url = (
        f"https://releases.hashicorp.com/terraform/{TERRAFORM_VERSION}/"
        f"terraform_{TERRAFORM_VERSION}_{os_name}_{arch}.zip"
    )
    print(f"[01] Downloading terraform {TERRAFORM_VERSION} binary ...")
    print(f"     {url}")

    try:
        with httpx.Client(follow_redirects=True, timeout=300) as client:
            r = client.get(url)
            r.raise_for_status()
    except Exception as exc:
        print(f"[01] Failed to download terraform binary: {exc}")
        return None

    tf_dir = Path(tempfile.mkdtemp(prefix="tf_bin_"))
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        for member in zf.namelist():
            if "terraform" in member.lower() and not member.endswith("/"):
                zf.extract(member, tf_dir)
                tf_path = tf_dir / member
                tf_path.chmod(tf_path.stat().st_mode | stat.S_IEXEC)
                print(f"[01] terraform binary installed at {tf_path}")
                return str(tf_path)
    return None


if __name__ == "__main__":
    schema = None

    tf_on_path = shutil.which("terraform") or shutil.which("tofu")
    if tf_on_path:
        print(f"[01] Found terraform at {tf_on_path}")
        schema = _run_terraform_schema(tf_on_path)

    if schema is None:
        tf_bin = _install_terraform()
        if tf_bin:
            schema = _run_terraform_schema(tf_bin)

    if schema is None:
        print("[01] WARNING: falling back to Go source parsing (attribute nesting may be imprecise)")
        schema = _fallback_zip_schema()

    provider_schemas = schema.get("provider_schemas", {})
    total_resources = 0
    for p, key in zip(PROVIDERS, PROVIDER_KEYS):
        n = len(provider_schemas.get(key, {}).get("resource_schemas", {}))
        total_resources += n
        status = "✓" if n > 0 else "✗ MISSING"
        print(f"[01] {key} ({p['source']}): {n:,} resource types {status}")

    if total_resources == 0:
        print("[01] ERROR: 0 resources extracted across all configured providers.", file=sys.stderr)
        sys.exit(1)

    missing = [p["source"] for p, key in zip(PROVIDERS, PROVIDER_KEYS)
               if not provider_schemas.get(key, {}).get("resource_schemas")]
    if missing:
        print(f"[01] WARNING: no resources extracted for: {missing} "
              f"(schema saved anyway with whatever providers succeeded)")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)

    print(f"[01] Saved {total_resources:,} total resource types across "
          f"{len(PROVIDERS)} provider(s) to {OUTPUT_FILE}.")

    aws_resources = provider_schemas.get(_AWS_PROVIDER_KEY, {}).get("resource_schemas", {})
    probe = aws_resources.get("aws_s3_bucket", {})
    req_attrs = [
        k for k, v in probe.get("block", {}).get("attributes", {}).items()
        if v.get("required")
    ]
    print(f"[01] Sanity check aws_s3_bucket required attrs: {req_attrs}")

    docker_resources = provider_schemas.get(
        "registry.terraform.io/kreuzwerker/docker", {}
    ).get("resource_schemas", {})
    print(f"[01] Sanity check docker_container present: {'docker_container' in docker_resources}")
    print(f"[01] Sanity check docker_image present    : {'docker_image' in docker_resources}")
