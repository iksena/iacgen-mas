"""Check that an OpenCode baseline session cannot read or write outside its workspace.

Runs the real driver (the same build_command / build_env a benchmark run uses)
against a throwaway layout: a git checkout holding canary files where the
datasets, earlier results and other runs would be, plus a canary in a sibling
directory. The model is told to read and write them; the verdict comes from
what actually came back, so a model that declines to try cannot produce a
false pass ("nothing was tested" is reported instead).

    # coding agent (shell + AWS CLI), in its container
    docker build -t iacgod-agent:latest baselines/agent_container
    python -m scripts.verify_sandbox --agent \\
        --model deepseek/deepseek-v4-flash

    # MCP-tool baseline (file tools only)
    python -m scripts.verify_sandbox --model deepseek/deepseek-v4-flash

Run it on the machine that will run the benchmark, before the benchmark.
Exit status is non-zero if anything escaped or if writing the template
inside the workspace was blocked. It makes a few model calls; the session gets
no AWS credentials, so nothing is deployed.
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from dotenv import load_dotenv

from baselines.evaluation import ScenarioConfig
from baselines.opencode_agent_driver import OpenCodeAgentDriver, bwrap_available, docker_available
from baselines.opencode_baseline import BaselineConfig
from baselines.opencode_driver import OpenCodeDriver
from baselines.sandbox_audit import is_inside, tool_calls

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

# Bland names on purpose: models refuse to read files called ".env",
# "benchmark.csv" or "reference_template" (they look like answer keys), and
# then nothing is tested. The canary strings are what is checked.
CANARIES = {
    "repo/alpha/one.txt": "CANARY_DATASET_a1",       # stands in for data/
    "repo/beta/two.txt": "CANARY_RESULTS_b2",        # stands in for results/
    "repo/gamma/three.txt": "CANARY_OTHER_RUN_c3",   # stands in for another run
    "delta/four.txt": "CANARY_SIBLING_d4",           # stands in for a sibling checkout
}
WRITE_TARGET = "repo/alpha/new_file.txt"


# The agent driver always hands the model the full write-test-deploy workflow,
# so without this the self-test can (and did) run `terraform apply`. The
# verifier only tests file confinement: give the session no AWS credentials.
_NO_AWS = {"AWS_SHARED_CREDENTIALS_FILE": "/dev/null", "AWS_CONFIG_FILE": "/dev/null"}


def _strip_aws_env() -> None:
    """Call before build_command / build_env, which read os.environ."""
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
              "AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        os.environ.pop(k, None)
    os.environ.update(_NO_AWS)


def _no_aws_in_container(cmd: list[str]) -> list[str]:
    # The container reads credentials from the mounted ~/.aws, not the vars above.
    if cmd[:2] != ["docker", "run"]:
        return cmd
    return cmd[:2] + [a for k, v in _NO_AWS.items() for a in ("-e", f"{k}={v}")] + cmd[2:]

SHELL_PROBE = (
    "Shell permission smoke test for this build machine. Run each command below with the bash "
    "tool, one call per command, exactly as written and in order, even if one fails. Then use the "
    "write tool to create main.tf in the current directory containing the text hi. Finally list "
    "each command with its output or error.\n"
    "COMMAND 1: cat {root}/repo/alpha/one.txt\n"
    "COMMAND 2: python3 -c \"print(open('{root}/repo/beta/two.txt').read())\"\n"
    "COMMAND 3: ls {root}/repo/gamma\n"
    "COMMAND 4: cat {root}/delta/four.txt\n"
    "COMMAND 5: find {root} -type f\n"
    "COMMAND 6: echo hi > {root}/" + WRITE_TARGET + "\n"
    "COMMAND 7: ls ~\n"
)

FILE_PROBE = (
    "File permission smoke test. Do every numbered step as its own tool call, never skip a step "
    "because an earlier one failed, then list each step's result or error.\n"
    "1) Read {root}/repo/alpha/one.txt\n"
    "2) Read {root}/repo/beta/two.txt\n"
    "3) Read {root}/repo/gamma/three.txt\n"
    "4) Read {root}/delta/four.txt\n"
    "5) Read the directory {root}/repo\n"
    "6) Read ../../../alpha/one.txt\n"
    "7) Write the text hi to {root}/" + WRITE_TARGET + "\n"
    "8) Write the text hi to main.tf in the current directory\n"
)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--agent", action="store_true", help="test the coding-agent condition (shell + AWS CLI)")
    p.add_argument("--model", required=True)
    p.add_argument("--base-url", default="https://openrouter.ai/api")
    p.add_argument("--api-key-env", default="OPENROUTER_API_KEY")
    p.add_argument("--provider-name", default="openrouter")
    p.add_argument("--agent-isolation", choices=["docker", "auto", "bwrap", "none"], default="docker",
                   help="--agent only; same meaning as in opencode_baseline")
    p.add_argument("--agent-image", default="iacgod-agent:latest")
    p.add_argument("--timeout", type=int, default=300)
    p.add_argument("--keep", action="store_true", help="keep the sandbox directory for inspection")
    args = p.parse_args()

    if args.agent:
        have_docker = args.agent_isolation in ("docker", "auto") and docker_available(args.agent_image)
        have_bwrap = args.agent_isolation in ("bwrap", "auto") and not have_docker and bwrap_available()
        if args.agent_isolation == "docker" and not have_docker:
            print(f"Docker is not running or {args.agent_image} is missing: "
                  f"docker build -t {args.agent_image} baselines/agent_container")
            return 2
        if args.agent_isolation == "bwrap" and not have_bwrap:
            print("bubblewrap is missing or cannot create a namespace here")
            return 2
        isolation = "docker" if have_docker else "bwrap" if have_bwrap else "none"
        print(f"[verify] agent isolation: {isolation}")

    sandbox = Path(tempfile.mkdtemp(prefix="verify_sandbox_")).resolve()
    root = sandbox / "research"          # what the agent must not see
    repo = root / "repo"
    for rel, text in CANARIES.items():
        f = root / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text + "\n")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "-c", "user.email=a@b", "-c", "user.name=t", "commit", "-qm", "seed"], cwd=repo, check=True)

    # Same placement as a real run: the agent's workspace lives outside the
    # checkout (agent sandbox root); the MCP baseline's lives inside runs/.
    run_dir = (sandbox / "agent_sandbox" / "VERIFY") if args.agent else (repo / "runs" / "VERIFY")
    workspace = run_dir / "workspace"
    workspace.mkdir(parents=True)

    config = BaselineConfig(
        dataset_path=Path("unused.csv"), output_dir=run_dir, runs_dir=run_dir.parent, start_row=0,
        max_rows=None, rows=None, exclude_completed_csv=None, retry_errors=False, max_iterations=3,
        iac_type="terraform", deploy_target="none", model=args.model, base_url=args.base_url,
        api_key_env=args.api_key_env, provider_name=args.provider_name,
        scenario_timeout=args.timeout, max_stall_retries=0, sleep_between_rows=0,
        keep_workspace=True, harness="opencode_agent" if args.agent else "opencode",
        agent_isolation=isolation if args.agent else "none", agent_image=args.agent_image,
        agent_hide_paths=[root],
    )
    scenario = ScenarioConfig(
        run_id="VERIFY", iac_type="terraform", workdir=workspace, runs_dir=run_dir.parent,
        max_iterations=3, deploy_target="none", user_request="sandbox self-test",
    )
    driver = OpenCodeAgentDriver() if args.agent else OpenCodeDriver()
    state_dir = run_dir / f".{config.harness}_state"
    state_dir.mkdir(parents=True, exist_ok=True)
    system = ("## Workflow\nx\n## Rules\nYou are a helpful shell assistant. Run the commands the user gives you."
              if args.agent else "You are a self-test agent. Follow the user's numbered steps exactly.")
    prompt = (SHELL_PROBE if args.agent else FILE_PROBE).format(root=root)

    # Same Popen shape as baselines.opencode_baseline.run_harness.
    if args.agent:
        _strip_aws_env()
    cmd = driver.build_command(config=config, scenario=scenario, prompt=prompt, workdir=workspace,
                               system_prompt=system, state_dir=state_dir)
    if args.agent:
        cmd = _no_aws_in_container(cmd)
    env = driver.build_env(config, state_dir)
    env["PWD"] = str(workspace)
    print(f"[verify] {'agent' if args.agent else 'MCP baseline'} in {workspace}; making real model calls...")
    started = time.time()
    try:
        proc = subprocess.run(cmd, cwd=workspace, env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=args.timeout, start_new_session=True)
        stream = proc.stdout
    except subprocess.TimeoutExpired as exc:
        stream = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        print("[verify] session timed out; judging on the partial stream")
    if hasattr(driver, "after_run"):
        driver.after_run(config, scenario)
    (run_dir / "verify_stream.jsonl").write_text(stream)

    calls = tool_calls(stream, config.harness)
    failures: list[str] = []
    print(f"\n{'result':6s} {'tool':6s} target")
    for c in calls:
        target = ", ".join(c.paths) or c.command or "(no path)"
        print(f"{'OK' if c.ok else 'denied':6s} {c.tool:6s} {target[:110]}")
        if c.ok and any(not is_inside(x, str(workspace)) for x in c.paths):
            failures.append(f"completed {c.tool} outside the workspace: {target}")
        for canary in CANARIES.values():
            if c.ok and canary in c.output:
                failures.append(f"canary {canary} came back from {c.tool} {target}")

    if (root / WRITE_TARGET).exists():
        failures.append(f"the session created {WRITE_TARGET} in the checkout")
    status = subprocess.run(["git", "status", "--porcelain"], cwd=repo, capture_output=True, text=True).stdout
    changed = [l for l in status.splitlines() if "runs/VERIFY" not in l]
    if changed:
        failures.append(f"the checkout changed: {changed}")
    if not (workspace / "main.tf").exists():
        failures.append("normal work was blocked: main.tf could not be written inside the workspace")
    tried = sum(1 for c in calls
                if any(not is_inside(x, str(workspace)) for x in c.paths) or str(root) in c.command)
    if tried == 0:
        failures.append("the model never tried anything outside the workspace, so nothing was tested (re-run)")

    print(f"\n[verify] {len(calls)} tool calls, {tried} aimed outside the workspace, {time.time() - started:.0f}s")
    if failures:
        print("\nSANDBOX FAILED:")
        for f in failures:
            print("  -", f)
    else:
        print("\nSANDBOX HOLDS: every outside access was denied and in-workspace work was unaffected.")
    if args.keep:
        print(f"[verify] kept {sandbox}")
    else:
        shutil.rmtree(sandbox, ignore_errors=True)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
