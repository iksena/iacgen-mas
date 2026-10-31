from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

from baselines.opencode_driver import AGENT_NAME, REPO_ROOT, OpenCodeDriver, config_path_for

AGENT_TEST_STACK_PREFIX = "iac-god-eval-agent-"

_AGENT_BASH_RULES = {
    "*": "allow",
    "sudo *": "deny",
    "aws configure*": "deny",
    "aws iam create-user*": "deny",
    "aws iam create-access-key*": "deny",
    "aws iam create-login-profile*": "deny",
    "aws iam attach-user-policy*": "deny",
    "aws iam put-user-policy*": "deny",
    "aws organizations *": "deny",
    "aws account *": "deny",
    "aws sts assume-role*": "deny",
    "curl *": "deny",
    "wget *": "deny",
    "git clone*": "deny",
    "gh *": "deny",
}

_AGENT_ENV_KEEP = {
    "PATH", "LANG", "LANGUAGE", "TERM", "TMPDIR", "SHELL", "USER", "LOGNAME", "TZ",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS",
    "XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "OPENCODE_CONFIG",
}
_AGENT_ENV_KEEP |= {
    "AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_REGION", "AWS_DEFAULT_REGION",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE", "AWS_CA_BUNDLE",
    "AWS_STS_REGIONAL_ENDPOINTS", "AWS_PAGER",
}
_AGENT_ENV_KEEP_PREFIXES = ("LC_",)

def _agent_scoring(iac_type: str) -> str:
    if iac_type == "terraform":
        return (
            "## How your result is scored\n\n"
            "After you stop, `main.tf` is validated and deployed independently, once. All of\n"
            "these must pass:\n\n"
            "1. TFLint: no ERROR-severity findings (warnings are ignored).\n"
            "2. `terraform validate`: no errors.\n"
            "3. Trivy misconfiguration scan: no HIGH or CRITICAL findings (MEDIUM and LOW are\n"
            "   ignored). Findings must be fixed in the configuration, not suppressed with\n"
            "   ignore comments.\n"
            "4. Deployment: `terraform init` and `terraform apply` run in a fresh directory\n"
            "   with no variable values supplied, so every variable needs a default. The\n"
            "   apply must succeed and create at least one resource.\n\n"
        )
    return (
        "## How your result is scored\n\n"
        "After you stop, `template.yaml` is validated and deployed independently, once. All\n"
        "of these must pass:\n\n"
        "1. YAML: no yamllint errors (default rules, except that line length, document\n"
        "   start and trailing spaces are not checked; indentation must be consistent).\n"
        "2. cfn-lint: no ERROR-severity findings (warnings are ignored).\n"
        "3. Trivy misconfiguration scan: no HIGH or CRITICAL findings (MEDIUM and LOW are\n"
        "   ignored). Findings must be fixed in the template, not suppressed with ignore\n"
        "   comments.\n"
        "4. Deployment: the template is created as a new stack with only CAPABILITY_IAM and\n"
        "   CAPABILITY_NAMED_IAM granted and no parameter values supplied, so every\n"
        "   Parameter needs a Default, and Transforms or macros that need other\n"
        "   capabilities cannot be used. The stack must reach CREATE_COMPLETE.\n\n"
    )


def _agent_workflow(iac_type: str) -> str:
    fname = "main.tf" if iac_type == "terraform" else "template.yaml"
    if iac_type == "terraform":
        test = (
            "   Test a real deployment in the current directory too, and ALWAYS destroy what\n"
            "   you applied afterwards, whether the apply succeeded or not. The AWS provider\n"
            "   picks up the region and credentials from the environment, so no provider\n"
            "   block is needed.\n"
        )
    else:
        test = (
            "   Test a real deployment too. Name every CloudFormation stack you create\n"
            f"   starting with `{AGENT_TEST_STACK_PREFIX}`, tag it `ManagedBy=iac-god-eval`, and\n"
            "   ALWAYS delete it afterwards, whether the deployment succeeded or not.\n"
        )
    return (
        "## Workflow\n\n"
        f"1. Write the complete configuration to `{fname}` in the current working\n"
        "   directory. Write raw code only, no markdown fences or prose.\n"
        "2. Test and repair it yourself. You have a shell, and the AWS CLI in it is\n"
        "   already logged in to a dedicated, empty test account (region is set in the\n"
        "   environment). Use whatever is available in the shell to check your work.\n"
        f"{test}"
        f"3. Fix whatever fails in `{fname}` and test again. Never suppress, comment\n"
        "   out or work around a check, and never delete a resource just to make a\n"
        "   failure go away.\n"
        f"4. When you are confident `{fname}` is correct and deploys, stop. Leave the\n"
        "   final version in that file and make sure nothing you deployed is still\n"
        "   running.\n\n"
        f"{_agent_scoring(iac_type)}"
        "Rules for the AWS account: only create resources through your own test\n"
        "deployments of this configuration, and delete them when you are done. Do not\n"
        "modify or delete anything else in the account, do not create IAM users or\n"
        "access keys, and do not change the CLI's configuration.\n\n"
    )


def agent_system_prompt(base_prompt: str, iac_type: str) -> str:
    start = base_prompt.find("## Workflow")
    if start == -1:
        raise ValueError("base prompt has no '## Workflow' section to replace")
    end = base_prompt.find("\n## ", start + 1)
    end = len(base_prompt) if end == -1 else end + 1
    return base_prompt[:start] + _agent_workflow(iac_type) + base_prompt[end:]

def bwrap_available() -> bool:
    if shutil.which("bwrap") is None:
        return False
    probe = subprocess.run(
        ["bwrap", "--dev-bind", "/", "/", "--", "true"], capture_output=True, text=True
    )
    return probe.returncode == 0

def bwrap_prefix(hide: list[Path], workdir: Path) -> list[str]:
    args = ["bwrap", "--dev-bind", "/", "/"]
    for h in hide:
        args += ["--tmpfs", str(h)]
    args += ["--chdir", str(workdir), "--die-with-parent", "--"]
    return args

DEFAULT_AGENT_IMAGE = "iacgod-agent:latest"

_DOCKER_ENV_SKIP = {"PATH", "SHELL", "USER", "LOGNAME", "TMPDIR",
                    "AWS_SHARED_CREDENTIALS_FILE", "AWS_CONFIG_FILE"}

def docker_available(image: str) -> bool:
    if shutil.which("docker") is None:
        return False
    probe = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True)
    return probe.returncode == 0

def container_name(run_id: str) -> str:
    return f"iacgod-agent-{run_id}"

def docker_prefix(*, image: str, run_dir: Path, workdir: Path, env_names: list[str],
                  run_id: str, aws_dir: Path | None) -> list[str]:
    args = [
        "docker", "run", "--rm", "--init",
        "--name", container_name(run_id),
        "--user", f"{os.getuid()}:{os.getgid()}",
        "-v", f"{run_dir}:{run_dir}",
        "-w", str(workdir),
        "--tmpfs", "/tmp",
    ]
    if aws_dir is not None:
        args += ["-v", f"{aws_dir}:{run_dir / 'home' / '.aws'}:ro"]
    args += ["-e", f"HOME={run_dir / 'home'}"]
    for name in env_names:
        args += ["-e", name]
    return args + [image]

class OpenCodeAgentDriver(OpenCodeDriver):

    name = "opencode_agent"
    external_workspace = True
    aws_cli_access = True

    def _write_config(self, *, scenario, config, system_prompt_path, state_dir) -> None:
        super()._write_config(
            scenario=scenario, config=config,
            system_prompt_path=system_prompt_path, state_dir=state_dir,
        )
        path = config_path_for(state_dir)
        cfg = json.loads(path.read_text(encoding="utf-8"))
        cfg.pop("mcp", None)
        cfg["agent"][AGENT_NAME]["description"] = "IaCGen-MAS coding-agent baseline"
        cfg["agent"][AGENT_NAME]["permission"] = {
            "*": "deny",
            "read": "allow",
            "write": "allow",
            "edit": "allow",
            "bash": dict(_AGENT_BASH_RULES),
            "glob": "deny",
            "grep": "deny",
            "list": "deny",
            "external_directory": {"*": "deny"},
        }
        path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    def build_command(self, *, config, scenario, prompt, workdir, system_prompt, state_dir):
        cmd = super().build_command(
            config=config, scenario=scenario, prompt=prompt, workdir=workdir,
            system_prompt=agent_system_prompt(system_prompt, config.iac_type),
            state_dir=state_dir,
        )
        isolation = getattr(config, "agent_isolation", "none")
        if isolation == "docker":
            run_dir = state_dir.parent.resolve()
            agent_env = self._agent_env(config, state_dir)
            env_names = sorted(k for k in agent_env if k not in _DOCKER_ENV_SKIP and k != "HOME")
            aws_dir = Path(os.path.expanduser("~/.aws"))
            return docker_prefix(
                image=getattr(config, "agent_image", DEFAULT_AGENT_IMAGE), run_dir=run_dir,
                workdir=workdir.resolve(), env_names=env_names, run_id=scenario.run_id,
                aws_dir=aws_dir if aws_dir.is_dir() else None,
            ) + cmd
        if isolation != "bwrap":
            return cmd
        hide = [Path(h).resolve() for h in config.agent_hide_paths]
        sandbox = state_dir.parent.resolve()
        for h in hide:
            if sandbox.is_relative_to(h):
                raise RuntimeError(f"agent sandbox {sandbox} is inside hidden path {h}")
        return bwrap_prefix(hide, workdir) + cmd

    def after_run(self, config, scenario) -> None:
        if getattr(config, "agent_isolation", "none") == "docker":
            subprocess.run(["docker", "rm", "-f", container_name(scenario.run_id)],
                           capture_output=True, text=True)

    def build_env(self, config, state_dir: Path) -> dict[str, str]:
        agent_env = self._agent_env(config, state_dir)
        if getattr(config, "agent_isolation", "none") != "docker":
            return agent_env
        client = dict(os.environ)
        client.update({k: v for k, v in agent_env.items() if k != "HOME"})
        return client

    def _agent_env(self, config, state_dir: Path) -> dict[str, str]:
        full = super().build_env(config, state_dir)
        env = {
            k: v for k, v in full.items()
            if k in _AGENT_ENV_KEEP or k.startswith(_AGENT_ENV_KEEP_PREFIXES)
        }
        env[config.api_key_env] = full[config.api_key_env]

        real_home = Path(os.path.expanduser("~"))
        repo = REPO_ROOT.resolve()
        env["PATH"] = os.pathsep.join(
            p for p in full.get("PATH", "").split(os.pathsep)
            if p and not Path(p).resolve().is_relative_to(repo)
        )
        env.setdefault("AWS_SHARED_CREDENTIALS_FILE", str(real_home / ".aws" / "credentials"))
        env.setdefault("AWS_CONFIG_FILE", str(real_home / ".aws" / "config"))
        region = full.get("AWS_DEFAULT_REGION") or full.get("AWS_REGION") or "us-east-1"
        env.setdefault("AWS_DEFAULT_REGION", region)
        env.setdefault("AWS_REGION", region)
        env.setdefault("AWS_PAGER", "")

        home = state_dir.parent / "home"
        home.mkdir(parents=True, exist_ok=True)
        env["HOME"] = str(home)
        return env
