import os
from dataclasses import dataclass, field
from enum import Enum
from dotenv import load_dotenv

load_dotenv()


def _parse_csv_env(value: str | None) -> tuple[str, ...]:
    if not value:
        return ()
    parts = [part.strip() for part in value.split(",")]
    return tuple(part for part in parts if part)


def _parse_optional_int(value: str | None) -> int | None:
    if not value or not value.strip():
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


OPENROUTER_QUANTIZATION_ORDER: tuple[str, ...] = (
    "int4",
    "int8",
    "fp4",
    "fp6",
    "fp8",
    "fp16",
    "bf16",
    "fp32",
    "unknown",
)


def quantizations_from_min(min_quantization: str | None) -> tuple[str, ...]:
    if not min_quantization:
        return ()

    q = min_quantization.strip().lower()
    if not q:
        return ()

    if q not in OPENROUTER_QUANTIZATION_ORDER:
        supported = ", ".join(OPENROUTER_QUANTIZATION_ORDER)
        raise ValueError(
            f"Unsupported min quantization '{q}'. Supported values: {supported}"
        )

    start = OPENROUTER_QUANTIZATION_ORDER.index(q)
    return OPENROUTER_QUANTIZATION_ORDER[start:]


_OPENAI_REASONING_PREFIXES = ("o1", "o3", "o4", "codex")


def is_openai_reasoning_model(model: str) -> bool:
    name = (model or "").strip().lower()
    if name.startswith("openai/"):
        name = name[len("openai/"):]
    return any(
        name == p or name.startswith(p + "-") or name.startswith(p + "_")
        for p in _OPENAI_REASONING_PREFIXES
    )


class LLMProvider(Enum):
    OPENROUTER = "openrouter"
    CLAUDE = "claude"
    OPENAI = "openai"
    DEEPSEEK = "deepseek"


class DeployTarget(Enum):
    NONE = "none"
    LOCALSTACK = "localstack"
    AWS = "aws"


@dataclass
class LLMConfig:
    provider: LLMProvider = LLMProvider.OPENROUTER
    model: str = "deepseek/deepseek-v4-flash"
    temperature: float = 0.0
    max_tokens: int | None = 8192
    reasoning_enabled: bool = True

    llm_retry_max_attempts: int = field(
        default_factory=lambda: int(os.getenv("LLM_RETRY_MAX_ATTEMPTS", "4"))
    )
    llm_retry_backoff_seconds: float = field(
        default_factory=lambda: float(os.getenv("LLM_RETRY_BACKOFF_SECONDS", "2.0"))
    )

    openrouter_api_key: str = field(
        default_factory=lambda: os.getenv("OPENROUTER_API_KEY", "")
    )
    openrouter_base_url: str = "https://openrouter.ai/api/v1"
    openrouter_provider_only: tuple[str, ...] = field(
        default_factory=lambda: _parse_csv_env(os.getenv("OPENROUTER_PROVIDER_ONLY"))
    )
    openrouter_min_quantization: str = field(
        default_factory=lambda: os.getenv("OPENROUTER_MIN_QUANTIZATION", "").strip().lower()
    )
    openrouter_reasoning_effort: str = field(
        default_factory=lambda: os.getenv("OPENROUTER_REASONING_EFFORT", "").strip().lower()
    )
    openrouter_reasoning_max_tokens: int | None = field(
        default_factory=lambda: _parse_optional_int(os.getenv("OPENROUTER_REASONING_MAX_TOKENS"))
    )

    anthropic_api_key: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", "")
    )

    openai_api_key: str = field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY", "")
    )
    openai_base_url: str = field(
        default_factory=lambda: os.getenv("OPENAI_BASE_URL", "")
    )

    deepseek_api_key: str = field(
        default_factory=lambda: os.getenv("DEEPSEEK_API_KEY", "")
    )
    deepseek_base_url: str = field(
        default_factory=lambda: os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    )


@dataclass
class DeployConfig:
    target: DeployTarget = DeployTarget.NONE
    localstack_endpoint: str = field(
        default_factory=lambda: os.getenv("LOCALSTACK_ENDPOINT", "http://localhost:4566")
    )
    localstack_reset_wait: float = 5
    aws_region: str = field(
        default_factory=lambda: os.getenv("AWS_DEFAULT_REGION", "us-east-1")
    )
    aws_profile: str = field(
        default_factory=lambda: os.getenv("AWS_PROFILE", "default")
    )
    stack_creation_timeout: int = 30 * 60
    stack_deletion_timeout: int = 5 * 60


SIMPLE_MODE_THRESHOLD: int = 0


def build_openrouter_provider_preferences(config: LLMConfig) -> dict:
    provider: dict[str, object] = {}

    if config.openrouter_provider_only:
        provider["only"] = list(config.openrouter_provider_only)

    quantizations = quantizations_from_min(config.openrouter_min_quantization)
    if quantizations:
        provider["quantizations"] = list(quantizations)

    return provider


DEFAULT_CONFIG = LLMConfig()
DEFAULT_DEPLOY_CONFIG = DeployConfig()


def configure_llm(
    provider: str = "openrouter",
    model: str | None = None,
    *,
    openrouter_provider_only: str | None = None,
    openrouter_min_quantization: str | None = None,
    openrouter_reasoning_effort: str | None = None,
    openrouter_reasoning_max_tokens: int | None = None,
    disable_reasoning: bool = False,
    max_tokens: int | None = None,
    no_max_tokens: bool = False,
) -> None:
    if provider == "claude":
        DEFAULT_CONFIG.provider = LLMProvider.CLAUDE
        DEFAULT_CONFIG.model = model or "claude-3-5-sonnet-20241022"

    elif provider == "openai":
        DEFAULT_CONFIG.provider = LLMProvider.OPENAI
        DEFAULT_CONFIG.model = model or os.getenv("OPENAI_MODEL", "o3-mini")
        if not DEFAULT_CONFIG.openai_api_key:
            raise ValueError(
                "OPENAI_API_KEY is not set. "
                "Add it to your .env file or set the environment variable directly."
            )

    elif provider == "deepseek":
        DEFAULT_CONFIG.provider = LLMProvider.DEEPSEEK
        DEFAULT_CONFIG.model = model or os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
        if not DEFAULT_CONFIG.deepseek_api_key:
            raise ValueError(
                "DEEPSEEK_API_KEY is not set. "
                "Add it to your .env file or set the environment variable directly."
            )
        if disable_reasoning:
            DEFAULT_CONFIG.reasoning_enabled = False

    else:
        DEFAULT_CONFIG.provider = LLMProvider.OPENROUTER
        DEFAULT_CONFIG.model = model or "arcee-ai/trinity-large-preview:free"

        if openrouter_provider_only is not None:
            DEFAULT_CONFIG.openrouter_provider_only = _parse_csv_env(openrouter_provider_only)
        if openrouter_min_quantization is not None:
            DEFAULT_CONFIG.openrouter_min_quantization = openrouter_min_quantization.strip().lower()
        if openrouter_reasoning_effort is not None:
            DEFAULT_CONFIG.openrouter_reasoning_effort = openrouter_reasoning_effort.strip().lower()
        if openrouter_reasoning_max_tokens is not None:
            DEFAULT_CONFIG.openrouter_reasoning_max_tokens = openrouter_reasoning_max_tokens
        if disable_reasoning:
            DEFAULT_CONFIG.reasoning_enabled = False

    if no_max_tokens:
        DEFAULT_CONFIG.max_tokens = None
    elif max_tokens is not None:
        DEFAULT_CONFIG.max_tokens = max_tokens
