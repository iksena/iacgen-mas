from __future__ import annotations

import json
import time

import anthropic
import openai

from config import (
    DEFAULT_CONFIG,
    LLMProvider,
    build_openrouter_provider_preferences,
    is_openai_reasoning_model,
)


class EmptyCompletionError(RuntimeError):

    def __init__(self, message: str, usage: dict | None = None):
        super().__init__(message)
        self.usage = usage or {}


_CONNECTION_ERRORS = (openai.APIConnectionError, anthropic.APIConnectionError)


def _is_count(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _merge_usage(usage: dict, wasted: dict) -> dict:
    merged = dict(usage)
    for key, value in wasted.items():
        merged[key] = merged.get(key, 0) + value
    return merged


def _call_with_retry(fn, *, label: str, max_attempts: int, backoff_seconds: float):
    wasted_usage: dict = {}
    last_exc: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            content, usage = fn()
            if wasted_usage:
                usage = _merge_usage(usage, wasted_usage)
            return content, usage
        except EmptyCompletionError as exc:
            last_exc = exc
            for key, value in exc.usage.items():
                if _is_count(value):
                    wasted_usage[key] = wasted_usage.get(key, 0) + value
            reason = "empty completion"
        except _CONNECTION_ERRORS as exc:
            last_exc = exc
            reason = "connection error"

        if attempt >= max_attempts:
            print(f"[LLMClient] {label}: {reason} on attempt {attempt}/{max_attempts}, giving up: {last_exc}")
            raise last_exc

        delay = backoff_seconds * (2 ** (attempt - 1))
        print(
            f"[LLMClient] {label}: {reason} on attempt {attempt}/{max_attempts}, "
            f"retrying in {delay:.0f}s: {last_exc}"
        )
        time.sleep(delay)

    raise last_exc


def _build_client():
    if DEFAULT_CONFIG.provider == LLMProvider.OPENROUTER:
        from openai import OpenAI
        return OpenAI(
            api_key=DEFAULT_CONFIG.openrouter_api_key,
            base_url=DEFAULT_CONFIG.openrouter_base_url,
        ), DEFAULT_CONFIG.model

    if DEFAULT_CONFIG.provider == LLMProvider.OPENAI:
        from openai import OpenAI
        kwargs: dict = {"api_key": DEFAULT_CONFIG.openai_api_key}
        if DEFAULT_CONFIG.openai_base_url:
            kwargs["base_url"] = DEFAULT_CONFIG.openai_base_url
        return OpenAI(**kwargs), DEFAULT_CONFIG.model

    if DEFAULT_CONFIG.provider == LLMProvider.DEEPSEEK:
        from openai import OpenAI
        return OpenAI(
            api_key=DEFAULT_CONFIG.deepseek_api_key,
            base_url=DEFAULT_CONFIG.deepseek_base_url,
        ), DEFAULT_CONFIG.model

    import anthropic
    return anthropic.Anthropic(
        api_key=DEFAULT_CONFIG.anthropic_api_key
    ), DEFAULT_CONFIG.model


def _to_int(value: object) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _response_debug_blob(response: object) -> str:
    if response is None:
        return "response=None"
    try:
        if hasattr(response, "model_dump_json"):
            return response.model_dump_json(indent=2)
    except Exception:
        pass
    try:
        return json.dumps(response, default=str, indent=2)
    except Exception:
        return repr(response)


def _cache_block(text: str) -> list[dict]:
    return [{"type": "text", "text": text, "cache_control": {"type": "ephemeral"}}]


def _mark_last_message_cacheable(messages: list) -> list:
    if not messages or not isinstance(messages[-1].get("content"), str):
        return messages
    marked = dict(messages[-1])
    marked["content"] = _cache_block(marked["content"])
    return messages[:-1] + [marked]


def _openrouter_model_needs_explicit_cache_marker(model: str) -> bool:
    m = model.lower()
    return m.startswith("anthropic/") or m.startswith("google/gemini") or "qwen" in m


def build_session_id(state: dict, agent_name: str) -> str | None:
    run_id = state.get("run_id")
    return f"{run_id}:{agent_name}" if run_id else None


_OPENROUTER_REASONING_EFFORT_SHARE = {
    "minimal": 0.10, "low": 0.20, "medium": 0.50, "high": 0.80,
    "xhigh": 0.95, "max": 0.95,
}
_MAX_TOKENS_OVERRIDE_CAP = 128_000


def _reasoning_expanded_max_tokens(base_max_tokens: int | None, effort: str) -> int | None:
    if base_max_tokens is None:
        return None
    share = _OPENROUTER_REASONING_EFFORT_SHARE.get(effort)
    if share is None:
        return None
    return min(int(base_max_tokens / (1 - share)), _MAX_TOKENS_OVERRIDE_CAP)


def _call_openai_compat(
    client,
    model: str,
    system: str,
    messages: list,
    *,
    is_reasoning: bool,
    extra_body: dict | None = None,
    max_tokens_override: int | None = None,
    use_cache_control: bool = False,
    session_id: str | None = None,
) -> tuple[str, dict]:
    if use_cache_control:
        chat_messages = (
            [{"role": "system", "content": _cache_block(system)}]
            + _mark_last_message_cacheable(messages)
        )
    else:
        chat_messages = [{"role": "system", "content": system}] + messages

    request_kwargs: dict = {
        "model": model,
        "messages": chat_messages,
    }

    max_tokens = max_tokens_override if max_tokens_override is not None else DEFAULT_CONFIG.max_tokens

    if is_reasoning:
        if max_tokens is not None:
            request_kwargs["max_completion_tokens"] = max_tokens
    else:
        request_kwargs["temperature"] = DEFAULT_CONFIG.temperature
        if max_tokens is not None:
            request_kwargs["max_tokens"] = max_tokens

    merged_extra_body: dict = dict(extra_body) if extra_body else {}
    if session_id:
        merged_extra_body["session_id"] = session_id
    if merged_extra_body:
        request_kwargs["extra_body"] = merged_extra_body

    def _do_call() -> tuple[str, dict]:
        r = client.chat.completions.create(**request_kwargs)

        usage_obj = getattr(r, "usage", None)
        prompt_details = getattr(usage_obj, "prompt_tokens_details", None)
        completion_details = getattr(usage_obj, "completion_tokens_details", None)
        usage = {
            "prompt_tokens": _to_int(getattr(usage_obj, "prompt_tokens", 0)),
            "completion_tokens": _to_int(getattr(usage_obj, "completion_tokens", 0)),
            "cache_creation_input_tokens": _to_int(getattr(prompt_details, "cache_write_tokens", 0)),
            "cache_read_input_tokens": _to_int(getattr(prompt_details, "cached_tokens", 0)),
            "reasoning_tokens": _to_int(getattr(completion_details, "reasoning_tokens", 0)),
        }
        reported_model = getattr(r, "model", None)
        if reported_model:
            usage["reported_model"] = reported_model

        choices = getattr(r, "choices", None) or []
        if not choices:
            raise EmptyCompletionError(
                f"OpenAI-compat API returned no choices. "
                f"model={model} response={_response_debug_blob(r)}",
                usage=usage,
            )

        message = getattr(choices[0], "message", None)
        content = getattr(message, "content", None) if message is not None else None

        if isinstance(content, list):
            content = "".join(
                part.get("text", "") if isinstance(part, dict) else ""
                for part in content
            ).strip()

        if not isinstance(content, str) or not content.strip():
            raise EmptyCompletionError(
                f"OpenAI-compat API returned empty/non-text content. "
                f"model={model} response={_response_debug_blob(r)}",
                usage=usage,
            )

        return content, usage

    return _call_with_retry(
        _do_call,
        label=f"openai-compat({model})",
        max_attempts=DEFAULT_CONFIG.llm_retry_max_attempts,
        backoff_seconds=DEFAULT_CONFIG.llm_retry_backoff_seconds,
    )


def _call_llm_with_history(
    client,
    model: str,
    system: str,
    messages: list,
    *,
    session_id: str | None = None,
) -> tuple[str, dict]:
    if DEFAULT_CONFIG.provider == LLMProvider.CLAUDE and DEFAULT_CONFIG.max_tokens is None:
        raise ValueError(
            "max_tokens=None (uncapped) is only supported for OpenRouter/OpenAI "
            "direct — Anthropic's API requires an explicit max_tokens and errors "
            "out without one. Set --max-tokens to a specific value for Claude."
        )
    if DEFAULT_CONFIG.provider == LLMProvider.OPENROUTER:
        extra_body: dict = {}
        provider_preferences = build_openrouter_provider_preferences(DEFAULT_CONFIG)
        if provider_preferences:
            extra_body["provider"] = provider_preferences
        max_tokens_override = None
        if DEFAULT_CONFIG.reasoning_enabled:
            reasoning_opts: dict = {"enabled": True}
            if DEFAULT_CONFIG.openrouter_reasoning_max_tokens:
                reasoning_opts["max_tokens"] = DEFAULT_CONFIG.openrouter_reasoning_max_tokens
                if DEFAULT_CONFIG.max_tokens is not None:
                    max_tokens_override = DEFAULT_CONFIG.max_tokens + DEFAULT_CONFIG.openrouter_reasoning_max_tokens
            elif DEFAULT_CONFIG.openrouter_reasoning_effort:
                reasoning_opts["effort"] = DEFAULT_CONFIG.openrouter_reasoning_effort
                max_tokens_override = _reasoning_expanded_max_tokens(
                    DEFAULT_CONFIG.max_tokens, DEFAULT_CONFIG.openrouter_reasoning_effort
                )
            extra_body["reasoning"] = reasoning_opts
        return _call_openai_compat(
            client, model, system, messages,
            is_reasoning=False,
            extra_body=extra_body or None,
            max_tokens_override=max_tokens_override,
            use_cache_control=_openrouter_model_needs_explicit_cache_marker(model),
            session_id=session_id,
        )

    if DEFAULT_CONFIG.provider == LLMProvider.OPENAI:
        return _call_openai_compat(
            client, model, system, messages,
            is_reasoning=is_openai_reasoning_model(model),
        )

    if DEFAULT_CONFIG.provider == LLMProvider.DEEPSEEK:
        extra_body = None if DEFAULT_CONFIG.reasoning_enabled else {"thinking": {"type": "disabled"}}
        return _call_openai_compat(
            client, model, system, messages,
            is_reasoning=False,
            extra_body=extra_body,
        )

    def _do_call() -> tuple[str, dict]:
        r = client.messages.create(
            model=model,
            system=_cache_block(system),
            messages=_mark_last_message_cacheable(messages),
            temperature=DEFAULT_CONFIG.temperature,
            max_tokens=DEFAULT_CONFIG.max_tokens,
        )
        usage = {
            "input_tokens": _to_int(getattr(r.usage, "input_tokens", 0)),
            "output_tokens": _to_int(getattr(r.usage, "output_tokens", 0)),
            "cache_creation_input_tokens": _to_int(getattr(r.usage, "cache_creation_input_tokens", 0)),
            "cache_read_input_tokens": _to_int(getattr(r.usage, "cache_read_input_tokens", 0)),
        }
        reported_model = getattr(r, "model", None)
        if reported_model:
            usage["reported_model"] = reported_model
        blocks = getattr(r, "content", None) or []
        text = "".join(
            getattr(b, "text", "") for b in blocks if getattr(b, "type", None) == "text"
        ).strip()
        if not text:
            raise EmptyCompletionError(
                f"Anthropic API returned empty/non-text content. "
                f"model={model} response={_response_debug_blob(r)}",
                usage=usage,
            )
        return text, usage

    return _call_with_retry(
        _do_call,
        label=f"anthropic({model})",
        max_attempts=DEFAULT_CONFIG.llm_retry_max_attempts,
        backoff_seconds=DEFAULT_CONFIG.llm_retry_backoff_seconds,
    )
