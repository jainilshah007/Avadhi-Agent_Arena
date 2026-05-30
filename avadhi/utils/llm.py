"""
avadhi/utils/llm.py — LLM provider setup with integrated rate limiting.

Every LLM call goes through the shared rate limiter automatically.
"""
from __future__ import annotations

import logging
import time

from langchain_core.language_models import BaseChatModel

from avadhi.config import MODEL, ANTHROPIC_API_KEY, OPENAI_API_KEY

logger = logging.getLogger(__name__)

_llm_instance: BaseChatModel | None = None


def get_llm(temperature: float = 0.0) -> BaseChatModel:
    """Get the LLM instance. Cached after first call."""
    global _llm_instance
    if _llm_instance is not None:
        return _llm_instance

    if MODEL.startswith("claude") or MODEL.startswith("anthropic"):
        from langchain_anthropic import ChatAnthropic
        _llm_instance = ChatAnthropic(
            model=MODEL,
            api_key=ANTHROPIC_API_KEY,
            max_tokens=4096,
            temperature=temperature,
            timeout=120.0,
        )
    else:
        from langchain_openai import ChatOpenAI
        _llm_instance = ChatOpenAI(
            model=MODEL,
            api_key=OPENAI_API_KEY,
            temperature=temperature,
            timeout=60.0,
        )

    return _llm_instance


def invoke_with_rate_limit(llm_or_structured, messages, *,
                           estimated_input_tokens: int = 2000,
                           estimated_output_tokens: int = 1500,
                           max_retries: int = 3):
    """
    Invoke an LLM with automatic rate limiting and retry logic.

    This is the preferred way to call any LLM in the Avadhi pipeline.
    It acquires a rate limit slot before calling, records actual usage
    after, and retries on transient failures with exponential backoff.
    """
    from avadhi.utils.rate_limiter import rate_limiter

    last_exc = None
    for attempt in range(1, max_retries + 1):
        rid = rate_limiter.acquire(
            estimated_input_tokens=estimated_input_tokens,
            estimated_output_tokens=estimated_output_tokens,
        )
        try:
            response = llm_or_structured.invoke(messages)

            # Record actual token usage from response metadata
            usage = getattr(response, "usage_metadata", None) or {}
            if isinstance(usage, dict):
                actual_in = usage.get("input_tokens", estimated_input_tokens)
                actual_out = usage.get("output_tokens", estimated_output_tokens)
            else:
                actual_in = getattr(usage, "input_tokens", estimated_input_tokens)
                actual_out = getattr(usage, "output_tokens", estimated_output_tokens)

            rate_limiter.record_usage(rid, actual_in, actual_out)
            return response

        except Exception as e:
            rate_limiter.cancel_reservation(rid)
            last_exc = e

            error_str = str(e).lower()
            is_rate_limit = "rate" in error_str or "429" in error_str or "overloaded" in error_str
            is_transient = is_rate_limit or "timeout" in error_str or "500" in error_str or "503" in error_str

            if attempt == max_retries or not is_transient:
                raise

            # Exponential backoff: 2s, 4s, 8s (longer for rate limits)
            backoff = (4 if is_rate_limit else 2) * (2 ** (attempt - 1))
            logger.warning(
                "LLM call failed (attempt %d/%d): %s. Retrying in %ds...",
                attempt, max_retries, e, backoff,
            )
            time.sleep(backoff)

    raise last_exc  # Should never reach here, but just in case


def invoke_with_fallback(structured_llm, messages, max_retries: int = 3):
    """Backwards-compatible wrapper — now uses rate limiting internally."""
    return invoke_with_rate_limit(
        structured_llm, messages,
        max_retries=max_retries,
    )
