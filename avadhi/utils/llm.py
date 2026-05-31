"""
avadhi/utils/llm.py — LLM provider setup with integrated rate limiting.

Every LLM call goes through the shared rate limiter automatically.
Supports per-thread model selection and automatic Claude→GPT-4o fallback
on rate limit errors to prevent contest task failures.
"""
from __future__ import annotations

import logging
import threading
import time

from langchain_core.language_models import BaseChatModel

from avadhi.config import (
    MODEL, DEFAULT_MODEL, FALLBACK_MODEL,
    ANTHROPIC_API_KEY, OPENAI_API_KEY,
)

logger = logging.getLogger(__name__)

# ── Thread-local storage ──────────────────────────────────────────────────────
# Each audit task runs in its own thread (see handler.py). Storing the active
# model and LLM instance per-thread allows concurrent tasks to use different
# models without interfering with each other.
_thread_local = threading.local()


def get_thread_model() -> str:
    """Return the active model for the current thread."""
    # Priority: thread-local override → global AVADHI_MODEL → DEFAULT_MODEL
    return getattr(_thread_local, "model", None) or MODEL or DEFAULT_MODEL


def set_thread_model(model_name: str) -> None:
    """
    Set the active model for the current thread and clear the cached instance
    so a fresh LLM client is created for this model on the next call.
    """
    _thread_local.model = model_name
    _thread_local.llm_instance = None
    logger.info("Thread model set to '%s'", model_name)


def _clear_thread_llm() -> None:
    """Clear cached LLM instance so next get_llm() recreates it."""
    _thread_local.llm_instance = None


def get_llm(temperature: float = 0.0) -> BaseChatModel:
    """
    Get the LLM instance for the current thread. Cached per-thread after
    first call. If set_thread_model() has been called, uses that model.
    """
    cached = getattr(_thread_local, "llm_instance", None)
    if cached is not None:
        return cached

    model = get_thread_model()

    if model.startswith("claude") or model.startswith("anthropic"):
        from langchain_anthropic import ChatAnthropic
        instance = ChatAnthropic(
            model=model,
            api_key=ANTHROPIC_API_KEY,
            max_tokens=4096,
            temperature=temperature,
            timeout=120.0,
        )
    else:
        from langchain_openai import ChatOpenAI
        instance = ChatOpenAI(
            model=model,
            api_key=OPENAI_API_KEY,
            temperature=temperature,
            timeout=60.0,
        )

    _thread_local.llm_instance = instance
    logger.debug("Initialized LLM: %s", model)
    return instance


def invoke_with_rate_limit(llm_or_structured, messages, *,
                           estimated_input_tokens: int = 2000,
                           estimated_output_tokens: int = 1500,
                           max_retries: int = 3):
    """
    Invoke an LLM with automatic rate limiting and retry logic.

    On rate-limit errors, if the current thread is using Claude Opus,
    automatically falls back to the configured FALLBACK_MODEL (GPT-4o) and
    retries the same call — preventing complete task failure.
    """
    from avadhi.utils.rate_limiter import get_rate_limiter

    last_exc = None
    for attempt in range(1, max_retries + 1):
        current_model = get_thread_model()
        limiter = get_rate_limiter(current_model)

        rid = limiter.acquire(
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

            limiter.record_usage(rid, actual_in, actual_out)
            return response

        except Exception as e:
            limiter.cancel_reservation(rid)
            last_exc = e

            error_str = str(e).lower()
            is_rate_limit = "rate" in error_str or "429" in error_str or "overloaded" in error_str
            is_transient = is_rate_limit or "timeout" in error_str or "500" in error_str or "503" in error_str

            # ── Claude → GPT-4o automatic fallback ───────────────────────────
            if is_rate_limit and current_model != FALLBACK_MODEL and (
                current_model.startswith("claude") or current_model.startswith("anthropic")
            ):
                logger.warning(
                    "⚠️  Rate limit hit on '%s' (attempt %d). "
                    "Falling back to '%s' for the remainder of this task.",
                    current_model, attempt, FALLBACK_MODEL,
                )
                set_thread_model(FALLBACK_MODEL)
                # Rebuild the structured LLM wrapper with the new base LLM
                # so the caller's structured_with_fallback also updates.
                new_llm = get_llm()
                # If the caller passed a structured wrapper, try to rewrap it
                if hasattr(llm_or_structured, "with_structured_output"):
                    pass  # caller must rewrap; just retry with new base llm
                else:
                    llm_or_structured = new_llm
                continue  # retry immediately with GPT-4o

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
