"""
avadhi/utils/rate_limiter.py — Proactive rate limiter for Anthropic Tier-1.

Enforces THREE separate sliding-window budgets per minute:
  • Requests per minute      (RPM)  — 50
  • Input tokens per minute  (ITPM) — 30,000
  • Output tokens per minute (OTPM) — 8,000

All public methods are thread-safe; a single shared instance is used across
the entire avadhi pipeline (hunters, depth analyzer, critic, PoC generator).

Usage:
    from avadhi.utils.rate_limiter import rate_limiter

    # Before every LLM call — will SLEEP until budget is available.
    rate_limiter.acquire(estimated_input_tokens=2000, estimated_output_tokens=1000)

    response = llm.invoke(...)

    # After the call — record actual token usage from response headers/metadata.
    rate_limiter.record_usage(
        input_tokens=response.usage.input_tokens,
        output_tokens=response.usage.output_tokens,
    )
"""
from __future__ import annotations

import threading
import time
from collections import deque


class SlidingWindowRateLimiter:
    """
    Thread-safe sliding-window rate limiter with three independent budgets.

    All windows are exactly 60 seconds wide (rolling, not fixed-epoch).
    """

    def __init__(
        self,
        rpm_limit: int = 50,
        itpm_limit: int = 30_000,
        otpm_limit: int = 8_000,
        *,
        safety_factor: float = 0.90,  # stay at 90% of hard limits
    ):
        self._lock = threading.Lock()

        # Hard limits (after safety factor)
        self._rpm   = int(rpm_limit   * safety_factor)  # 45 effective
        self._itpm  = int(itpm_limit  * safety_factor)  # 27,000 effective
        self._otpm  = int(otpm_limit  * safety_factor)  # 7,200 effective

        # Sliding windows: each entry is (timestamp, value)
        self._req_window:    deque[tuple[float, int]] = deque()
        self._input_window:  deque[tuple[float, int]] = deque()
        self._output_window: deque[tuple[float, int]] = deque()

        # Pending reservations: tokens claimed but LLM call not yet complete
        # key = reservation_id, value = (estimated_input, estimated_output)
        self._pending: dict[int, tuple[int, int]] = {}
        self._next_id = 0

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _evict(self, now: float) -> None:
        """Remove entries older than 60 s from all windows."""
        cutoff = now - 60.0
        for window in (self._req_window, self._input_window, self._output_window):
            while window and window[0][0] <= cutoff:
                window.popleft()

    def _current_usage(self) -> tuple[int, int, int]:
        """Return (requests, input_tokens, output_tokens) in the last 60 s."""
        req  = sum(v for _, v in self._req_window)
        inp  = sum(v for _, v in self._input_window)
        out  = sum(v for _, v in self._output_window)
        # Add pending reservations
        for est_in, est_out in self._pending.values():
            inp += est_in
            out += est_out
        req += len(self._pending)
        return req, inp, out

    def _oldest_expiry(self) -> float:
        """Seconds until the oldest entry expires (i.e., how long to sleep)."""
        oldest = float("inf")
        for window in (self._req_window, self._input_window, self._output_window):
            if window:
                oldest = min(oldest, window[0][0] + 60.0)
        return oldest

    # ── Public API ────────────────────────────────────────────────────────────

    def acquire(
        self,
        estimated_input_tokens: int = 2000,
        estimated_output_tokens: int = 1000,
    ) -> int:
        """
        Block until all three budgets can accommodate this call.

        Returns a reservation_id that must be passed to record_usage() after
        the LLM call completes so pending estimates are replaced with actuals.
        """
        while True:
            with self._lock:
                now = time.monotonic()
                self._evict(now)
                req_u, inp_u, out_u = self._current_usage()

                req_ok  = (req_u  + 1)                      <= self._rpm
                inp_ok  = (inp_u  + estimated_input_tokens)  <= self._itpm
                out_ok  = (out_u  + estimated_output_tokens) <= self._otpm

                if req_ok and inp_ok and out_ok:
                    # Reserve the slot
                    rid = self._next_id
                    self._next_id += 1
                    self._pending[rid] = (estimated_input_tokens, estimated_output_tokens)
                    return rid

                # Calculate how long to sleep: wait until oldest event expires
                sleep_secs = max(0.1, self._oldest_expiry() - now)

            # Sleep OUTSIDE the lock so other threads can still make progress
            time.sleep(min(sleep_secs, 5.0))  # cap at 5 s so we re-check often

    def record_usage(
        self,
        reservation_id: int,
        input_tokens: int,
        output_tokens: int,
    ) -> None:
        """
        Called after the LLM call completes. Replaces the pending estimate
        with actual token counts in the sliding windows.
        """
        now = time.monotonic()
        with self._lock:
            self._pending.pop(reservation_id, None)
            self._req_window.append((now, 1))
            self._input_window.append((now, max(0, input_tokens)))
            self._output_window.append((now, max(0, output_tokens)))

    def cancel_reservation(self, reservation_id: int) -> None:
        """Call this if the LLM call failed without completing (e.g. exception)."""
        with self._lock:
            self._pending.pop(reservation_id, None)

    def status(self) -> dict:
        """Return current usage stats (for debugging/logging)."""
        with self._lock:
            now = time.monotonic()
            self._evict(now)
            req, inp, out = self._current_usage()
        return {
            "rpm_used":  req,  "rpm_limit":  self._rpm,
            "itpm_used": inp,  "itpm_limit": self._itpm,
            "otpm_used": out,  "otpm_limit": self._otpm,
            "pending": len(self._pending),
        }


# ── Singleton shared across the entire process ────────────────────────────────
# Reads from config.py so env vars (AVADHI_RPM, AVADHI_ITPM, AVADHI_OTPM)
# are the single place to tune limits for a different API tier.
from avadhi.config import RATE_LIMIT_RPM, RATE_LIMIT_ITPM, RATE_LIMIT_OTPM  # noqa: E402

rate_limiter = SlidingWindowRateLimiter(
    rpm_limit=RATE_LIMIT_RPM,
    itpm_limit=RATE_LIMIT_ITPM,
    otpm_limit=RATE_LIMIT_OTPM,
)
