"""
Defense Pipeline — Layer 1: Rate Limiter

Why this layer?
    Without rate limiting an attacker can run thousands of injection attempts
    per minute.  This layer stops brute-force and enumeration attacks that the
    content-based layers alone cannot prevent.

What it does:
    Implements a **sliding-window** counter per user_id.  Only the timestamps
    that fall inside the current window are retained; older ones are discarded.
    When the count hits the limit the request is blocked and the caller is
    told how many seconds to wait before trying again.

ADK Plugin Callback Order:
    1. on_user_message_callback  — reads user_id + checks window, stores block flag
    2. before_run_callback       — emits block Content as final event (early exit)
    Using before_run_callback for blocking is necessary because it is the only
    callback where a returned Content is emitted as an event AND causes an
    early exit (no LLM call). on_user_message_callback only replaces the user
    message; it does NOT short-circuit the LLM.
"""
import time
from collections import defaultdict, deque

from google.genai import types
from google.adk.plugins import base_plugin
from google.adk.agents.invocation_context import InvocationContext


class RateLimitPlugin(base_plugin.BasePlugin):
    """Block users who exceed max_requests within window_seconds.

    Uses a per-user sliding-window deque of request timestamps.
    Expired entries are pruned on every call so memory stays bounded.
    """

    def __init__(self, max_requests: int = 10, window_seconds: int = 60):
        """
        Args:
            max_requests:   Maximum allowed requests in the time window.
            window_seconds: Duration of the sliding window in seconds.
        """
        super().__init__(name="rate_limiter")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # Map of user_id -> deque of request timestamps (floats)
        self.user_windows: dict[str, deque] = defaultdict(deque)
        # Map of invocation_id -> block Content (set in on_user_message, read in before_run)
        self._pending_blocks: dict[str, types.Content] = {}
        # Statistics for monitoring
        self.hit_count = 0
        self.total_count = 0

    def _block_response(self, wait_seconds: float) -> types.Content:
        """Return a friendly block message that includes the retry wait time."""
        return types.Content(
            role="model",
            parts=[types.Part.from_text(
                text=(
                    f"You have sent too many requests. "
                    f"Please wait {wait_seconds:.0f} seconds before trying again."
                )
            )],
        )

    async def on_user_message_callback(
        self,
        *,
        invocation_context: InvocationContext,
        user_message: types.Content,
    ) -> types.Content | None:
        """Check request rate for the current user.

        If over the limit, stores a block Content in _pending_blocks keyed by
        invocation_id so before_run_callback can emit it as an early-exit event.
        Always returns None here (we don't replace the user message).
        """
        self.total_count += 1

        # invocation_context.user_id is a property that returns session.user_id
        user_id = "anonymous"
        if invocation_context:
            try:
                user_id = invocation_context.user_id or "anonymous"
            except Exception:
                if hasattr(invocation_context, "session") and invocation_context.session:
                    user_id = getattr(invocation_context.session, "user_id", "anonymous")

        now = time.time()
        window = self.user_windows[user_id]
        cutoff = now - self.window_seconds

        # Remove timestamps that have fallen outside the sliding window.
        while window and window[0] < cutoff:
            window.popleft()

        if len(window) >= self.max_requests:
            wait_seconds = self.window_seconds - (now - window[0])
            self.hit_count += 1
            # Store the block content; before_run_callback will emit it.
            inv_id = getattr(invocation_context, "invocation_id", None)
            if inv_id:
                self._pending_blocks[inv_id] = self._block_response(max(0.0, wait_seconds))
            return None  # Don't replace user message

        # Request is within limits — record and allow.
        window.append(now)
        return None

    async def before_run_callback(
        self,
        *,
        invocation_context: InvocationContext,
    ) -> types.Content | None:
        """Emit block Content as the final response if rate limit was exceeded.

        This callback is the correct place for early-exit blocking in ADK:
        returning a Content here causes the runner to emit it as an event and
        immediately exit without calling the LLM.
        """
        inv_id = getattr(invocation_context, "invocation_id", None)
        if inv_id and inv_id in self._pending_blocks:
            block_content = self._pending_blocks.pop(inv_id)
            return block_content
        return None
