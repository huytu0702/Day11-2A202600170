"""
Defense Pipeline — Layer 3 (BONUS): Session Anomaly Detector

Why this layer?
    A single injection attempt might be a mistake.  But if the same session
    sends 3+ messages that match injection patterns, that is a deliberate
    adversarial session.  Permanently blocking the session stops the attacker
    from iterating through variants of the same attack.

    This catches attacks that the per-request input guardrail misses because it
    has no memory across requests.  It is complementary, not redundant.

What it does:
    Counts the number of injection-like messages per session_id.
    Once the threshold is exceeded, ALL further messages from that session
    are blocked — regardless of content.
"""
import re
from collections import defaultdict

from google.genai import types
from google.adk.plugins import base_plugin
from google.adk.agents.invocation_context import InvocationContext


# Lightweight subset of injection signals — intentionally broader than the
# input guardrail so we catch attempts that narrowly slip through that layer.
_ANOMALY_SIGNALS = [
    r"ignore (all )?(previous|above|prior) instructions?",
    r"forget.{0,20}instructions?",
    r"you are now\b",
    r"pretend (you are|to be)",
    r"act as.{0,20}(un)?restricted",
    r"(reveal|show|output|translate).{0,30}(system.?prompt|instructions?|credentials?)",
    r"(password|api.?key|secret)\s*[:=]",
    r"bỏ qua.{0,20}(hướng dẫn|chỉ thị)",
    r"tiết lộ.{0,20}(mật khẩu|api)",
    r"\bDAN\b",
    r"jailbreak",
    r"(base64|rot13).{0,20}(prompt|instructions?)",
]

_COMPILED_SIGNALS = [re.compile(p, re.IGNORECASE) for p in _ANOMALY_SIGNALS]


class SessionAnomalyPlugin(base_plugin.BasePlugin):
    """Block sessions that show repeated adversarial behaviour.

    A session is flagged as anomalous once suspicious_threshold injection
    signals have been detected.  After that, all messages from the session
    are blocked immediately without reaching the LLM.

    Uses the two-callback pattern:
      on_user_message_callback — detects signals, stores block flag
      before_run_callback      — emits block Content as early-exit event
    """

    def __init__(self, suspicious_threshold: int = 3):
        """
        Args:
            suspicious_threshold: Number of suspicious messages before the
                                  entire session is permanently blocked.
        """
        super().__init__(name="session_anomaly")
        self.suspicious_threshold = suspicious_threshold
        # session_id -> count of suspicious messages
        self.session_counts: dict[str, int] = defaultdict(int)
        # session_id -> True if permanently blocked
        self.blocked_sessions: set[str] = set()
        # invocation_id -> block Content
        self._pending_blocks: dict[str, types.Content] = {}
        # Statistics
        self.sessions_blocked = 0
        self.total_count = 0

    def _is_suspicious(self, text: str) -> bool:
        """Return True if the text matches any anomaly signal pattern."""
        return any(sig.search(text) for sig in _COMPILED_SIGNALS)

    def _extract_text(self, content: types.Content) -> str:
        """Extract plain text from a Content object."""
        if content and content.parts:
            return "".join(
                part.text for part in content.parts
                if hasattr(part, "text") and part.text
            )
        return ""

    async def on_user_message_callback(
        self,
        *,
        invocation_context: InvocationContext,
        user_message: types.Content,
    ) -> types.Content | None:
        """Detect session anomalies and store block flag if needed.

        Returns None always (does not replace user message).
        The actual blocking happens in before_run_callback.
        """
        self.total_count += 1
        inv_id = getattr(invocation_context, "invocation_id", None)

        session_id = "unknown_session"
        if invocation_context and hasattr(invocation_context, "session") and invocation_context.session:
            session_id = getattr(invocation_context.session, "id", "unknown_session")

        # If the session is already permanently blocked, schedule rejection.
        if session_id in self.blocked_sessions:
            if inv_id:
                self._pending_blocks[inv_id] = types.Content(
                    role="model",
                    parts=[types.Part.from_text(
                        text=(
                            "Your session has been suspended due to repeated policy violations. "
                            "Please contact VinBank support if you believe this is an error."
                        )
                    )],
                )
            return None

        text = self._extract_text(user_message)

        # Increment suspicious counter when an anomaly signal is detected.
        if self._is_suspicious(text):
            self.session_counts[session_id] += 1

            if self.session_counts[session_id] >= self.suspicious_threshold:
                # Permanently block this session.
                self.blocked_sessions.add(session_id)
                self.sessions_blocked += 1
                if inv_id:
                    self._pending_blocks[inv_id] = types.Content(
                        role="model",
                        parts=[types.Part.from_text(
                            text=(
                                "Multiple policy violations detected in this session. "
                                "Your access has been suspended. "
                                "Please contact VinBank support to resolve this."
                            )
                        )],
                    )

        return None

    async def before_run_callback(
        self,
        *,
        invocation_context: InvocationContext,
    ) -> types.Content | None:
        """Emit block Content as early-exit event for flagged sessions."""
        inv_id = getattr(invocation_context, "invocation_id", None)
        if inv_id and inv_id in self._pending_blocks:
            return self._pending_blocks.pop(inv_id)
        return None
