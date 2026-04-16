"""
Defense Pipeline — Layer 6: Audit Log

Why this layer?
    Without an immutable audit trail you cannot investigate incidents, prove
    compliance, or tune guardrails.  Every interaction — whether blocked or
    allowed — must be recorded.

What it does:
    Records per-request structured entries:
        - timestamp (ISO 8601)
        - user_id
        - session_id
        - input text (first 500 chars)
        - output text (first 500 chars)
        - blocked_by: name of the layer that blocked, or "none"
        - latency_ms: total round-trip time
        - judge_scores: SAFETY/RELEVANCE/ACCURACY/TONE if judge ran

    Exports to JSON via export_json().  All log writes are synchronous and
    in-process — for production, swap to an async append-only store.
"""
import json
import time
from datetime import datetime, timezone

from google.genai import types
from google.adk.plugins import base_plugin
from google.adk.agents.invocation_context import InvocationContext


class AuditLogPlugin(base_plugin.BasePlugin):
    """Record every interaction for compliance and forensic analysis.

    Hooks into both the input callback (to capture user message + start time)
    and the output callback (to record the response and compute latency).
    Neither callback ever blocks a request.
    """

    def __init__(self):
        super().__init__(name="audit_log")
        self.logs: list[dict] = []
        # Pending entries keyed by session_id, waiting for the response.
        self._pending: dict[str, dict] = {}

    def _extract_text(self, content: types.Content | None, limit: int = 500) -> str:
        """Extract up to `limit` characters of text from a Content object."""
        if not content or not content.parts:
            return ""
        return "".join(
            part.text for part in content.parts
            if hasattr(part, "text") and part.text
        )[:limit]

    async def on_user_message_callback(
        self,
        *,
        invocation_context: InvocationContext,
        user_message: types.Content,
    ) -> types.Content | None:
        """Record the user message and start timing.  Never blocks."""
        user_id = (
            invocation_context.user_id
            if invocation_context and hasattr(invocation_context, "user_id")
            else "anonymous"
        )
        session_id = (
            invocation_context.session.id
            if invocation_context
            and hasattr(invocation_context, "session")
            and invocation_context.session
            else "unknown"
        )

        self._pending[session_id] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "session_id": session_id,
            "input": self._extract_text(user_message),
            "output": "",
            "blocked_by": "none",
            "latency_ms": 0,
            "_start": time.monotonic(),
        }
        return None  # Never blocks

    async def after_model_callback(
        self,
        *,
        callback_context,
        llm_response,
    ):
        """Record the response and finalise the log entry.  Never modifies."""
        session_id = (
            callback_context.session.id
            if callback_context
            and hasattr(callback_context, "session")
            and callback_context.session
            else "unknown"
        )

        entry = self._pending.pop(session_id, None)
        if entry is None:
            # No matching pending entry — create a minimal one.
            entry = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user_id": "unknown",
                "session_id": session_id,
                "input": "",
                "blocked_by": "none",
                "_start": time.monotonic(),
            }

        elapsed = time.monotonic() - entry.pop("_start", time.monotonic())
        entry["latency_ms"] = round(elapsed * 1000, 1)

        # Extract response text from the LLM response object.
        response_text = ""
        if hasattr(llm_response, "content") and llm_response.content:
            response_text = self._extract_text(llm_response.content)
        entry["output"] = response_text

        self.logs.append(entry)
        return llm_response  # Never modifies

    def add_blocked_entry(
        self,
        user_id: str,
        session_id: str,
        input_text: str,
        blocked_by: str,
        output_text: str = "",
    ) -> None:
        """Manually log a request that was blocked before reaching the LLM.

        Called by the test runner when a plugin returns a block response
        (rate limiter, input guardrail, session anomaly).
        """
        self.logs.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user_id": user_id,
            "session_id": session_id,
            "input": input_text[:500],
            "output": output_text[:500],
            "blocked_by": blocked_by,
            "latency_ms": 0,
        })

    def export_json(self, filepath: str = "audit_log.json") -> None:
        """Write all log entries to a JSON file.

        Args:
            filepath: Destination path for the JSON file.
        """
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.logs, f, indent=2, ensure_ascii=False, default=str)
        print(f"Audit log exported: {filepath} ({len(self.logs)} entries)")
