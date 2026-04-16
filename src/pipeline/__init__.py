"""
Defense-in-Depth Pipeline — production safety layer package.

Layer order (as loaded by defense_pipeline.py):
  1. RateLimitPlugin      — sliding-window per-user request throttle
  2. InputGuardrailPlugin — injection detection + topic filter  (from lab)
  3. SessionAnomalyPlugin — block sessions with repeated attacks (BONUS)
  4. [LLM runs here]
  5. OutputGuardrailPlugin — PII redaction                      (from lab)
  6. LlmJudgePlugin       — multi-criteria SAFETY/RELEVANCE/ACCURACY/TONE
  7. AuditLogPlugin       — full interaction logging + JSON export
"""
