"""
Defense Pipeline — Monitoring & Alerts

Why this module?
    Guardrails need to be monitored in production.  A sudden spike in block rate
    indicates an ongoing attack; a drop in block rate on known attacks indicates
    a regression in the pipeline.  This module surfaces those signals.

What it does:
    Reads statistics from the active plugins and computes:
        - block_rate:         fraction of total requests blocked by input/output guardrails
        - rate_limit_hit_rate: fraction of total requests throttled by rate limiter
        - judge_fail_rate:    fraction of LLM responses rejected by the judge

    Fires console alerts when any metric exceeds its threshold.
    In production these would emit to Prometheus / DataDog / PagerDuty.
"""


# Alert thresholds.  Tune these based on baseline behaviour.
BLOCK_RATE_ALERT_THRESHOLD = 0.30        # >30% of requests blocked → potential attack
RATE_LIMIT_ALERT_THRESHOLD = 0.20        # >20% rate-limited → DDoS / abuse
JUDGE_FAIL_ALERT_THRESHOLD = 0.15        # >15% judge failures → model regression


class MonitoringAlert:
    """Compute pipeline health metrics and raise alerts on threshold breaches.

    Usage:
        monitor = MonitoringAlert(plugins)
        monitor.check_metrics()
    """

    def __init__(self, plugins: list):
        """
        Args:
            plugins: List of plugin instances from the pipeline assembly.
                     The monitor inspects their .total_count / .hit_count etc.
        """
        self.plugins = plugins

    def _get_plugin(self, name: str):
        """Find a plugin by its registered name."""
        for p in self.plugins:
            if hasattr(p, "name") and p.name == name:
                return p
        return None

    def compute_metrics(self) -> dict:
        """Calculate current health metrics from plugin statistics.

        Returns:
            dict with rate_limit_hit_rate, block_rate, judge_fail_rate, totals.
        """
        rate_limiter = self._get_plugin("rate_limiter")
        input_guard = self._get_plugin("input_guardrail")
        session_anomaly = self._get_plugin("session_anomaly")
        output_guard = self._get_plugin("output_guardrail")
        llm_judge = self._get_plugin("llm_judge")
        audit_log = self._get_plugin("audit_log")

        # Total requests seen at the earliest layer (rate limiter or input guard).
        total = (
            getattr(rate_limiter, "total_count", 0)
            or getattr(input_guard, "total_count", 0)
        )
        total = max(total, 1)  # avoid division by zero

        rate_limit_hits = getattr(rate_limiter, "hit_count", 0)
        input_blocked = getattr(input_guard, "blocked_count", 0)
        session_blocked = getattr(session_anomaly, "sessions_blocked", 0)
        output_redacted = getattr(output_guard, "redacted_count", 0)
        output_blocked = getattr(output_guard, "blocked_count", 0)
        judge_fails = getattr(llm_judge, "fail_count", 0)
        judge_total = getattr(llm_judge, "total_count", 0)
        audit_entries = len(getattr(audit_log, "logs", []))

        total_blocked = input_blocked + session_blocked + output_blocked + rate_limit_hits

        return {
            "total_requests": total,
            "rate_limit_hits": rate_limit_hits,
            "rate_limit_hit_rate": rate_limit_hits / total,
            "input_blocked": input_blocked,
            "session_blocked": session_blocked,
            "output_redacted": output_redacted,
            "output_blocked": output_blocked,
            "total_blocked": total_blocked,
            "block_rate": total_blocked / total,
            "judge_fails": judge_fails,
            "judge_total": max(judge_total, 1),
            "judge_fail_rate": judge_fails / max(judge_total, 1),
            "audit_entries": audit_entries,
        }

    def check_metrics(self) -> dict:
        """Print a metrics summary and fire alerts for any threshold breaches.

        Returns:
            The metrics dict computed by compute_metrics().
        """
        m = self.compute_metrics()

        print("\n" + "=" * 60)
        print("MONITORING DASHBOARD")
        print("=" * 60)
        print(f"  Total requests:          {m['total_requests']}")
        print(f"  Rate-limit hits:         {m['rate_limit_hits']}  ({m['rate_limit_hit_rate']:.1%})")
        print(f"  Input blocked:           {m['input_blocked']}")
        print(f"  Session anomaly blocked: {m['session_blocked']}")
        print(f"  Output redacted:         {m['output_redacted']}")
        print(f"  Output blocked (judge):  {m['output_blocked'] + m['judge_fails']}")
        print(f"  Total blocked:           {m['total_blocked']}  ({m['block_rate']:.1%})")
        print(f"  Judge fail rate:         {m['judge_fails']}/{m['judge_total']}  ({m['judge_fail_rate']:.1%})")
        print(f"  Audit log entries:       {m['audit_entries']}")
        print("-" * 60)

        alerts = []

        if m["block_rate"] > BLOCK_RATE_ALERT_THRESHOLD:
            alerts.append(
                f"HIGH BLOCK RATE {m['block_rate']:.1%} > {BLOCK_RATE_ALERT_THRESHOLD:.0%} "
                f"— possible active attack"
            )

        if m["rate_limit_hit_rate"] > RATE_LIMIT_ALERT_THRESHOLD:
            alerts.append(
                f"HIGH RATE-LIMIT HIT RATE {m['rate_limit_hit_rate']:.1%} > "
                f"{RATE_LIMIT_ALERT_THRESHOLD:.0%} — possible DDoS"
            )

        if m["judge_fail_rate"] > JUDGE_FAIL_ALERT_THRESHOLD:
            alerts.append(
                f"HIGH JUDGE FAIL RATE {m['judge_fail_rate']:.1%} > "
                f"{JUDGE_FAIL_ALERT_THRESHOLD:.0%} — model regression or new attack vector"
            )

        if alerts:
            print("  ALERTS FIRED:")
            for alert in alerts:
                print(f"    [ALERT] {alert}")
        else:
            print("  All metrics within normal thresholds.")

        print("=" * 60)
        return m
