"""
Lab 11 — Part 4: Human-in-the-Loop Design
  TODO 12: Confidence Router
  TODO 13: Design 3 HITL decision points
"""
from dataclasses import dataclass


# ============================================================
# TODO 12: Implement ConfidenceRouter
#
# Route agent responses based on confidence scores:
#   - HIGH (>= 0.9): Auto-send to user
#   - MEDIUM (0.7 - 0.9): Queue for human review
#   - LOW (< 0.7): Escalate to human immediately
#
# Special case: if the action is HIGH_RISK (e.g., money transfer,
# account deletion), ALWAYS escalate regardless of confidence.
#
# Implement the route() method.
# ============================================================

HIGH_RISK_ACTIONS = [
    "transfer_money",
    "close_account",
    "change_password",
    "delete_data",
    "update_personal_info",
]


@dataclass
class RoutingDecision:
    """Result of the confidence router."""
    action: str          # "auto_send", "queue_review", "escalate"
    confidence: float
    reason: str
    priority: str        # "low", "normal", "high"
    requires_human: bool


class ConfidenceRouter:
    """Route agent responses based on confidence and risk level.

    Thresholds:
        HIGH:   confidence >= 0.9 -> auto-send
        MEDIUM: 0.7 <= confidence < 0.9 -> queue for review
        LOW:    confidence < 0.7 -> escalate to human

    High-risk actions always escalate regardless of confidence.
    """

    HIGH_THRESHOLD = 0.9
    MEDIUM_THRESHOLD = 0.7

    def route(self, response: str, confidence: float,
              action_type: str = "general") -> RoutingDecision:
        """Route a response based on confidence score and action type.

        Args:
            response: The agent's response text
            confidence: Confidence score between 0.0 and 1.0
            action_type: Type of action (e.g., "general", "transfer_money")

        Returns:
            RoutingDecision with routing action and metadata
        """
        # High-risk actions must always involve a human regardless of confidence.
        # A 99%-confident AI recommendation to transfer $100,000 is still too risky
        # to auto-approve — the stakes outweigh the automation benefit.
        if action_type in HIGH_RISK_ACTIONS:
            return RoutingDecision(
                action="escalate",
                confidence=confidence,
                reason=f"High-risk action: {action_type}",
                priority="high",
                requires_human=True,
            )

        # High confidence: the agent is sure enough for auto-send.
        if confidence >= self.HIGH_THRESHOLD:
            return RoutingDecision(
                action="auto_send",
                confidence=confidence,
                reason="High confidence",
                priority="low",
                requires_human=False,
            )

        # Medium confidence: human review improves quality but isn't urgent.
        if confidence >= self.MEDIUM_THRESHOLD:
            return RoutingDecision(
                action="queue_review",
                confidence=confidence,
                reason="Medium confidence — needs review",
                priority="normal",
                requires_human=True,
            )

        # Low confidence: the agent is uncertain; escalate immediately to avoid
        # sending a wrong or harmful answer to the customer.
        return RoutingDecision(
            action="escalate",
            confidence=confidence,
            reason="Low confidence — escalating",
            priority="high",
            requires_human=True,
        )


# ============================================================
# TODO 13: Design 3 HITL decision points
#
# For each decision point, define:
# - trigger: What condition activates this HITL check?
# - hitl_model: Which model? (human-in-the-loop, human-on-the-loop,
#   human-as-tiebreaker)
# - context_needed: What info does the human reviewer need?
# - example: A concrete scenario
#
# Think about real banking scenarios where human judgment is critical.
# ============================================================

hitl_decision_points = [
    {
        "id": 1,
        "name": "Large / Unusual Money Transfer",
        # Triggered when a customer requests a transfer that exceeds normal limits
        # or is to an unfamiliar recipient — classic fraud vector.
        "trigger": (
            "Transfer amount exceeds 50 million VND, or destination account is new "
            "(not transacted with in the past 30 days), or the request is made from "
            "a new device / IP address."
        ),
        "hitl_model": "human-in-the-loop",
        # The human agent must actively approve or deny before the transaction proceeds.
        "context_needed": (
            "Customer ID, full transaction history for last 90 days, flagged amount, "
            "destination account owner name, current session device/IP, fraud score."
        ),
        "example": (
            "Customer asks to transfer 200 million VND to a new account at 11 PM "
            "from a device that has never been used before. Agent flags as suspicious, "
            "queues for immediate human review. Human calls customer to verify identity "
            "before approving."
        ),
    },
    {
        "id": 2,
        "name": "Fraud / Dispute Claim",
        # Customers reporting fraud or disputing charges need empathy and legal accuracy
        # — two things a purely automated system handles poorly.
        "trigger": (
            "Customer message contains keywords: 'unauthorised', 'I did not make', "
            "'stolen', 'dispute', 'fraud', or LLM-as-Judge TONE score ≤ 2 on a "
            "complaint-type conversation."
        ),
        "hitl_model": "human-on-the-loop",
        # AI drafts a response and opens a ticket; human reviews the draft and the
        # case before it is sent (can override without blocking the queue).
        "context_needed": (
            "Recent transaction list, dispute amount, customer account status, "
            "any prior dispute history, AI-drafted response, relevant bank policy snippet."
        ),
        "example": (
            "Customer: 'There are three charges I never made on my card last night.' "
            "The agent opens a fraud case, drafts a response, and routes to the fraud "
            "team queue. A human specialist reviews the draft, attaches the chargeback "
            "form link, and sends it within 15 minutes."
        ),
    },
    {
        "id": 3,
        "name": "Account Closure or Critical Data Change",
        # Irreversible actions (account closure, change of registered phone/email)
        # carry high risk if processed based on a compromised or confused session.
        "trigger": (
            "Detected intent to close account, delete data, or change primary contact "
            "details (phone number, email, legal name). ConfidenceRouter always routes "
            "these to 'escalate' regardless of confidence score."
        ),
        "hitl_model": "human-in-the-loop",
        # Full stop — no automation proceeds until a human verifies identity
        # via out-of-band channel (phone call or branch visit).
        "context_needed": (
            "Customer identity documents on file, reason for closure / change, "
            "outstanding balances or linked products, last login details, verification "
            "status (KYC level)."
        ),
        "example": (
            "Customer requests to close their savings account and transfer the balance "
            "out. The AI collects the request details and informs the customer that a "
            "relationship manager will call within 2 business hours to verify identity "
            "and complete the process — nothing is actioned automatically."
        ),
    },
]


# ============================================================
# Quick tests
# ============================================================

def test_confidence_router():
    """Test ConfidenceRouter with sample scenarios."""
    router = ConfidenceRouter()

    test_cases = [
        ("Balance inquiry", 0.95, "general"),
        ("Interest rate question", 0.82, "general"),
        ("Ambiguous request", 0.55, "general"),
        ("Transfer $50,000", 0.98, "transfer_money"),
        ("Close my account", 0.91, "close_account"),
    ]

    print("Testing ConfidenceRouter:")
    print("=" * 80)
    print(f"{'Scenario':<25} {'Conf':<6} {'Action Type':<18} {'Decision':<15} {'Priority':<10} {'Human?'}")
    print("-" * 80)

    for scenario, conf, action_type in test_cases:
        decision = router.route(scenario, conf, action_type)
        print(
            f"{scenario:<25} {conf:<6.2f} {action_type:<18} "
            f"{decision.action:<15} {decision.priority:<10} "
            f"{'Yes' if decision.requires_human else 'No'}"
        )

    print("=" * 80)


def test_hitl_points():
    """Display HITL decision points."""
    print("\nHITL Decision Points:")
    print("=" * 60)
    for point in hitl_decision_points:
        print(f"\n  Decision Point #{point['id']}: {point['name']}")
        print(f"    Trigger:  {point['trigger']}")
        print(f"    Model:    {point['hitl_model']}")
        print(f"    Context:  {point['context_needed']}")
        print(f"    Example:  {point['example']}")
    print("\n" + "=" * 60)


if __name__ == "__main__":
    test_confidence_router()
    test_hitl_points()
