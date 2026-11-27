"""Stable decision reason codes (twin of src/guard/reasons.ts)."""

__all__ = ["DECISION_REASONS", "DecisionReason", "is_decision_reason"]

DecisionReason = str

DECISION_REASONS: tuple[DecisionReason, ...] = (
    "plan-violation",
    "injection-source-flow",
    "untrusted-to-exfil-sink",
    "untrusted-to-exec",
    "untrusted-to-payment",
    "payment-confirm",
    "injection-then-sink",
    "args-injection",
    "approval-mismatch",
    "approval-expired",
    "approved",
    "lineage-untrusted",
    "tool-unpinned",
    "tool-drift",
    "budget-exceeded",
    "envelope-invalid",
    "handoff-untrusted",
    "internal-error",
)

_KNOWN = frozenset(DECISION_REASONS)


def is_decision_reason(value: str) -> bool:
    """Return whether ``value`` is exactly one of the reason codes a guard can emit."""
    return value in _KNOWN
