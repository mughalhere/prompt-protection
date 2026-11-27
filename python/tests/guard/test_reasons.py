"""RED tests for prompt_protection.guard.reasons (twin of src/guard/reasons.ts: Node is the oracle)."""

import pytest

from prompt_protection.guard.reasons import DECISION_REASONS, is_decision_reason

# node -e "console.log(JSON.stringify(require('./dist/guard/index.cjs').DECISION_REASONS))"
JS_DECISION_REASONS = [
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
]

# Node: require('./dist/guard/index.cjs').isDecisionReason(value) is false for each value below.
NON_MEMBERS = [
    pytest.param("", id="empty"),
    pytest.param("x", id="unknown-code"),
    pytest.param("Approved", id="case-differs"),
    pytest.param(" approved", id="leading-space"),
    pytest.param("approved ", id="trailing-space"),
    pytest.param("approved\n", id="trailing-newline"),
    pytest.param("turn-untrusted-to-untrusted-destination", id="strict-preset-policy-id-is-not-a-reason"),
]


def test_decision_reasons_equal_the_js_list_in_order() -> None:
    assert list(DECISION_REASONS) == JS_DECISION_REASONS


@pytest.mark.parametrize("reason", JS_DECISION_REASONS)
def test_is_decision_reason_accepts_every_member(reason: str) -> None:
    assert is_decision_reason(reason) is True


@pytest.mark.parametrize("value", NON_MEMBERS)
def test_is_decision_reason_rejects_everything_else(value: str) -> None:
    assert is_decision_reason(value) is False
