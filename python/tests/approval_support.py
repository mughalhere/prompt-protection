"""Fakes shared by the approval tests: a manual clock, approval-store stand-ins and a check context."""

from typing import Any

TIMESTAMP_PATTERN = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z"


class Clock:
    """A millisecond clock a test moves by hand; pass it as the ``now`` seam."""

    def __init__(self, now: int = 0) -> None:
        self.now = now

    def __call__(self) -> int:
        return self.now


class SpyStore:
    """Answers every lookup with ``state`` and records the lookups and the consumed ids."""

    def __init__(self, state: Any = None) -> None:
        self.state = state
        self.looked_up: list[tuple[Any, str]] = []
        self.consumed: list[str] = []

    def lookup(self, call: Any, canonical_args: str) -> Any:
        self.looked_up.append((call, canonical_args))
        return self.state

    def consume(self, approval_id: str) -> None:
        self.consumed.append(approval_id)


class ThrowingStore:
    def lookup(self, call: Any, canonical_args: str) -> Any:
        raise RuntimeError("store down")

    def consume(self, approval_id: str) -> None:
        return None


def base_ctx(**over: Any) -> Any:
    """A CheckContext for check_tool_call, twin of baseCtx in tests/guard/conformance.test.ts."""
    from prompt_protection.guard import DEFAULT_POLICIES, CheckContext, FlowThresholds, SourceIndex, TrustState
    from prompt_protection.logging_ import LoggingOptions

    fields: dict[str, Any] = {
        "index": SourceIndex(64, 200_000),
        "trust": TrustState(set(), ""),
        "thresholds": FlowThresholds(0.5, 0.6),
        "policies": DEFAULT_POLICIES,
        "resolve_sink": lambda _name: "network",
        "plan": None,
        "turn": 0,
        "analyze_options": {},
        "fail_mode": "closed",
        "label_of": lambda _source_id: "tool",
        "depth": 0,
        "logging": LoggingOptions(),
    }
    return CheckContext(**{**fields, **over})
