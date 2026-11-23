"""The error raised when the guard blocks a tool call (twin of src/guard/errors.ts, plan D1)."""

from prompt_protection.guard._types import BlockedDecision

__all__ = ["ToolCallBlockedError"]


class ToolCallBlockedError(Exception):
    """Raised by the wrap and verify paths when the guard blocks a tool call."""

    def __init__(self, decision: BlockedDecision) -> None:
        policy = "guard" if decision.policy is None else decision.policy
        super().__init__(
            f'prompt-protection: tool call "{decision.tool_name}" blocked by {policy} '
            f"(sink {decision.sink}, {len(decision.flows)} flow(s))"
        )
        self.decision = decision
