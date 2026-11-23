"""The tool-call guard (twin of src/guard/index.ts); later tasks add the rest of its surface."""

from prompt_protection.guard.errors import ToolCallBlockedError
from prompt_protection.guard.policy import DEFAULT_POLICIES, evaluate_policies
from prompt_protection.guard.reasons import DECISION_REASONS, is_decision_reason
from prompt_protection.guard.sinks import EXEC_SINKS, EXFIL_SINKS, create_sink_resolver, default_sink

__all__ = [
    "DECISION_REASONS",
    "DEFAULT_POLICIES",
    "EXEC_SINKS",
    "EXFIL_SINKS",
    "ToolCallBlockedError",
    "create_sink_resolver",
    "default_sink",
    "evaluate_policies",
    "is_decision_reason",
]
