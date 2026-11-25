"""The guard presets (twin of src/guard/presets.ts, plan D2, D40; PY-19 ports the strict-only policy, e-4e4edc)."""

from collections.abc import Mapping
from typing import Any, Literal

from prompt_protection.guard._types import GuardPolicy, PolicyAction, PolicyContext
from prompt_protection.guard.policy import (
    DEFAULT_POLICIES,
    _FunctionPolicy,
    approval_expired,
    approval_mismatch,
    args_injection,
    budget_exceeded,
    envelope_invalid,
    handoff_untrusted,
    injection_source_flow,
    injection_then_sink,
    lineage_untrusted,
    payment_confirm,
    plan_violation,
    tool_drift,
    tool_unpinned,
    turn_untrusted_to_untrusted_destination,
    untrusted_to_exec,
    untrusted_to_exfil_sink,
    untrusted_to_payment,
)

__all__ = ["GuardPreset", "PERMISSIVE_POLICIES", "PRESETS", "STRICT_POLICIES", "resolve_preset"]

GuardPreset = Literal["strict", "balanced", "permissive"]


def _remap(base: GuardPolicy, action: PolicyAction) -> GuardPolicy:
    """A policy with ``base``'s id and trigger that gives ``action`` whenever ``base`` fires."""

    def evaluate(ctx: PolicyContext) -> PolicyAction | None:
        return None if base.evaluate(ctx) is None else action

    return _FunctionPolicy(base.id, evaluate)


_args_injection_block = _remap(args_injection, "block")
_payment_flag = _remap(payment_confirm, "flag")
_untrusted_to_payment_flag = _remap(untrusted_to_payment, "flag")

STRICT_POLICIES: tuple[GuardPolicy, ...] = (
    approval_mismatch,
    approval_expired,
    tool_unpinned,
    tool_drift,
    budget_exceeded,
    plan_violation,
    envelope_invalid,
    handoff_untrusted,
    injection_source_flow,
    lineage_untrusted,
    untrusted_to_exfil_sink,
    untrusted_to_exec,
    untrusted_to_payment,
    payment_confirm,
    turn_untrusted_to_untrusted_destination,
    injection_then_sink,
    _args_injection_block,
)

PERMISSIVE_POLICIES: tuple[GuardPolicy, ...] = (
    approval_mismatch,
    approval_expired,
    tool_unpinned,
    tool_drift,
    budget_exceeded,
    plan_violation,
    envelope_invalid,
    handoff_untrusted,
    injection_source_flow,
    lineage_untrusted,
    untrusted_to_exfil_sink,
    untrusted_to_exec,
    _untrusted_to_payment_flag,
    _payment_flag,
)

PRESETS: Mapping[str, Mapping[str, Any]] = {
    "balanced": {"policies": DEFAULT_POLICIES},
    "strict": {
        "policies": STRICT_POLICIES,
        "budgets": {"max_calls_per_turn": 20, "max_repeat_identical": 2, "max_depth": 3},
        "min_containment": 0.4,
    },
    "permissive": {"policies": PERMISSIVE_POLICIES, "annotations_default": "heuristic"},
}


def resolve_preset(options: Mapping[str, Any]) -> dict[str, Any]:
    """Merge the preset named by ``options["preset"]`` under the explicit options and return a new dict.

    An option that is ``None`` counts as absent and takes the preset's value. Any other value wins, falsy or not.
    The ``preset`` key stays in the result. Raises ``TypeError`` for a preset that is not in ``PRESETS``.
    """
    preset = options.get("preset")
    if preset is None:
        return dict(options)
    base = PRESETS.get(preset) if isinstance(preset, str) else None
    if base is None:
        raise TypeError(f"unknown guard preset {preset}")
    merged = {key: value for key, value in options.items() if value is not None}
    for key, value in base.items():
        merged.setdefault(key, value)
    return merged
