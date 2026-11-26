"""OpenAI Agents SDK adapter (twin of src/adapters/openai-agents.ts, plan Scope In adapter, D24, D39).

``protect(guard)`` returns one agent input guardrail, tool input and output guardrails and a
``needs_approval`` policy, all driven by one guard. Each hook is an async wrapper around a sync guard call.
Needs the ``openai-agents`` extra.
"""

import copy
import inspect
import json
from collections.abc import Awaitable, Callable, Mapping, Sequence
from typing import Any, NoReturn, TypeVar

try:
    from agents import (
        Agent,
        FunctionTool,
        GuardrailFunctionOutput,
        InputGuardrail,
        RunContextWrapper,
        ToolGuardrailFunctionOutput,
        ToolInputGuardrail,
        ToolInputGuardrailData,
        ToolOutputGuardrail,
        ToolOutputGuardrailData,
    )
except ImportError as err:
    raise ImportError(
        "prompt_protection.adapters.openai_agents needs the OpenAI Agents SDK. "
        "Install it with: pip install 'prompt-protection[openai-agents]'"
    ) from err

from prompt_protection._types import FailMode
from prompt_protection.adapters._core import denial, error_message, guarded
from prompt_protection.guard import Guard, GuardDecision, ToolCall

__all__ = ["OpenAIAgentsProtected", "protect"]

NAME = "prompt-protection"
_ToolT = TypeVar("_ToolT", bound=FunctionTool)
ApprovalPolicy = Callable[[RunContextWrapper[Any], Any, str], Awaitable[bool]]


def _reject_constant(name: str) -> NoReturn:
    raise ValueError(name)


def _parse_args(raw: str) -> object:
    """Parse tool arguments as ``JSON.parse`` does. Empty is ``{}``. Text that is not JSON is ``{"raw": text}``."""
    if not raw:
        return {}
    try:
        return json.loads(raw, parse_constant=_reject_constant)
    except (ValueError, RecursionError):
        return {"raw": raw}


def _part_text(part: object) -> str:
    text = part.get("text") if isinstance(part, Mapping) else None
    return text if isinstance(text, str) else ""


def _item_text(item: object) -> str:
    if item is None:
        raise TypeError("Cannot read properties of null (reading 'content')")
    content = item.get("content") if isinstance(item, Mapping) else None
    if isinstance(content, str):
        return content
    if isinstance(content, Sequence):
        return "\n".join(_part_text(part) for part in content)
    return ""


def _text_of(prompt: str | Sequence[object]) -> str:
    """The text of an agent input: a string, or the content of each message item joined by newlines."""
    return prompt if isinstance(prompt, str) else "\n".join(_item_text(item) for item in prompt)


class OpenAIAgentsProtected:
    """The hooks ``protect`` builds. Add them to an ``Agent``, to its tools, or pass each tool to ``wrap_tool``."""

    input_guardrails: list[InputGuardrail[Any]]
    tool_input_guardrail: ToolInputGuardrail[Any]
    tool_output_guardrail: ToolOutputGuardrail[Any]

    def __init__(self, guard: Guard, *, fail_mode: FailMode = "closed", score_input: bool = True) -> None:
        self._guard = guard
        self._fail_mode: FailMode = fail_mode
        self._score_input = score_input
        self.input_guardrails = [
            InputGuardrail(guardrail_function=self._input, name=NAME, run_in_parallel=False),
        ]
        self.tool_input_guardrail = ToolInputGuardrail(guardrail_function=self._tool_input, name=NAME)
        self.tool_output_guardrail = ToolOutputGuardrail(guardrail_function=self._tool_output, name=NAME)

    async def _input(
        self, _ctx: RunContextWrapper[Any], _agent: Agent[Any], prompt: str | Sequence[object]
    ) -> GuardrailFunctionOutput:
        def run() -> GuardrailFunctionOutput:
            text = _text_of(prompt)
            if not self._score_input:
                self._guard.trust(text)
                return GuardrailFunctionOutput(output_info={"action": "allow"}, tripwire_triggered=False)
            result = self._guard.analyze_user_turn(text)
            info = {"action": result.action, "score": result.score, "categories": result.categories}
            return GuardrailFunctionOutput(output_info=info, tripwire_triggered=result.action == "block")

        def fail(err: Exception, tripped: bool) -> GuardrailFunctionOutput:
            return GuardrailFunctionOutput(output_info={"error": error_message(err)}, tripwire_triggered=tripped)

        return guarded(run, self._fail_mode, lambda err: fail(err, True), lambda err: fail(err, False))

    async def _tool_input(self, data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
        def run() -> ToolGuardrailFunctionOutput:
            context = data.context
            call = ToolCall(
                tool_name=context.tool_name,
                args=_parse_args(context.tool_arguments),
                tool_call_id=context.tool_call_id,
            )
            decision = self._guard.check_tool_call(call)
            if decision.action == "block":
                return ToolGuardrailFunctionOutput.reject_content(denial(decision).message)
            return ToolGuardrailFunctionOutput.allow({"action": decision.action, "reasons": decision.reasons})

        return guarded(
            run,
            self._fail_mode,
            lambda err: ToolGuardrailFunctionOutput.reject_content(
                f"prompt-protection: guard error ({error_message(err)})"
            ),
            lambda _err: ToolGuardrailFunctionOutput.allow(),
        )

    async def _tool_output(self, data: ToolOutputGuardrailData) -> ToolGuardrailFunctionOutput:
        def run() -> ToolGuardrailFunctionOutput:
            source = self._guard.taint(data.context.tool_name, data.output, id=data.context.tool_call_id)
            return ToolGuardrailFunctionOutput.allow({"sourceId": source.id, "injection": source.injection.action})

        return guarded(
            run,
            self._fail_mode,
            lambda err: ToolGuardrailFunctionOutput.reject_content(
                f"prompt-protection: taint error ({error_message(err)})"
            ),
            lambda _err: ToolGuardrailFunctionOutput.allow(),
        )

    def needs_approval(self, tool_name: str) -> ApprovalPolicy:
        """The ``needs_approval`` policy for one tool: true when the guard says confirm, or errors under ``closed``.

        The SDK does not pass the tool name to the policy, so each policy is bound to one tool.
        """

        async def policy(_ctx: RunContextWrapper[Any], params: Any, call_id: str | None = None) -> bool:
            return guarded(
                lambda: (
                    self._guard.check_tool_call(
                        ToolCall(tool_name=tool_name, args=params, tool_call_id=call_id)
                    ).requires_confirmation
                ),
                self._fail_mode,
                lambda _err: True,
                lambda _err: False,
            )

        return policy

    def wrap_tool(self, tool: _ToolT) -> _ToolT:
        """Return a copy of a ``FunctionTool`` carrying all three hooks. Existing guardrails run first and stay."""
        prior = tool.needs_approval
        ours = self.needs_approval(tool.name)

        async def bound(ctx: RunContextWrapper[Any], params: Any, call_id: str) -> bool:
            if await ours(ctx, params, call_id):
                return True
            if callable(prior):
                answer = prior(ctx, params, call_id)
                return bool(await answer if inspect.isawaitable(answer) else answer)
            return prior is True

        wrapped = copy.copy(tool)
        wrapped.needs_approval = bound
        wrapped.tool_input_guardrails = [*(tool.tool_input_guardrails or []), self.tool_input_guardrail]
        wrapped.tool_output_guardrails = [*(tool.tool_output_guardrails or []), self.tool_output_guardrail]
        return wrapped

    def last_decision(self, call_id: str) -> GuardDecision | None:
        """The most recent decision the guard made for this tool call id."""
        return self._guard.last_decision(call_id)


def protect(guard: Guard, *, fail_mode: FailMode = "closed", score_input: bool = True) -> OpenAIAgentsProtected:
    """Build the OpenAI Agents hooks for ``guard``.

    ``fail_mode`` is the verdict when a hook throws an ``Exception``: ``closed`` rejects, ``open`` allows.
    ``score_input`` scores the agent's text input through the guard's session. When false it only trusts it.
    """
    return OpenAIAgentsProtected(guard, fail_mode=fail_mode, score_input=score_input)
