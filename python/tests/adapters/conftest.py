"""Fixtures for the OpenAI Agents adapter tests (PY-24). They drive the adapter's hooks through the real SDK types."""

import asyncio
from collections.abc import Callable
from typing import Any

import pytest
from agents import Agent, RunContextWrapper, ToolInputGuardrailData, ToolOutputGuardrailData, Usage
from agents.tool_context import ToolContext

from prompt_protection.guard import Guard, create_guard


def tool_context(name: str, arguments: str, call_id: str) -> Any:
    return ToolContext(context=None, usage=Usage(), tool_name=name, tool_call_id=call_id, tool_arguments=arguments)


@pytest.fixture
def guard() -> Guard:
    return create_guard()


@pytest.fixture
def agent() -> Agent[Any]:
    return Agent(name="test-agent")


@pytest.fixture
def run_input_guardrail(agent: Agent[Any]) -> Callable[[Any, Any], Any]:
    """Run an ``InputGuardrail`` on a prompt and return its ``GuardrailFunctionOutput``."""

    def run(guardrail: Any, prompt: Any) -> Any:
        return asyncio.run(guardrail.run(agent, prompt, RunContextWrapper(context=None))).output

    return run


@pytest.fixture
def run_tool_input(agent: Agent[Any]) -> Callable[..., Any]:
    """Run a tool input guardrail on a call, giving the ``ToolGuardrailFunctionOutput``."""

    def run(guardrail: Any, name: str, args: str = "{}", call_id: str = "c1") -> Any:
        data = ToolInputGuardrailData(context=tool_context(name, args, call_id), agent=agent)
        return asyncio.run(guardrail.run(data))

    return run


@pytest.fixture
def run_tool_output(agent: Agent[Any]) -> Callable[..., Any]:
    """Run a tool output guardrail on a result, giving the ``ToolGuardrailFunctionOutput``."""

    def run(guardrail: Any, name: str, output: Any, call_id: str = "c1") -> Any:
        data = ToolOutputGuardrailData(context=tool_context(name, "{}", call_id), agent=agent, output=output)
        return asyncio.run(guardrail.run(data))

    return run
