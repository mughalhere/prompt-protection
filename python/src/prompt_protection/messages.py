"""Chat transcripts to analysable text, ported from src/messages.ts."""

from collections.abc import Mapping, Sequence
from typing import Any, TypeGuard

from prompt_protection._js import js_trim
from prompt_protection._types import AnalyzeRoles, ChatMessage, PromptInput

__all__ = ["flatten_chat_messages", "is_chat_message_array", "resolve_prompt_input"]

_DEFAULT_UNTRUSTED_ROLES = frozenset({"user", "tool", "function"})
_BAD_INPUT = "prompt-protection: expected a string or an array of { role, content } messages"


def is_chat_message_array(value: object) -> TypeGuard[list[ChatMessage]]:
    """Return whether ``value`` is a non-empty list of ``{role, content}`` dicts with string values."""
    if not isinstance(value, (list, tuple)) or not value:
        return False
    return all(
        isinstance(item, Mapping) and isinstance(item.get("role"), str) and isinstance(item.get("content"), str)
        for item in value
    )


def _roles_to_scan(analyze_roles: AnalyzeRoles | None) -> frozenset[str] | None:
    if analyze_roles == "all":
        return None
    if isinstance(analyze_roles, (list, tuple)) and analyze_roles:
        return frozenset(role.lower() for role in analyze_roles)
    return _DEFAULT_UNTRUSTED_ROLES


def flatten_chat_messages(messages: Sequence[Mapping[str, Any]], analyze_roles: AnalyzeRoles | None = None) -> str:
    """Join the trimmed, non-empty contents with newlines; by default only user, tool and function turns count."""
    roles = _roles_to_scan(analyze_roles)
    selected = list(messages) if roles is None else [m for m in messages if m["role"].lower() in roles]
    source = selected or messages
    return "\n".join(content for content in (js_trim(m["content"]) for m in source) if content)


def resolve_prompt_input(input: PromptInput | object, analyze_roles: AnalyzeRoles | None = None) -> str:  # noqa: A002
    """Return the text to analyse. Raises ``TypeError`` unless ``input`` is a string or a chat message list."""
    if isinstance(input, str):
        return input
    if not is_chat_message_array(input):
        raise TypeError(_BAD_INPUT)
    return flatten_chat_messages(input, analyze_roles)
