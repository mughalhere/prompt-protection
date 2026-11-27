"""Option and input types shared by the analyze API (twin of the matching part of src/types.ts)."""

import re
from collections.abc import Mapping, Sequence
from typing import Any, Literal, TypedDict

__all__ = ["AnalyzeRoles", "ChatMessage", "CustomRule", "FailMode", "MlMode", "PromptInput", "Severity"]

Severity = Literal["critical", "high", "medium", "low", "safe"]
FailMode = Literal["closed", "open"]
MlMode = Literal["off", "escalate", "hybrid"]
AnalyzeRoles = Literal["all"] | Sequence[str]


class ChatMessage(TypedDict):
    role: str
    content: str


class _CustomRuleRequired(TypedDict):
    id: str
    category: str
    pattern: re.Pattern[str]
    weight: float
    description: str


class CustomRule(_CustomRuleRequired, total=False):
    precision: Literal["high", "medium", "low"]
    mappings: Mapping[str, Any]
    origin: Mapping[str, Any]


PromptInput = str | Sequence[ChatMessage]
