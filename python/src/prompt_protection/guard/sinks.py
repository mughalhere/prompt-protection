"""Tool-name sink heuristics (twin of src/guard/sinks.ts, plan D1, D2)."""

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from prompt_protection.guard._types import SinkKind, SinkResolver

__all__ = ["DEFAULT_SINK_PATTERNS", "EXEC_SINKS", "EXFIL_SINKS", "SinkPattern", "create_sink_resolver", "default_sink"]

# JS /i without /u folds ASCII only, and JS $ ends the string, so: re.ASCII and \Z, never $.
_FLAGS = re.ASCII | re.IGNORECASE


@dataclass(frozen=True)
class SinkPattern:
    sink: SinkKind
    pattern: re.Pattern[str]


def _entry(sink: SinkKind, source: str) -> SinkPattern:
    return SinkPattern(sink, re.compile(source, _FLAGS))


# Read-only verbs come first so fetch_url and get_record stay none; a bare send falls to network.
DEFAULT_SINK_PATTERNS: tuple[SinkPattern, ...] = (
    _entry(
        "none",
        r"^(?:get|read|fetch|list|search|query|lookup|find|view|browse|load|open|reply_to_user|final_answer"
        r"|respond|answer)(?:_|\Z)",
    ),
    _entry("network", r"http|curl|webhook|socket|dns"),
    _entry("payment", r"pay|payment|charge|transfer|checkout|purchase|refund|billing|invoice|wire|donat"),
    _entry("exec", r"exec|shell|bash|command|cmd|terminal|spawn|eval|script|run(?:_|\Z)|sudo|process"),
    _entry("email", r"e?mail|smtp|gmail|outlook"),
    _entry(
        "message",
        r"slack|discord|teams|sms|whatsapp|telegram|signal|imessage|message|msg|chat|dm(?:_|\Z)|comment|tweet"
        r"|post(?:_|\Z)|publish|notify|notification|broadcast",
    ),
    _entry(
        "file-write",
        r"write|save|create|delete|remove|append|upload|edit|update|move|rename|mkdir|rm(?:_|\Z)|unlink"
        r"|put_file|store|persist",
    ),
    _entry(
        "network",
        r"http|url|request|curl|webhook|api|send|submit|call|dispatch|push|sync|export|download|navigate|visit"
        r"|connect|socket|dns",
    ),
)


def default_sink(tool_name: str) -> SinkKind:
    """Classify a tool name with the default heuristics; an unknown name is ``none``."""
    for entry in DEFAULT_SINK_PATTERNS:
        if entry.pattern.search(tool_name):
            return entry.sink
    return "none"


def create_sink_resolver(
    sinks: Mapping[str, SinkKind | None] | SinkResolver | None = None,
) -> Callable[[str], SinkKind]:
    """Build a resolver from the ``sinks`` option: explicit entries win and the defaults fill gaps."""
    if callable(sinks):
        resolve = sinks

        def from_function(tool_name: str) -> SinkKind:
            answer = resolve(tool_name)
            return default_sink(tool_name) if answer is None else answer

        return from_function
    table: Mapping[str, SinkKind | None] = {} if sinks is None else sinks

    def from_mapping(tool_name: str) -> SinkKind:
        explicit = table.get(tool_name)
        return default_sink(tool_name) if explicit is None else explicit

    return from_mapping


# Sinks where untrusted data leaving the process is the concern.
EXFIL_SINKS: frozenset[SinkKind] = frozenset({"network", "email", "message", "unknown"})
# Sinks where untrusted data can change local state or run code.
EXEC_SINKS: frozenset[SinkKind] = frozenset({"exec", "file-write", "unknown"})
