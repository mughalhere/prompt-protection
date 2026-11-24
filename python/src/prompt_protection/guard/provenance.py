"""Argument-to-source flow detection (twin of src/guard/provenance.ts, plan D1, D2, D32, D40).

Lengths and slices count UTF-16 code units, as the JS ``.length`` and ``.slice`` do. Postings are
dicts, and ``ShingleSet`` iterates in insertion order, so results follow the order JS ``Map`` and ``Set`` give.
"""

import copy
import math
import re
import sys
from collections import OrderedDict, deque
from collections.abc import Hashable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Protocol, TypeVar, cast

from prompt_protection._js import JS_WHITESPACE, js_number_str, js_trim, utf16_len, utf16_slice
from prompt_protection.canonical import _json_string
from prompt_protection.encoding import decode_obfuscation
from prompt_protection.identifiers import extract_identifiers
from prompt_protection.normalizer import normalize
from prompt_protection.shingle import WORD_SHINGLE, OrderedHashSet, ShingleSet, build_shingles, containment
from prompt_protection.unicode import normalize_unicode

__all__ = [
    "DESTINATION_KEYS",
    "DESTINATION_KINDS",
    "IDENTIFIER_STRENGTH",
    "MIN_CONTENT_CHARS",
    "MIN_CONTENT_WORDS",
    "MIN_DESTINATION_CHARS",
    "MIN_EXACT_CHARS",
    "MIN_URL_PATH_CHARS",
    "ArgLeaf",
    "ContainmentScore",
    "Flow",
    "FlowReport",
    "FlowThresholds",
    "IndexableSource",
    "IndexedSource",
    "SourceIndex",
    "TrustState",
    "collect_leaves",
    "containment_of",
    "defang",
    "detect_flows",
    "identifier_values",
    "key_of",
    "stringify_value",
    "url_path_of",
]

MIN_EXACT_CHARS = 12
MIN_CONTENT_WORDS = WORD_SHINGLE + 2
MIN_CONTENT_CHARS = 32
IDENTIFIER_STRENGTH = 0.9
MIN_DESTINATION_CHARS = 4
MIN_URL_PATH_CHARS = 12
_MAX_LEAF_DEPTH = 32
_MAX_DEPTH = 300
_PREVIEW_UNITS = 64

DESTINATION_KINDS: frozenset[str] = frozenset({"url", "host", "email", "ipv4", "phone", "handle"})
DESTINATION_KEYS: frozenset[str] = frozenset(
    (
        "to cc bcc recipient recipients user userid channel address email url endpoint host hostname target "
        "destination dest iban account accountid payee payeeurl phone number processor webhook"
    ).split()
)

# JS /i without /u folds ASCII only, \s is the JS whitespace set and $ ends the string.
_DEFANG_RE = re.compile(
    r"\bh(?:xx|XX)ps?(?=://)|\[\.\]|\(\.\)|"
    + JS_WHITESPACE
    + r"\(?dot\)?"
    + JS_WHITESPACE
    + r"(?=[a-z0-9-]+(?:"
    + JS_WHITESPACE
    + r"|\Z|[/?#]))",
    re.ASCII | re.IGNORECASE,
)
_XX_RE = re.compile(r"xx", re.ASCII | re.IGNORECASE)
_INDEX_SUFFIX_RE = re.compile(r"\[[0-9]+\]\Z")
_NOT_LETTER_RE = re.compile(r"[^a-z]")
_ARRAY_INDEX_RE = re.compile(r"(?:0|[1-9][0-9]*)\Z", re.ASCII)
_MAX_ARRAY_INDEX = 2**32 - 2
_QUERY_OR_FRAGMENT_RE = re.compile(r"[?#]")

_K = TypeVar("_K", bound=Hashable)


class _NoJsonForm(Exception):
    """A value ``JSON.stringify`` would throw on: a cycle, too deep, or a type JSON cannot hold."""


def _number_text(value: float, nested: bool) -> str:
    try:
        number = float(value)
    except OverflowError:
        raise _NoJsonForm from None
    return "null" if nested and not math.isfinite(number) else js_number_str(number)


def _js_key_order(keys: list[str]) -> list[str]:
    """Order keys as a JS object lists them: canonical array indexes ascending, then insertion order."""
    indexes = {k for k in keys if _ARRAY_INDEX_RE.match(k) and int(k) <= _MAX_ARRAY_INDEX}
    return sorted(indexes, key=int) + [k for k in keys if k not in indexes]


def _json_text(value: object, seen: set[int], depth: int = 0) -> str:
    """Return compact JSON text. A container deeper than ``_MAX_DEPTH`` has no JSON form (the root is depth 0)."""
    if value is None:
        return "null"
    if isinstance(value, str):
        return _json_string(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _number_text(value, True)
    if not isinstance(value, (list, tuple, Mapping)) or id(value) in seen or depth > _MAX_DEPTH:
        raise _NoJsonForm
    seen.add(id(value))
    parts: list[str] = []
    try:
        if isinstance(value, Mapping):
            pairs = {k if isinstance(k, str) else _python_str(k): item for k, item in value.items()}
            for key in _js_key_order(list(pairs)):
                parts.append(f"{_json_string(key)}:{_json_text(pairs[key], seen, depth + 1)}")
            return "{" + ",".join(parts) + "}"
        for item in value:
            parts.append(_json_text(item, seen, depth + 1))
        return "[" + ",".join(parts) + "]"
    finally:
        seen.discard(id(value))


_DEFAULT_INT_DIGIT_LIMIT = 4300
_CONTAINERS = (list, tuple, dict, set, frozenset, deque)
_STRUCTURED_REPRS = frozenset(kind.__repr__ for kind in (list, tuple, dict, set, frozenset, deque, OrderedDict))
_UNSET_SLOTS = ("__dict__", "__weakref__")
_DEPTH_MARKER = "<too deep>"


@lru_cache(maxsize=8)
def _power_of_ten(digits: int) -> int:
    return int(10**digits)


def _digit_limit() -> int:
    """Return N, the most digits an int prints with: min(4300, the interpreter's limit), and 4300 if that is 0."""
    getter = getattr(sys, "get_int_max_str_digits", None)
    limit = getter() if getter is not None else 0
    return min(_DEFAULT_INT_DIGIT_LIMIT, limit) if limit else _DEFAULT_INT_DIGIT_LIMIT


def _over_limit(value: int, limit: int) -> bool:
    bound = _power_of_ten(limit)
    return not -bound < value < bound


def _own_repr(value: object, limit: int) -> str | None:
    """Return ``repr(value)``, or ``None`` when it raises or holds a run of over ``limit`` digits (3.10 prints one)."""
    try:
        text = repr(value)
    except Exception:
        return None
    return None if re.search(f"[0-9]{{{limit + 1}}}", text) else text


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _fields_of(value: object) -> list[tuple[object, object]]:
    """Return an object's fields: set ``__slots__`` (base classes first), then its ``__dict__`` items."""
    kind = type(value)
    out: list[tuple[object, object]] = []
    for klass in reversed(kind.__mro__):
        slots = klass.__dict__.get("__slots__", ())
        for name in (slots,) if isinstance(slots, str) else slots:
            if name in _UNSET_SLOTS:
                continue
            stored = (
                f"_{klass.__name__.lstrip('_')}{name}" if name.startswith("__") and not name.endswith("__") else name
            )
            try:
                out.append((name, klass.__dict__[stored].__get__(value, kind)))
            except (KeyError, AttributeError):
                continue
    instance_dict = getattr(value, "__dict__", None)
    if isinstance(instance_dict, dict):
        out.extend(instance_dict.items())
    return out


def _named(name: str, pairs: Iterable[tuple[object, object]], limit: int, path: set[int]) -> str:
    parts: list[str] = []
    for key, item in pairs:
        shown = key if isinstance(key, str) else _render(key, limit, path)
        parts.append(f"{shown}={_render(item, limit, path)}")
    return f"{name}({', '.join(parts)})"


def _container_text(value: Any, limit: int, path: set[int]) -> str:
    """Render a container over plain loops, so each level of nesting costs two Python frames."""
    kind = type(value)
    is_dict = isinstance(value, dict)
    if isinstance(value, tuple) and hasattr(kind, "_fields"):
        return _named(kind.__name__, zip(kind._fields, value, strict=False), limit, path)
    parts: list[str] = []
    if is_dict:
        for key, item in value.items():
            parts.append(f"{_render(key, limit, path)}: {_render(item, limit, path)}")
    else:
        for item in value:
            parts.append(_render(item, limit, path))
    body = ", ".join(parts)
    if isinstance(value, deque):
        tail = "" if value.maxlen is None else f", maxlen={value.maxlen}"
        return f"{kind.__name__}([{body}]{tail})"
    if is_dict:
        if not isinstance(value, OrderedDict):
            return "{" + body + "}"
        return f"{kind.__name__}({{{body}}})" if value else f"{kind.__name__}()"
    if isinstance(value, list):
        return "[" + body + "]"
    if isinstance(value, tuple):
        return "(" + body + ("," if len(value) == 1 else "") + ")"
    inner = "{" + body + "}" if value else ""
    return (inner or "set()") if kind is set else f"{kind.__name__}({inner})"


def _revisit_text(value: object) -> str:
    kind = type(value)
    if not isinstance(value, _CONTAINERS) or hasattr(kind, "_fields"):
        return f"{kind.__name__}(...)"
    if isinstance(value, tuple):
        return "(...)"
    return "[...]" if isinstance(value, (list, deque)) else "{...}"


def _range_text(value: range, limit: int, path: set[int]) -> str:
    """Print a range as Python does (step 1 left out), with each over-limit bound as hex."""
    bounds = [_render(bound, limit, path) for bound in (value.start, value.stop)]
    if value.step != 1:
        bounds.append(_render(value.step, limit, path))
    return f"range({', '.join(bounds)})"


def _is_scalar(value: object, kind: type) -> bool:
    return kind.__module__ == "builtins" and not isinstance(value, _CONTAINERS)


def _render(value: object, limit: int, path: set[int], top: bool = False) -> str:
    """Return Python's ``str()`` of ``value``, with each over-limit int as hex and a plain object as its fields.

    ``top`` keeps a type's own ``__str__``. Deeper, Python's ``repr()`` shows, as in a list's ``str()``.
    An object met again on the way down prints ``Name(...)``, or ``[...]`` for a list, and the walk ends.
    A container or object deeper than 300 (the root is depth 0) prints as ``<too deep>``. A builtin scalar stays.
    """
    if _is_int(value):
        return hex(cast(int, value)) if _over_limit(cast(int, value), limit) else repr(value)
    kind = type(value)
    own_str = kind.__str__ is not object.__str__
    if top and own_str:
        return str(value)
    if len(path) > _MAX_DEPTH and not _is_scalar(value, kind):
        return _DEPTH_MARKER
    if id(value) in path:
        return _revisit_text(value)
    path.add(id(value))
    try:
        structured = isinstance(value, _CONTAINERS) and (kind.__repr__ in _STRUCTURED_REPRS or hasattr(kind, "_fields"))
        if structured:
            return _container_text(value, limit, path)
        if kind.__repr__ is object.__repr__:
            return str(value) if own_str else _named(kind.__name__, _fields_of(value), limit, path)
        if kind is range:
            return _range_text(cast(range, value), limit, path)
        if _is_scalar(value, kind):
            return repr(value)
        text = _own_repr(value, limit)
        if text is not None:
            return text
        if isinstance(value, _CONTAINERS):
            return _container_text(value, limit, path)
        fields = _fields_of(value)
        return _named(kind.__name__, fields, limit, path) if fields else repr(value)
    finally:
        path.discard(id(value))


def _python_str(value: object) -> str:
    return _render(value, _digit_limit(), set(), True)


def stringify_value(value: object) -> str:
    """Return the text a tool result is scanned as: a string as is, ``None`` as ``""``, else compact JSON.

    An int or float is a JS number. Python has no bigint, so an int too large for a float is one.
    A value with no JSON form (a cycle, a set, bytes, an object) falls back to Python's ``str()``.
    There an int of more than N digits prints as ``hex()``, with N the smaller of 4300 and
    ``sys.get_int_max_str_digits()`` (4300 when that is 0 or absent), and every other value stays visible.
    An object with no ``__str__`` or ``__repr__`` of its own prints as ``Name(field=value, ...)``.
    """
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    if _is_int(value) and _over_limit(cast(int, value), _digit_limit()):
        return hex(cast(int, value))
    try:
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return _number_text(value, False)
        return _json_text(value, set())
    except (_NoJsonForm, RecursionError):
        pass
    try:
        return _python_str(value)
    except Exception:
        return object.__repr__(value)


def defang(text: str) -> str:
    """Undo common URL defanging (``hxxps://``, ``evil[.]com``, ``evil (dot) com``)."""
    return _DEFANG_RE.sub(
        lambda m: _XX_RE.sub("tt", m.group(), count=1) if m.group().lower().startswith("hxx") else ".", text
    )


def key_of(path: str) -> str:
    """Return the last path segment, lowercased and stripped to letters (``args.items[0].to`` gives ``to``)."""
    tail = _INDEX_SUFFIX_RE.sub("", path[path.rfind(".") + 1 :], count=1)
    return _NOT_LETTER_RE.sub("", tail.lower())


def url_path_of(url: str) -> str | None:
    """Return the path of a URL when it is specific enough to correlate on its own, else ``None``."""
    scheme = url.find("//")
    after_scheme = url[scheme + 2 :] if scheme != -1 else utf16_slice(url, 1)
    slash = after_scheme.find("/")
    if slash == -1:
        return None
    path = _QUERY_OR_FRAGMENT_RE.split(after_scheme[slash:], maxsplit=1)[0]
    segments = [segment for segment in path.split("/") if segment]
    if not segments:
        return None
    return path if len(segments) >= 2 or utf16_len(path) >= MIN_URL_PATH_CHARS else None


def _decoded_text(text: str) -> str:
    return decode_obfuscation(normalize_unicode(text))


def identifier_values(text: str, derived: bool = True) -> dict[str, str]:
    """Map each lowercased identifier value to its kind over the raw, defanged and decoded forms of ``text``.

    With ``derived`` (sources and trusted text) a URL also yields its specific path and an email its
    domain, so a destination split across arguments still correlates. Argument leaves are indexed
    without derivation. The first kind seen for a value wins, and the dict keeps first-seen order.
    """
    out: dict[str, str] = {}
    defanged = defang(text)
    variants = [text, _decoded_text(text)] if defanged == text else [text, defanged, _decoded_text(defanged)]
    for variant in variants:
        for found in extract_identifiers(variant):
            value = found.value.lower()
            out.setdefault(value, found.kind)
            if not derived:
                continue
            if found.kind == "url":
                path = url_path_of(value)
                if path is not None:
                    out.setdefault(path, "path")
            elif found.kind == "email":
                domain = value[value.rfind("@") + 1 :]
                if domain:
                    out.setdefault(domain, "host")
    return out


@dataclass(frozen=True, slots=True)
class ArgLeaf:
    path: str
    value: str


def _walk(args: Any, path: str, out: list[ArgLeaf], depth: int) -> None:
    if depth > _MAX_LEAF_DEPTH:
        return
    if isinstance(args, str):
        out.append(ArgLeaf(path, args))
    elif isinstance(args, (list, tuple)):
        for i, item in enumerate(args):
            _walk(item, f"{path}[{i}]", out, depth + 1)
    elif isinstance(args, Mapping):
        for raw_key, item in args.items():
            key = raw_key if isinstance(raw_key, str) else str(raw_key)
            out.append(ArgLeaf(f"{path}.{key}", key))
            _walk(item, f"{path}.{key}", out, depth + 1)


def collect_leaves(args: object) -> list[ArgLeaf]:
    """Deep-walk an argument value, collecting every string leaf and every mapping key. Stops below 32 levels."""
    out: list[ArgLeaf] = []
    _walk(args, "args", out, 0)
    return out


@dataclass(slots=True)
class ContainmentScore:
    word: float
    char: float


def containment_of(needle: str, hay: str) -> ContainmentScore:
    """Return the word and char containment of ``needle`` in ``hay``, both normalized first."""
    found = containment(normalize(needle).normalized, normalize(hay).normalized)
    return ContainmentScore(found.word, found.char)


class IndexableSource(Protocol):
    """The attributes ``SourceIndex`` and ``detect_flows`` read from a registered source."""

    id: str
    tool: str
    text: str
    normalized: str
    shingles: ShingleSet
    identifiers: Mapping[str, str]


class IndexedSource(IndexableSource, Protocol):
    """A registered source. The hash sets are kept so eviction can remove its postings without a rebuild."""

    word_hashes: OrderedHashSet
    char_hashes: OrderedHashSet


_Postings = dict[_K, dict[str, None]]


def _post(postings: _Postings[_K], key: _K, source_id: str) -> None:
    postings.setdefault(key, {})[source_id] = None


def _unpost(postings: _Postings[_K], key: _K, source_id: str) -> None:
    ids = postings.get(key)
    if ids is None:
        return
    ids.pop(source_id, None)
    if not ids:
        del postings[key]


def _count_hits(postings: _Postings[int], needle: Iterable[int]) -> dict[str, int]:
    hits: dict[str, int] = {}
    for shingle in needle:
        for source_id in postings.get(shingle, ()):
            hits[source_id] = hits.get(source_id, 0) + 1
    return hits


class SourceIndex:
    """Inverted index over registered sources: shingle hash and identifier to source ids.

    ``add`` stores a shallow copy of the source with ``word_hashes`` and ``char_hashes`` set, so the
    source must accept new attributes. The copy is what ``get`` and ``sources`` return.
    """

    def __init__(self, max_sources: int, max_source_chars: int) -> None:
        self._max_sources = max_sources
        self._max_source_chars = max_source_chars
        self._words: _Postings[int] = {}
        self._chars: _Postings[int] = {}
        self._ids: _Postings[str] = {}
        self._by_id: dict[str, IndexedSource] = {}
        self._order: list[IndexedSource] = []
        self._total_chars = 0

    @property
    def sources(self) -> Sequence[IndexedSource]:
        return self._order

    def get(self, source_id: str) -> IndexedSource | None:
        return self._by_id.get(source_id)

    def has(self, source_id: str) -> bool:
        return source_id in self._by_id

    def add(self, source: IndexableSource) -> IndexedSource:
        indexed = cast(IndexedSource, copy.copy(source))
        indexed.word_hashes = source.shingles.words
        indexed.char_hashes = source.shingles.chars
        self._order.append(indexed)
        self._by_id[indexed.id] = indexed
        self._total_chars += utf16_len(indexed.text)
        for shingle in indexed.word_hashes:
            _post(self._words, shingle, indexed.id)
        for shingle in indexed.char_hashes:
            _post(self._chars, shingle, indexed.id)
        for value in indexed.identifiers:
            _post(self._ids, value, indexed.id)
        self._evict()
        return indexed

    def clear(self) -> None:
        self._words.clear()
        self._chars.clear()
        self._ids.clear()
        self._by_id.clear()
        self._order.clear()
        self._total_chars = 0

    def _evict(self) -> None:
        while self._order and (len(self._order) > self._max_sources or self._total_chars > self._max_source_chars):
            victim = self._order.pop(0)
            self._by_id.pop(victim.id, None)
            self._total_chars -= utf16_len(victim.text)
            for shingle in victim.word_hashes:
                _unpost(self._words, shingle, victim.id)
            for shingle in victim.char_hashes:
                _unpost(self._chars, shingle, victim.id)
            for value in victim.identifiers:
                _unpost(self._ids, value, victim.id)

    def identifier_hits(self, values: Iterable[str]) -> dict[str, tuple[str, ...]]:
        """Map each value some source holds to the ids of every source holding it."""
        out: dict[str, tuple[str, ...]] = {}
        for value in values:
            hit = self._ids.get(value)
            if hit:
                out[value] = tuple(hit)
        return out

    def containment(self, needle: ShingleSet) -> dict[str, ContainmentScore]:
        """Map each source id sharing a shingle with ``needle`` to its word and char containment."""
        out: dict[str, ContainmentScore] = {}
        for source_id, hits in _count_hits(self._words, needle.words).items():
            out[source_id] = ContainmentScore(hits / len(needle.words), 0)
        for source_id, hits in _count_hits(self._chars, needle.chars).items():
            entry = out.setdefault(source_id, ContainmentScore(0, 0))
            entry.char = hits / len(needle.chars)
        return out


@dataclass(frozen=True, slots=True)
class FlowThresholds:
    min_containment: float
    min_char_containment: float


@dataclass(slots=True)
class TrustState:
    """``identifiers`` holds the lowercased values the user authored. ``text`` is the normalized user text."""

    identifiers: set[str]
    text: str


@dataclass(frozen=True, slots=True)
class Flow:
    """``identifier_kind`` is ``None`` for ``exact`` and ``content`` flows and ``handle`` for a verbatim destination."""

    kind: str
    source_id: str
    source_tool: str
    path: str
    value: str
    strength: float
    identifier_kind: str | None = None


@dataclass(frozen=True, slots=True)
class FlowReport:
    flows: list[Flow]
    untrusted_leaves: list[ArgLeaf]
    destination_trusted: bool


def _is_trusted(value: str, trust: TrustState) -> bool:
    return value in trust.identifiers or (bool(trust.text) and value in trust.text)


def _preview(text: str) -> str:
    return text if utf16_len(text) <= _PREVIEW_UNITS else utf16_slice(text, 0, _PREVIEW_UNITS - 3) + "…"


def _identifier_flows(leaf: ArgLeaf, ids: Mapping[str, str], index: SourceIndex, trust: TrustState) -> list[Flow]:
    flows: list[Flow] = []
    for value, source_ids in index.identifier_hits(ids).items():
        if _is_trusted(value, trust):
            continue
        for source_id in source_ids:
            source = index.get(source_id)
            if source is None:
                continue
            flows.append(Flow("identifier", source_id, source.tool, leaf.path, value, IDENTIFIER_STRENGTH, ids[value]))
    return flows


def _handle_flows(leaf: ArgLeaf, compact: str, index: SourceIndex) -> list[Flow]:
    return [
        Flow("identifier", source.id, source.tool, leaf.path, compact, IDENTIFIER_STRENGTH, "handle")
        for source in index.sources
        if compact in source.normalized
    ]


def _content_strength(score: ContainmentScore, word_ok: bool, char_ok: bool, limits: FlowThresholds) -> float | None:
    word_flow = word_ok and score.word >= limits.min_containment
    char_flow = char_ok and score.char >= limits.min_char_containment
    if not (word_flow or char_flow):
        return None
    return max(score.word if word_flow else 0.0, score.char if char_flow else 0.0)


def _content_flows(leaf: ArgLeaf, compact: str, index: SourceIndex, limits: FlowThresholds) -> list[Flow]:
    flows: list[Flow] = []
    needle = build_shingles(compact)
    word_ok = needle.word_count >= MIN_CONTENT_WORDS
    compact_len = utf16_len(compact)
    for source_id, score in index.containment(needle).items():
        source = index.get(source_id)
        if source is None:
            continue
        if compact_len >= MIN_EXACT_CHARS and score.char >= 1 and compact in source.normalized:
            flows.append(Flow("exact", source_id, source.tool, leaf.path, _preview(compact), 1.0))
            continue
        strength = _content_strength(score, word_ok, compact_len >= MIN_CONTENT_CHARS, limits)
        if strength is not None:
            flows.append(Flow("content", source_id, source.tool, leaf.path, _preview(compact), strength))
    return flows


def _joined_flows(
    untrusted: Sequence[ArgLeaf], implicated: set[str], index: SourceIndex, limits: FlowThresholds
) -> list[Flow]:
    """Score the joined untrusted values once, for sources no single leaf implicated."""
    parts = (
        js_trim(normalize(leaf.value).normalized) for leaf in untrusted if not leaf.path.endswith(f".{leaf.value}")
    )
    joined = " ".join(part for part in parts if part)
    if utf16_len(joined) < MIN_CONTENT_CHARS:
        return []
    needle = build_shingles(joined)
    word_ok = needle.word_count >= MIN_CONTENT_WORDS
    flows: list[Flow] = []
    for source_id, score in index.containment(needle).items():
        source = index.get(source_id)
        if source_id in implicated or source is None:
            continue
        strength = _content_strength(score, word_ok, True, limits)
        if strength is not None:
            flows.append(Flow("content", source_id, source.tool, "args", _preview(joined), strength))
    return flows


def detect_flows(
    leaves: Sequence[ArgLeaf], index: SourceIndex, trust: TrustState, thresholds: FlowThresholds
) -> FlowReport:
    """Run the flow detectors on every string leaf of a call's arguments.

    A leaf found verbatim in trusted user text never yields a flow. A destination-key leaf (``to``,
    ``url``, ``user``) flows when its value appears verbatim in any source.
    """
    flows: list[Flow] = []
    untrusted: list[ArgLeaf] = []
    destinations = 0
    trusted_destinations = 0

    for leaf in leaves:
        compact = js_trim(normalize(leaf.value).normalized)
        if not compact:
            continue
        user_authored = bool(trust.text) and compact in trust.text
        if not user_authored:
            untrusted.append(leaf)

        ids = identifier_values(leaf.value, False)
        handle = key_of(leaf.path) in DESTINATION_KEYS and not ids and utf16_len(compact) >= MIN_DESTINATION_CHARS
        for value, kind in ids.items():
            if kind in DESTINATION_KINDS:
                destinations += 1
                trusted_destinations += _is_trusted(value, trust)
        if handle:
            destinations += 1
            trusted_destinations += user_authored or _is_trusted(compact, trust)
        if not index.sources:
            continue

        flows.extend(_identifier_flows(leaf, ids, index, trust))
        if user_authored:
            continue
        if handle and not _is_trusted(compact, trust):
            flows.extend(_handle_flows(leaf, compact, index))
        flows.extend(_content_flows(leaf, compact, index, thresholds))

    if len(untrusted) >= 2 and index.sources:
        flows.extend(_joined_flows(untrusted, {flow.source_id for flow in flows}, index, thresholds))

    return FlowReport(flows, untrusted, destinations > 0 and trusted_destinations == destinations)
