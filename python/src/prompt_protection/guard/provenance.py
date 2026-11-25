"""Argument-to-source flow detection (twin of src/guard/provenance.ts, plan D1, D2, D32, D40).

Lengths and slices count UTF-16 code units, as the JS ``.length`` and ``.slice`` do. Postings are
dicts, and ``ShingleSet`` iterates in insertion order, so results follow the order JS ``Map`` and ``Set`` give.
"""

import copy
import math
import re
import sys
from collections.abc import Callable, Hashable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from decimal import Decimal
from enum import Enum
from fractions import Fraction
from functools import lru_cache
from pathlib import PurePath, PurePosixPath, PureWindowsPath
from types import BuiltinFunctionType, FunctionType, MethodType, ModuleType
from typing import Any, Protocol, TypeVar, cast
from uuid import UUID

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
    """A value with no JSON form: a cycle, too deep, a type JSON cannot hold, or a dict with two keys of one text."""


def _number_text(value: float, nested: bool) -> str:
    try:
        number = int.__float__(cast(int, value)) if issubclass(type(value), int) else float.__float__(value)
    except OverflowError:
        raise _NoJsonForm from None
    return "null" if nested and not math.isfinite(number) else js_number_str(number)


def _js_key_order(keys: list[str]) -> list[str]:
    """Order keys as a JS object lists them: canonical array indexes ascending, then insertion order."""
    indexes = {k for k in keys if _ARRAY_INDEX_RE.match(k) and int(k) <= _MAX_ARRAY_INDEX}
    return sorted(indexes, key=int) + [k for k in keys if k not in indexes]


@dataclass(slots=True)
class _Render:
    """The digit limit of one rendering, and whether any value in it printed as a type marker."""

    limit: int
    unrenderable: bool = False


def _json_text(value: object, seen: set[int], ctx: _Render, depth: int = 0) -> str:
    """Return compact JSON text. A container deeper than ``_MAX_DEPTH`` has no JSON form (the root is depth 0)."""
    value = _unwrap_enum(value)
    kind = type(value)
    if value is None:
        return "null"
    if issubclass(kind, str):
        return _json_string(str.__str__(cast(str, value)))
    if kind is bool:
        return "true" if value else "false"
    if issubclass(kind, (int, float)):
        return _number_text(cast(float, value), True)
    if not (kind is dict or kind is list or kind is tuple) or id(value) in seen or depth > _MAX_DEPTH:
        raise _NoJsonForm
    seen.add(id(value))
    parts: list[str] = []
    try:
        if kind is dict:
            pairs: dict[str, Any] = {}
            for key, item in cast(dict[Any, Any], value).items():
                text = _key_text(key, ctx)
                if text in pairs:
                    raise _NoJsonForm
                pairs[text] = item
            for key in _js_key_order(list(pairs)):
                parts.append(f"{_json_string(key)}:{_json_text(pairs[key], seen, ctx, depth + 1)}")
            return "{" + ",".join(parts) + "}"
        for item in cast(Iterable[Any], value):
            parts.append(_json_text(item, seen, ctx, depth + 1))
        return "[" + ",".join(parts) + "]"
    finally:
        seen.discard(id(value))


_ENUM_DICT = Enum.__dict__["__dict__"]
_NO_VALUE = object()
_LEAF_BASES = (str, int, float, complex, Decimal, timedelta, timezone, Fraction, UUID, PurePath, date, time, datetime)


def _unwrap_enum(value: object) -> object:
    """Return what an Enum member holds, through any chain of members.

    A member of a leaf subclass (an int or str mixin, say) stays: it prints through its base method. Any other
    member gives its ``_value_`` from its own ``__dict__``, read with the base descriptor so no class code runs.
    A member with no stored ``_value_`` stays, and prints as a marker.
    """
    seen: set[int] = set()
    while issubclass(type(value), Enum) and not issubclass(type(value), _LEAF_BASES) and id(value) not in seen:
        seen.add(id(value))
        stored = dict.get(_ENUM_DICT.__get__(value), "_value_", _NO_VALUE)
        if stored is _NO_VALUE:
            break
        value = stored
    return value


def _key_text(key: object, ctx: _Render) -> str:
    key = _unwrap_enum(key)
    return str.__str__(key) if issubclass(type(key), str) else _render(key, ctx, set())


_DEFAULT_INT_DIGIT_LIMIT = 4300
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


def _int_text(value: int, limit: int) -> str:
    """Print an int through its base type, as hex() once it is over ``limit`` digits."""
    number = int.__int__(value)
    return hex(number) if _over_limit(number, limit) else repr(number)


# Each base method below reads no overridable attribute of the instance (owner decision A, 2026-11-25).
_BASE_TEXT: tuple[tuple[type, Callable[[Any], str]], ...] = (
    (complex, complex.__repr__),
    (Decimal, Decimal.__str__),
    (timedelta, timedelta.__str__),
    (timezone, timezone.__str__),
)
_DATE_PARTS = (date.year, date.month, date.day)
_DATETIME_CLOCK = (datetime.hour, datetime.minute, datetime.second, datetime.microsecond)
_TIME_CLOCK = (time.hour, time.minute, time.second, time.microsecond)
_HOST_PATH: type[PurePath] = type(PurePath())
_TYPE_QUALNAME = type.__dict__["__qualname__"]
_FUNCTION_QUALNAME = FunctionType.__dict__["__qualname__"]
_BUILTIN_SELF = BuiltinFunctionType.__dict__["__self__"]
_BUILTIN_NAME = BuiltinFunctionType.__dict__["__name__"]
_METHOD_FUNC = MethodType.__dict__["__func__"]


def _plain_zone(zone: object) -> bool:
    """True for no tzinfo or the final ``timezone``: its ``utcoffset`` is C code, so isoformat runs no user code."""
    return zone is None or type(zone) is timezone


def _moment_text(value: Any, kind: type) -> str | None:
    """Print a date, time or datetime through the base ``isoformat``. Any other tzinfo is dropped, not called."""
    if issubclass(kind, datetime):
        if not _plain_zone(datetime.tzinfo.__get__(value)):
            value = datetime(*(part.__get__(value) for part in (*_DATE_PARTS, *_DATETIME_CLOCK)))
        return datetime.isoformat(value, " ")
    if issubclass(kind, date):
        return date.isoformat(value)
    if issubclass(kind, time):
        if not _plain_zone(time.tzinfo.__get__(value)):
            value = time(*(part.__get__(value) for part in _TIME_CLOCK))
        return time.isoformat(value)
    return None


def _fraction_text(value: object, limit: int) -> str | None:
    try:
        numerator = Fraction.__dict__["_numerator"].__get__(value)
        denominator = Fraction.__dict__["_denominator"].__get__(value)
    except AttributeError:
        return None
    if not (issubclass(type(numerator), int) and issubclass(type(denominator), int)):
        return None
    top = _int_text(numerator, limit)
    return top if int.__int__(denominator) == 1 else f"{top}/{_int_text(denominator, limit)}"


def _uuid_text(value: object) -> str | None:
    try:
        number = UUID.__dict__["int"].__get__(value)
    except AttributeError:
        return None
    if not issubclass(type(number), int):
        return None
    digits = f"{int.__int__(number):032x}"
    return "-".join((digits[:8], digits[8:12], digits[12:16], digits[16:20], digits[20:]))


def _path_text(value: object, kind: type) -> str:
    """Print a path from a copy of its slots held by the exact flavour, so no subclass attribute is read."""
    flavour = next((base for base in (PureWindowsPath, PurePosixPath) if issubclass(kind, base)), _HOST_PATH)
    clone = object.__new__(flavour)
    for slot in PurePath.__slots__:
        field = PurePath.__dict__[slot]
        try:
            field.__set__(clone, field.__get__(value))
        except AttributeError:
            continue
    return str.__str__(PurePath.__str__(clone))


def _pattern_text(value: object) -> str:
    pattern = re.Pattern.pattern.__get__(value)
    return bytes.__repr__(pattern) if issubclass(type(pattern), bytes) else str.__str__(pattern)


def _name_text(value: object, kind: type) -> str | None:
    """Return ``__qualname__`` of a function, method or class, read from the base descriptors so no hook runs."""
    while kind is MethodType:
        value = _METHOD_FUNC.__get__(value)
        kind = type(value)
    if kind is FunctionType:
        return str.__str__(_FUNCTION_QUALNAME.__get__(value))
    if kind is BuiltinFunctionType:
        owner = _BUILTIN_SELF.__get__(value)
        name = _BUILTIN_NAME.__get__(value)
        if owner is None or issubclass(type(owner), ModuleType):
            return str.__str__(name)
        owner_type = owner if issubclass(type(owner), type) else type(owner)
        return str.__str__(_TYPE_QUALNAME.__get__(owner_type)) + "." + str.__str__(name)
    if issubclass(kind, type):
        return str.__str__(_TYPE_QUALNAME.__get__(value))
    return None


def _stdlib_text(value: object, kind: type, limit: int) -> str | None:
    for base, text in _BASE_TEXT:
        if issubclass(kind, base):
            return str.__str__(text(value))
    if issubclass(kind, Fraction):
        return _fraction_text(value, limit)
    if issubclass(kind, UUID):
        return _uuid_text(value)
    if issubclass(kind, PurePath):
        return _path_text(value, kind)
    if issubclass(kind, re.Pattern):
        return _pattern_text(value)
    return _moment_text(value, kind) or _name_text(value, kind)


def _leaf_text(value: object, kind: type, limit: int) -> str | None:
    """Return the text of an allowlisted leaf, read through its base type so no override changes it."""
    if value is None:
        return "None"
    if kind is bool:
        return "True" if value else "False"
    if issubclass(kind, str):
        return str.__repr__(cast(str, value))
    if issubclass(kind, int):
        return _int_text(cast(int, value), limit)
    if issubclass(kind, float):
        return float.__repr__(cast(float, value))
    if kind is bytes:
        return bytes.__repr__(cast(bytes, value))
    if kind is range:
        span = cast(range, value)
        bounds = [_int_text(bound, limit) for bound in (span.start, span.stop)]
        if span.step != 1:
            bounds.append(_int_text(span.step, limit))
        return f"range({', '.join(bounds)})"
    return _stdlib_text(value, kind, limit)


def _marker(value: object, ctx: _Render) -> str:
    """Print the name of a value's type and flag the rendering. Nothing of the value is read."""
    ctx.unrenderable = True
    return f"<{str.__str__(_TYPE_QUALNAME.__get__(type(value)))} not rendered>"


def _container_text(value: Any, kind: type, ctx: _Render, path: set[int]) -> str:
    """Render an exact dict by items and an exact list, tuple, set or frozenset by elements (two frames a level)."""
    parts: list[str] = []
    if kind is dict:
        for key, item in value.items():
            parts.append(f"{_render(key, ctx, path)}: {_render(item, ctx, path)}")
        return "{" + ", ".join(parts) + "}"
    for item in value:
        parts.append(_render(item, ctx, path))
    body = ", ".join(parts)
    if kind is list:
        return f"[{body}]"
    if kind is tuple:
        return f"({body},)" if len(parts) == 1 else f"({body})"
    if not parts:
        return "set()" if kind is set else "frozenset()"
    return "{" + body + "}" if kind is set else "frozenset({" + body + "})"


def _render(value: object, ctx: _Render, path: set[int]) -> str:
    """Return the text of ``value``: a leaf, an exact container, or ``<Type not rendered>`` for anything else.

    A container met again on the way down prints as ``[...]``, ``(...)`` or ``{...}``. Past depth 300 (root 0),
    a container prints ``<too deep>``.
    """
    value = _unwrap_enum(value)
    kind = type(value)
    leaf = _leaf_text(value, kind, ctx.limit)
    if leaf is not None:
        return leaf
    if not (kind is dict or kind is list or kind is tuple or kind is set or kind is frozenset):
        return _marker(value, ctx)
    if len(path) > _MAX_DEPTH:
        return _DEPTH_MARKER
    if id(value) in path:
        return "[...]" if kind is list else "(...)" if kind is tuple else "{...}"
    path.add(id(value))
    try:
        return _container_text(value, kind, ctx, path)
    finally:
        path.discard(id(value))


def _stringify_flagged(value: object) -> tuple[str, bool]:
    """Return ``stringify_value(value)`` and whether any value in it printed as a type marker."""
    ctx = _Render(_digit_limit())
    value = _unwrap_enum(value)
    kind = type(value)
    if issubclass(kind, str):
        return str.__str__(cast(str, value)), False
    if value is None:
        return "", False
    if issubclass(kind, int) and kind is not bool and _over_limit(int.__int__(cast(int, value)), ctx.limit):
        return hex(int.__int__(cast(int, value))), False
    try:
        if kind is bool:
            return ("true" if value else "false"), False
        if issubclass(kind, (int, float)):
            return _number_text(cast(float, value), False), False
        text = _json_text(value, set(), ctx)
        return text, ctx.unrenderable
    except (_NoJsonForm, RecursionError):
        pass
    ctx = _Render(ctx.limit)
    try:
        text = _render(value, ctx, set())
        return text, ctx.unrenderable
    except Exception:
        return _marker(value, ctx), True


def stringify_value(value: object) -> str:
    """Return the text a tool result is scanned as: a string as is, ``None`` as ``""``, else compact JSON.

    An int or float is a JS number. Python has no bigint, so an int too large for a float is one.
    A value with no JSON form (a cycle, a set, bytes, a stdlib leaf) falls back to a Python text. An exact
    ``dict``, ``list``, ``tuple``, ``set`` and ``frozenset`` print as Python does, and so do ``None``, ``bytes``,
    ``range``, and ``str``, ``int``, ``float`` and ``bool`` (a subclass prints its base value). These stdlib types
    are leaves, each printed through its base type: ``complex``, ``Decimal``, ``Fraction``, ``date``, ``time``,
    ``datetime``, ``timedelta``, ``timezone``, ``UUID`` and ``PurePath``. An Enum member prints its stored value,
    or its base value for a leaf mixin. A ``re.Pattern`` prints its pattern, a function, method or class its
    ``__qualname__``, any other value ``<Type not rendered>``, and none of its code runs. A dict with two keys
    of one text falls back to the Python text. An int of more than N digits prints as ``hex()``, with N the
    smaller of 4300 and ``sys.get_int_max_str_digits()`` (4300 when 0 or absent).
    """
    return _stringify_flagged(value)[0]


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
        by_text: dict[str, list[Any]] = {}
        for raw_key, item in args.items():
            by_text.setdefault(raw_key if isinstance(raw_key, str) else str(raw_key), []).append(item)
        for key in _js_key_order(list(by_text)):
            for item in by_text[key]:
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
