"""The ``to_dict`` mixin that turns a result dataclass into the JSON shape the JS library returns (plan D4)."""

from dataclasses import fields
from typing import Any, ClassVar

__all__ = ["JsResult"]


def _camel(name: str) -> str:
    head, *rest = [part for part in name.split("_") if part]
    return head + "".join(part[:1].upper() + part[1:] for part in rest)


def _convert(value: Any) -> Any:
    if isinstance(value, JsResult):
        return value.to_dict()
    if isinstance(value, (list, tuple)):
        return [_convert(item) for item in value]
    if isinstance(value, dict):
        return {key: _convert(item) for key, item in value.items()}
    return value


class JsResult:
    """Mixin for a dataclass: ``to_dict`` gives camelCase keys, drops ``None`` and recurses into nested values.

    A ``None`` field named in ``_js_nullable`` is kept as ``None``, like a JS ``T | null`` field.
    Dict keys are left as they are, and a tuple comes out as a list.
    """

    __slots__ = ()
    _js_nullable: ClassVar[frozenset[str]] = frozenset()

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for field in fields(self):  # type: ignore[arg-type]
            value = getattr(self, field.name)
            if value is None and field.name not in self._js_nullable:
                continue
            out[_camel(field.name)] = _convert(value)
        return out
