"""Signed taint envelopes (twin of src/envelope/index.ts, plan D5, D18).

An envelope carries a payload and its trust label across a process boundary. ``open`` trusts the label only
when the signature, the expiry and the nonce pass. Only HS256 is supported: an EdDSA key raises
``DeferredFeatureError`` (D5) and an EdDSA envelope fails closed with ``unknown-kid``.

``open`` checks in this order: malformed, key, signature, expiry and skew, nonce. A forged envelope never
reaches the nonce store. Keys are mappings with the JS names ``alg``, ``secret`` and ``kid``.
"""

import base64
import binascii
import hashlib
import hmac
import math
import re
import secrets
import threading
import time
import weakref
from collections.abc import Callable, Iterable, Mapping
from typing import Any, Literal, Protocol, TypedDict, TypeGuard, cast

from prompt_protection.canonical import _utf8, canonical_json
from prompt_protection.errors import DeferredFeatureError

__all__ = [
    "Envelope",
    "EnvelopeAlg",
    "EnvelopeError",
    "EnvelopeErrorCode",
    "EnvelopeKey",
    "NonceStore",
    "create_nonce_store",
    "from_base64_url",
    "generate_key",
    "is_envelope",
    "open",
    "seal",
    "to_base64_url",
]

EnvelopeAlg = Literal["HS256", "EdDSA"]
EnvelopeErrorCode = Literal["bad-signature", "expired", "replayed", "unknown-kid", "crypto-unavailable", "malformed"]

_DEFAULT_MAX_SKEW_MS = 60_000
_BASE64URL = re.compile(r"[A-Za-z0-9_-]*")


class _EnvelopeRequired(TypedDict):
    v: int
    alg: str
    iat: int
    nonce: str
    label: str
    payload: Any
    sig: str


_EnvelopeOptional = TypedDict("_EnvelopeOptional", {"kid": str, "exp": int, "from": str}, total=False)


class Envelope(_EnvelopeRequired, _EnvelopeOptional):
    """The wire form (D3). ``kid``, ``exp`` and ``from`` are absent when not given."""


class _EnvelopeKeyRequired(TypedDict):
    alg: str


class EnvelopeKey(_EnvelopeKeyRequired, total=False):
    """``secret`` is a non-empty ``str`` (UTF-8) or ``bytes``. An EdDSA key is accepted by no function here.

    An empty, missing or other-typed HS256 secret raises ``EnvelopeError('crypto-unavailable')``.
    """

    secret: str | bytes
    kid: str


class EnvelopeError(Exception):
    """Raised by ``seal`` and ``open``. ``code`` names the reason."""

    def __init__(self, code: EnvelopeErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code


class NonceStore(Protocol):
    """Replay memory for ``open``. Any object with ``has``, ``add`` and ``size`` fits."""

    def has(self, nonce: str) -> bool: ...

    def add(self, nonce: str) -> None: ...

    @property
    def size(self) -> int: ...


class _NonceRing:
    def __init__(self, max_size: int) -> None:
        self._max = max_size
        self._seen: dict[str, None] = {}
        self._lock = threading.Lock()

    def has(self, nonce: str) -> bool:
        with self._lock:
            return nonce in self._seen

    def add(self, nonce: str) -> None:
        with self._lock:
            self._seen.setdefault(nonce)
            if len(self._seen) > self._max:
                del self._seen[next(iter(self._seen))]

    @property
    def size(self) -> int:
        with self._lock:
            return len(self._seen)


_store_locks: "weakref.WeakKeyDictionary[Any, threading.Lock]" = weakref.WeakKeyDictionary()
_registry_lock = threading.Lock()
_fallback_lock = threading.Lock()


def _lock_for(store: NonceStore) -> threading.Lock:
    """Return the lock that serializes has-then-add on ``store``. One lock per store object."""
    try:
        with _registry_lock:
            return _store_locks.setdefault(store, threading.Lock())
    except TypeError:
        return _fallback_lock


def create_nonce_store(max_size: int = 1024) -> NonceStore:
    """Return an in-memory ring of seen nonces. The oldest is dropped past ``max_size``."""
    return _NonceRing(max_size)


def to_base64_url(data: bytes) -> str:
    """Encode ``data`` as base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_base64_url(text: str) -> bytes | None:
    """Decode unpadded base64url as the JS helper does. Return ``None`` for any other text."""
    if _BASE64URL.fullmatch(text) is None or len(text) % 4 == 1:
        return None
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError):
        return None


def _wall_clock_ms() -> int:
    return int(time.time() * 1000)


def _deferred_eddsa() -> DeferredFeatureError:
    return DeferredFeatureError("prompt-protection: EdDSA envelope keys are not supported in the Python package yet")


def _require_hs256(key: Mapping[str, Any]) -> None:
    alg = key.get("alg")
    if alg == "EdDSA":
        raise _deferred_eddsa()
    if alg != "HS256":
        raise ValueError(f"unsupported envelope key alg {alg!r}")


def _secret_bytes(key: Mapping[str, Any]) -> bytes:
    secret = key.get("secret")
    if isinstance(secret, str):
        raw = _utf8(secret)
    elif isinstance(secret, (bytes, bytearray, memoryview)):
        raw = bytes(secret)
    else:
        raise EnvelopeError("crypto-unavailable", "HMAC import failed: an HS256 key needs a str or bytes secret")
    if not raw:
        raise EnvelopeError("crypto-unavailable", "HMAC import failed: zero-length secret is not supported")
    return raw


def _mac(text: str, key: Mapping[str, Any]) -> bytes:
    _require_hs256(key)
    return hmac.new(_secret_bytes(key), _utf8(text), hashlib.sha256).digest()


def _unsigned(env: Mapping[str, Any]) -> str:
    return canonical_json({name: value for name, value in env.items() if name != "sig"})


def _sign(text: str, key: Mapping[str, Any]) -> str:
    return to_base64_url(_mac(text, key))


def _verify(text: str, sig: str, key: Mapping[str, Any]) -> bool:
    decoded = from_base64_url(sig)
    if decoded is None:
        return False
    return hmac.compare_digest(_mac(text, key), decoded)


def _is_finite_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(float(value))
    except OverflowError:
        return False


def _optional_is(env: Mapping[str, Any], name: str, test: Callable[[object], bool]) -> bool:
    return name not in env or test(env[name])


def is_envelope(value: object) -> TypeGuard[Envelope]:
    """Return whether ``value`` has the shape of a v1 envelope. It checks no signature."""
    if not isinstance(value, dict):
        return False
    version = value.get("v")
    if not _is_finite_number(version) or version != 1:
        return False
    if value.get("alg") not in ("HS256", "EdDSA") or not _is_finite_number(value.get("iat")):
        return False
    if not _optional_is(value, "exp", _is_finite_number):
        return False
    if not all(_optional_is(value, name, lambda item: isinstance(item, str)) for name in ("kid", "from")):
        return False
    return all(isinstance(value.get(name), str) for name in ("nonce", "label", "sig")) and "payload" in value


def seal(
    payload: Any,
    key: EnvelopeKey,
    *,
    label: str = "untrusted",
    ttl_ms: int | None = None,
    from_: str | None = None,
    now: Callable[[], int] | None = None,
) -> Envelope:
    """Seal ``payload`` with its trust label. ``from_`` is written to the envelope as ``from``."""
    _require_hs256(key)
    iat = (now or _wall_clock_ms)()
    env: dict[str, Any] = {"v": 1, "alg": key["alg"]}
    if key.get("kid") is not None:
        env["kid"] = key["kid"]
    env["iat"] = iat
    if ttl_ms is not None:
        env["exp"] = iat + ttl_ms
    env["nonce"] = secrets.token_hex(16)
    env["label"] = label
    if from_ is not None:
        env["from"] = from_
    env["payload"] = payload
    env["sig"] = _sign(_unsigned(env), key)
    return cast(Envelope, env)


def _select_key(env: Envelope, keys: Mapping[str, Any] | Iterable[Mapping[str, Any]]) -> Mapping[str, Any]:
    pool = [keys] if isinstance(keys, Mapping) else list(keys)
    if any(key.get("alg") == "EdDSA" for key in pool):
        raise _deferred_eddsa()
    kid = env.get("kid")
    for key in pool:
        if key.get("alg") == env["alg"] and key.get("kid") == kid:
            return key
    raise EnvelopeError("unknown-kid", f"no {env['alg']} key for kid {kid if kid is not None else '(none)'}")


def open(
    env: object,
    keys: Mapping[str, Any] | Iterable[Mapping[str, Any]],
    *,
    now: Callable[[], int] | None = None,
    max_skew_ms: int = _DEFAULT_MAX_SKEW_MS,
    nonces: NonceStore | None = None,
    require_exp: bool = False,
) -> Envelope:
    """Verify ``env`` and return it, or raise ``EnvelopeError``. Without ``nonces`` replay is not checked.

    The nonce check and add run under one lock per store, so a nonce passes a shared store once across threads.
    """
    if not is_envelope(env):
        raise EnvelopeError("malformed", "not a v1 envelope")
    key = _select_key(env, keys)
    if not _verify(_unsigned(env), env["sig"], key):
        raise EnvelopeError("bad-signature", "signature does not verify")
    at = (now or _wall_clock_ms)()
    if env["iat"] > at + max_skew_ms:
        raise EnvelopeError("expired", "issued in the future beyond the allowed skew")
    if "exp" in env and env["exp"] < at:
        raise EnvelopeError("expired", "envelope expired")
    if require_exp and "exp" not in env:
        raise EnvelopeError("expired", "envelope carries no exp")
    if nonces is not None:
        with _lock_for(nonces):
            if nonces.has(env["nonce"]):
                raise EnvelopeError("replayed", "nonce already seen")
            nonces.add(env["nonce"])
    return env


def generate_key(alg: EnvelopeAlg, kid: str | None = None) -> EnvelopeKey:
    """Return a random 32-byte HS256 key. ``generate_key('EdDSA')`` raises ``DeferredFeatureError``."""
    if alg == "EdDSA":
        raise _deferred_eddsa()
    if alg != "HS256":
        raise ValueError(f"unsupported envelope key alg {alg!r}")
    key: EnvelopeKey = {"alg": "HS256", "secret": secrets.token_bytes(32)}
    if kid is not None:
        key["kid"] = kid
    return key
