"""Envelope fixes from the PY-20 decision audit (plan D7, e-41ef84; JS twin src/envelope/index.ts).

A bad HS256 secret is crypto-unavailable, as in JS hmacKey. One nonce passes one shared store once, however
many threads open it.
"""

import sys
import threading
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any, get_args

import pytest

from prompt_protection.envelope import EnvelopeError, EnvelopeErrorCode, create_nonce_store, seal
from prompt_protection.envelope import open as open_envelope

GOOD_KEY: dict[str, Any] = {"alg": "HS256", "kid": "k1", "secret": "a-shared-secret-of-reasonable-length"}
NOW = 1_700_000_000_000
THREADS = 8
GATE_TIMEOUT_S = 1.0
HMAC_FAILURE_PREFIX = "HMAC import failed"

BAD_SECRETS = [
    pytest.param("", id="empty-str"),
    pytest.param(b"", id="empty-bytes"),
    pytest.param(None, id="none"),
    pytest.param(12345, id="int"),
]


def bad_key(secret: Any) -> dict[str, Any]:
    return {"alg": "HS256", "kid": "k1", "secret": secret}


def keyless() -> dict[str, Any]:
    return {"alg": "HS256", "kid": "k1"}


def outcome(call: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[str, str]:
    """Return (EnvelopeError code or exception type, message), or ("ok", "")."""
    try:
        call(*args, **kwargs)
    except EnvelopeError as error:
        return error.code, str(error)
    except Exception as error:
        return type(error).__name__, str(error)
    return "ok", ""


def assert_hmac_import_failure(result: tuple[str, str]) -> None:
    code, message = result
    assert code == "crypto-unavailable"
    assert message.startswith(HMAC_FAILURE_PREFIX)


def test_crypto_unavailable_stays_in_the_error_code_set_d7() -> None:
    assert "crypto-unavailable" in get_args(EnvelopeErrorCode)


@pytest.mark.parametrize("secret", BAD_SECRETS)
def test_seal_with_a_bad_secret_is_crypto_unavailable(secret: Any) -> None:
    assert_hmac_import_failure(outcome(seal, {"a": 1}, bad_key(secret), now=lambda: NOW))


def test_seal_with_a_missing_secret_is_crypto_unavailable() -> None:
    assert_hmac_import_failure(outcome(seal, {"a": 1}, keyless(), now=lambda: NOW))


@pytest.mark.parametrize("secret", BAD_SECRETS)
def test_open_with_a_bad_secret_is_crypto_unavailable(secret: Any) -> None:
    env = seal({"a": 1}, GOOD_KEY, now=lambda: NOW)
    assert_hmac_import_failure(outcome(open_envelope, env, bad_key(secret), now=lambda: NOW))


def test_open_with_a_missing_secret_is_crypto_unavailable() -> None:
    env = seal({"a": 1}, GOOD_KEY, now=lambda: NOW)
    assert_hmac_import_failure(outcome(open_envelope, env, keyless(), now=lambda: NOW))


class PlainStore:
    """A caller-supplied NonceStore with no lock of its own."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def has(self, nonce: str) -> bool:
        return nonce in self._seen

    def add(self, nonce: str) -> None:
        self._seen.add(nonce)

    @property
    def size(self) -> int:
        return len(self._seen)


@pytest.fixture
def raced_store(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Build a store whose has() parks each caller at a barrier after reading, forcing the has-then-add race."""
    store = request.param()
    gate = threading.Barrier(THREADS)
    original = type(store).has

    def has(self: Any, nonce: str) -> bool:
        seen = original(self, nonce)
        try:
            gate.wait(GATE_TIMEOUT_S)
        except threading.BrokenBarrierError:
            pass
        return seen

    monkeypatch.setattr(type(store), "has", has)
    return store


STORE_FACTORIES = pytest.mark.parametrize(
    "raced_store", [create_nonce_store, PlainStore], ids=["default-ring", "plain-store"], indirect=True
)


@STORE_FACTORIES
def test_one_nonce_passes_a_shared_store_once_across_threads(raced_store: Any) -> None:
    env = seal({"a": 1}, GOOD_KEY, now=lambda: NOW)
    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        futures = [
            pool.submit(outcome, open_envelope, env, GOOD_KEY, now=lambda: NOW, nonces=raced_store)
            for _ in range(THREADS)
        ]
        results = sorted(code for code, _ in (future.result() for future in futures))
    assert results == ["ok"] + ["replayed"] * (THREADS - 1)
    assert raced_store.size == 1


@pytest.fixture
def fast_thread_switching() -> Iterator[None]:
    previous = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)
    yield
    sys.setswitchinterval(previous)


@pytest.mark.usefixtures("fast_thread_switching")
def test_concurrent_adds_past_max_size_raise_nothing_and_keep_the_ring_full() -> None:
    max_size, per_thread = 16, 4000
    store = create_nonce_store(max_size)
    start = threading.Barrier(THREADS)
    errors: list[BaseException] = []

    def fill(worker: int) -> None:
        start.wait()
        try:
            for index in range(per_thread):
                store.add(f"{worker:02d}-{index:06d}")
        except BaseException as error:
            errors.append(error)

    workers = [threading.Thread(target=fill, args=(worker,)) for worker in range(THREADS)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join()
    assert errors == []
    assert store.size == max_size
