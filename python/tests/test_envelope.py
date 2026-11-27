"""RED tests for prompt_protection.envelope. Port of tests/envelope/envelope.test.ts.

Oracle: Node 22 against dist/envelope/index.js, plus tests/guard/__fixtures__/envelope.golden.json. The handoff,
memory and eddsa-handoff vectors sit at their own recorded iat, never header.now.
Keys are mappings with the JS names alg, secret and kid. EdDSA is deferred. Lock vectors belong to later tasks.
"""

import base64
import hashlib
import hmac
import json
import re
import time
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from prompt_protection.canonical import CanonicalJsonError, canonical_json
from prompt_protection.envelope import (
    EnvelopeError,
    _sign,
    _unsigned,
    create_nonce_store,
    from_base64_url,
    generate_key,
    is_envelope,
    seal,
    to_base64_url,
)
from prompt_protection.envelope import open as open_envelope
from prompt_protection.errors import DeferredFeatureError

GOLDEN_PATH = Path(__file__).resolve().parents[2] / "tests" / "guard" / "__fixtures__" / "envelope.golden.json"
SECRET = "a-shared-secret-of-reasonable-length"
DROP = object()
NONCE_RE = re.compile(r"^[0-9a-f]{32}$")
SIG_RE = re.compile(r"^[A-Za-z0-9_-]+$")
HS_KINDS = ("hs256", "handoff")


def hs_key(kid: str | None = "k1", secret: str | bytes = SECRET) -> dict[str, Any]:
    key: dict[str, Any] = {"alg": "HS256", "secret": secret}
    if kid is not None:
        key["kid"] = kid
    return key


def at(ms: int) -> Any:
    return lambda: ms


def mutate(env: dict[str, Any], **changes: Any) -> dict[str, Any]:
    """Copy ``env`` with each change applied; a change of ``DROP`` removes the key."""
    out = dict(env)
    for name, value in changes.items():
        key = "from" if name == "from_" else name
        if value is DROP:
            out.pop(key, None)
        else:
            out[key] = value
    return out


def hmac_sig(text: str, secret: str | bytes) -> str:
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    return base64.urlsafe_b64encode(hmac.new(key, text.encode("utf-8"), hashlib.sha256).digest()).rstrip(b"=").decode()


def code_of(call: Any, *args: Any, **kwargs: Any) -> str:
    try:
        call(*args, **kwargs)
    except EnvelopeError as err:
        return err.code
    return "ok"


@cache
def golden() -> dict[str, Any]:
    return json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


def vectors(*kinds: str) -> list[Any]:
    return [pytest.param(v, id=v["name"]) for v in golden()["vectors"] if v["kind"] in kinds]


def inner_envelope(vector: dict[str, Any]) -> dict[str, Any]:
    out = vector["output"]
    return json.loads(out["sig"]) if vector["kind"] == "memory" else out  # type: ignore[no-any-return]


def golden_key(env: dict[str, Any]) -> dict[str, Any]:
    return hs_key(env.get("kid"), golden()["header"]["secret"])


@pytest.fixture
def base() -> dict[str, Any]:
    """A signed envelope with every optional field, sealed at 10 000 ms and expiring at 11 000 ms."""
    return seal({"a": 1}, hs_key(), label="tool", ttl_ms=1_000, from_="agent-a", now=at(10_000))


VALID_SHAPE: dict[str, Any] = {
    "v": 1, "alg": "HS256", "iat": 1, "nonce": "n", "label": "tool", "payload": {"a": 1}, "sig": "AAAA",
}  # fmt: skip
MALFORMED = [
    pytest.param(None, id="none"),
    pytest.param("nope", id="string"),
    pytest.param([], id="list"),
    pytest.param(42, id="int"),
    pytest.param({}, id="empty-dict"),
    pytest.param(mutate(VALID_SHAPE, v=2), id="v-2"),
    pytest.param(mutate(VALID_SHAPE, v=True), id="v-true"),
    pytest.param(mutate(VALID_SHAPE, alg="RS256"), id="alg-unknown"),
    pytest.param(mutate(VALID_SHAPE, iat="1"), id="iat-string"),
    pytest.param(mutate(VALID_SHAPE, iat=True), id="iat-bool"),
    pytest.param(mutate(VALID_SHAPE, iat=float("nan")), id="iat-nan"),
    pytest.param(mutate(VALID_SHAPE, iat=float("inf")), id="iat-inf"),
    pytest.param(mutate(VALID_SHAPE, exp="1"), id="exp-string"),
    pytest.param(mutate(VALID_SHAPE, exp=True), id="exp-bool"),
    pytest.param(mutate(VALID_SHAPE, exp=float("inf")), id="exp-inf"),
    pytest.param(mutate(VALID_SHAPE, kid=1), id="kid-int"),
    pytest.param(mutate(VALID_SHAPE, from_=1), id="from-int"),
    pytest.param(mutate(VALID_SHAPE, nonce=DROP), id="no-nonce"),
    pytest.param(mutate(VALID_SHAPE, label=DROP), id="no-label"),
    pytest.param(mutate(VALID_SHAPE, label=3), id="label-int"),
    pytest.param(mutate(VALID_SHAPE, sig=DROP), id="no-sig"),
    pytest.param(mutate(VALID_SHAPE, sig=None), id="sig-none"),
    pytest.param(mutate(VALID_SHAPE, payload=DROP), id="no-payload"),
]
WELL_FORMED = [
    pytest.param(VALID_SHAPE, id="minimal"),
    pytest.param(mutate(VALID_SHAPE, payload=None), id="null-payload"),
    pytest.param(mutate(VALID_SHAPE, alg="EdDSA", kid="e", exp=2.5, from_="x"), id="eddsa-all-fields"),
    pytest.param(mutate(VALID_SHAPE, extra=1), id="unknown-field"),
]


# --- golden interop ---------------------------------------------------------------


def test_golden_holds_every_vector_kind() -> None:
    kinds = {v["kind"] for v in golden()["vectors"]}
    assert kinds == {"hs256", "handoff", "memory", "lock", "eddsa", "eddsa-handoff", "error"}


@pytest.mark.parametrize("vector", vectors(*HS_KINDS, "memory"))
def test_js_hs256_vector_opens_at_its_own_iat(vector: dict[str, Any]) -> None:
    env = inner_envelope(vector)
    opened = open_envelope(env, golden_key(env), now=at(env["iat"]))
    assert opened == env


@pytest.mark.parametrize("vector", vectors(*HS_KINDS, "memory"))
def test_python_resign_equals_js_sig_exactly(vector: dict[str, Any]) -> None:
    env = inner_envelope(vector)
    assert _sign(_unsigned(env), golden_key(env)) == env["sig"]


@pytest.mark.parametrize("vector", vectors(*HS_KINDS, "memory"))
def test_independent_hmac_oracle_equals_js_sig(vector: dict[str, Any]) -> None:
    env = inner_envelope(vector)
    unsigned_text = canonical_json({k: v for k, v in env.items() if k != "sig"})
    assert hmac_sig(unsigned_text, golden()["header"]["secret"]) == env["sig"]


@pytest.mark.parametrize("vector", vectors("error"))
def test_js_error_vector_gives_its_code(vector: dict[str, Any]) -> None:
    out = vector["output"]
    env = out["envelope"]
    assert code_of(open_envelope, env, golden_key(env), now=at(out["now"])) == out["code"]


@pytest.mark.parametrize("vector", vectors("eddsa", "eddsa-handoff"))
def test_js_eddsa_envelope_is_unknown_kid_under_hs256_keys(vector: dict[str, Any]) -> None:
    env = vector["output"]["envelope"]
    assert env["alg"] == "EdDSA"
    with pytest.raises(EnvelopeError, match=f"no EdDSA key for kid {env['kid']}") as caught:
        open_envelope(env, [golden_key(env)], now=at(env["iat"]))
    assert caught.value.code == "unknown-kid"


@pytest.mark.parametrize("vector", vectors("eddsa", "eddsa-handoff"))
def test_js_eddsa_envelope_with_an_eddsa_key_is_deferred(vector: dict[str, Any]) -> None:
    env = vector["output"]["envelope"]
    with pytest.raises(DeferredFeatureError):
        open_envelope(env, {"alg": "EdDSA", "kid": env["kid"]}, now=at(env["iat"]))


def test_expired_vector_opens_at_exp_and_not_one_ms_later() -> None:
    out = next(v for v in golden()["vectors"] if v["name"] == "error-expired")["output"]
    env = out["envelope"]
    assert open_envelope(env, golden_key(env), now=at(env["exp"]))["payload"] == {"text": "stale"}
    assert out["now"] == env["exp"] + 1


# --- _unsigned, _sign --------------------------------------------------------------------------------


def test_unsigned_is_canonical_json_without_sig_and_leaves_input_alone(base: dict[str, Any]) -> None:
    before = dict(base)
    text = _unsigned(base)
    assert text == canonical_json({k: v for k, v in base.items() if k != "sig"})
    assert '"sig"' not in text
    assert _unsigned(mutate(base, sig="other")) == text
    assert base == before


@pytest.mark.parametrize("secret", [SECRET, SECRET.encode("utf-8"), "sécret-with-accent-é-long", b"\x00\xff" * 8])
def test_sign_is_hmac_sha256_base64url_without_padding(secret: str | bytes) -> None:
    text = '{"a":"é"}'
    sig = _sign(text, hs_key(secret=secret))
    assert sig == hmac_sig(text, secret)
    assert SIG_RE.match(sig)
    assert len(sig) == 43


def test_sign_ignores_kid() -> None:
    assert _sign("x", hs_key(kid=None)) == _sign("x", hs_key(kid="other"))


def test_sign_with_an_eddsa_key_is_deferred() -> None:
    with pytest.raises(DeferredFeatureError):
        _sign("x", {"alg": "EdDSA", "kid": "e"})


# --- seal --------------------------------------------------------------------------------------------------


def test_seal_records_label_iat_exp_from_kid_and_payload() -> None:
    env = seal({"text": "hello", "n": 1}, hs_key(), label="tool", ttl_ms=60_000, from_="agent-a", now=at(1_000))
    assert {k: v for k, v in env.items() if k not in ("nonce", "sig")} == {
        "v": 1, "alg": "HS256", "kid": "k1", "iat": 1_000, "exp": 61_000, "label": "tool", "from": "agent-a",
        "payload": {"text": "hello", "n": 1},
    }  # fmt: skip
    assert NONCE_RE.match(env["nonce"])
    assert SIG_RE.match(env["sig"])
    assert env["sig"] == hmac_sig(canonical_json({k: v for k, v in env.items() if k != "sig"}), SECRET)


def test_seal_defaults_to_untrusted_and_omits_absent_optionals() -> None:
    env = seal({"a": 1}, hs_key(kid=None), now=at(5))
    assert set(env) == {"v", "alg", "iat", "nonce", "label", "payload", "sig"}
    assert env["label"] == "untrusted"
    assert is_envelope(env)


@pytest.mark.parametrize(("ttl_ms", "from_", "expected"), [(0, "", {"exp": 5, "from": ""}), (7, None, {"exp": 12})])
def test_seal_keeps_falsy_but_given_options(ttl_ms: int, from_: str | None, expected: dict[str, Any]) -> None:
    env = seal({"a": 1}, hs_key(), ttl_ms=ttl_ms, from_=from_, now=at(5))
    assert {k: env[k] for k in ("exp", "from") if k in env} == expected


def test_seal_nonces_are_fresh_per_call() -> None:
    nonces = {seal({"a": 1}, hs_key(), now=at(1))["nonce"] for _ in range(20)}
    assert len(nonces) == 20


def test_seal_reads_the_wall_clock_in_integer_ms_by_default() -> None:
    before = int(time.time() * 1000)
    env = seal({"a": 1}, hs_key())
    after = int(time.time() * 1000)
    assert type(env["iat"]) is int
    assert before <= env["iat"] <= after


def test_seal_survives_a_json_round_trip_and_opens() -> None:
    env = seal({"text": "é😀", "n": [1, 2.5, None]}, hs_key(), label="user", now=at(1_000))
    opened = open_envelope(json.loads(json.dumps(env)), hs_key(), now=at(2_000))
    assert opened["payload"] == {"text": "é😀", "n": [1, 2.5, None]}


def test_seal_with_an_eddsa_key_is_deferred() -> None:
    with pytest.raises(DeferredFeatureError):
        seal({"a": 1}, {"alg": "EdDSA", "kid": "e"}, now=at(1))


def test_seal_of_a_non_finite_payload_raises_canonical_json_error() -> None:
    with pytest.raises(CanonicalJsonError) as caught:
        seal({"a": float("nan")}, hs_key(), now=at(1))
    assert caught.value.code == "non-finite"


# --- open: shape, order, errors ----------------------------------------------------------------------------


@pytest.mark.parametrize("candidate", MALFORMED)
def test_malformed_input_is_malformed_whatever_the_keys(candidate: Any) -> None:
    with pytest.raises(EnvelopeError, match="not a v1 envelope") as caught:
        open_envelope(candidate, [])
    assert caught.value.code == "malformed"
    assert is_envelope(candidate) is False


@pytest.mark.parametrize("candidate", WELL_FORMED)
def test_is_envelope_accepts_well_formed_shapes(candidate: Any) -> None:
    assert is_envelope(candidate) is True


def test_is_envelope_accepts_a_sealed_envelope(base: dict[str, Any]) -> None:
    assert is_envelope(base)


def test_open_returns_the_envelope_with_its_payload(base: dict[str, Any]) -> None:
    assert open_envelope(base, hs_key(), now=at(10_500)) == base


@pytest.mark.parametrize(
    ("changes", "keys", "message"),
    [
        pytest.param({}, hs_key(kid="k9"), "no HS256 key for kid k1", id="kid-differs"),
        pytest.param({"kid": DROP}, hs_key(), "no HS256 key for kid \\(none\\)", id="env-has-no-kid"),
        pytest.param({"kid": "k9"}, [hs_key()], "no HS256 key for kid k9", id="env-kid-unlisted"),
        pytest.param({}, hs_key(kid=None), "no HS256 key for kid k1", id="key-has-no-kid"),
        pytest.param({"alg": "EdDSA"}, [hs_key()], "no EdDSA key for kid k1", id="alg-differs"),
        pytest.param({}, [], "no HS256 key for kid k1", id="no-keys"),
    ],
)
def test_unknown_kid(base: dict[str, Any], changes: dict[str, Any], keys: Any, message: str) -> None:
    with pytest.raises(EnvelopeError, match=message) as caught:
        open_envelope(mutate(base, **changes), keys, now=at(10_500))
    assert caught.value.code == "unknown-kid"


SIGNED_FIELD_CHANGES = {"payload": {"x": 2}, "label": "z", "from": "z", "iat": 10_001, "exp": 10_999, "nonce": "z"}


@pytest.mark.parametrize("field", SIGNED_FIELD_CHANGES)
def test_any_changed_signed_field_is_bad_signature(base: dict[str, Any], field: str) -> None:
    changed = mutate(base, **{field: SIGNED_FIELD_CHANGES[field]})
    with pytest.raises(EnvelopeError, match="signature does not verify") as caught:
        open_envelope(changed, hs_key(), now=at(10_500))
    assert caught.value.code == "bad-signature"


@pytest.mark.parametrize(
    "changes", [{"exp": DROP}, {"from": DROP}, {"extra": 1}], ids=["drop-exp", "drop-from", "add-field"]
)
def test_removing_or_adding_a_field_is_bad_signature(base: dict[str, Any], changes: dict[str, Any]) -> None:
    assert code_of(open_envelope, mutate(base, **changes), hs_key(), now=at(10_500)) == "bad-signature"


@pytest.mark.parametrize("sig", ["", "***", "AAAA\n", to_base64_url(bytes(32)), "A" * 43, "A" * 43 + "="])
def test_unusable_or_wrong_signature_is_bad_signature(base: dict[str, Any], sig: str) -> None:
    assert code_of(open_envelope, mutate(base, sig=sig), hs_key(), now=at(10_500)) == "bad-signature"


def test_first_character_flip_of_a_valid_sig_is_bad_signature(base: dict[str, Any]) -> None:
    flipped = ("B" if base["sig"][0] == "A" else "A") + base["sig"][1:]
    assert code_of(open_envelope, mutate(base, sig=flipped), hs_key(), now=at(10_500)) == "bad-signature"


def test_wrong_secret_under_the_right_kid_is_bad_signature(base: dict[str, Any]) -> None:
    assert code_of(open_envelope, base, hs_key(secret="another-secret"), now=at(10_500)) == "bad-signature"


def test_bytes_and_str_secrets_with_the_same_bytes_open_each_other() -> None:
    env = seal({"a": 1}, hs_key(secret=SECRET.encode("utf-8")), now=at(1))
    assert open_envelope(env, hs_key(secret=SECRET), now=at(1))["payload"] == {"a": 1}


@pytest.mark.parametrize(
    ("now", "options", "message"),
    [
        pytest.param(11_001, {}, "envelope expired", id="one-ms-past-exp"),
        pytest.param(12_000, {}, "envelope expired", id="past-exp"),
        pytest.param(9_000, {"max_skew_ms": 999}, "issued in the future beyond the allowed skew", id="custom-skew"),
    ],
)
def test_expiry_and_skew_rejections(base: dict[str, Any], now: int, options: dict[str, Any], message: str) -> None:
    with pytest.raises(EnvelopeError, match=message) as caught:
        open_envelope(base, hs_key(), now=at(now), **options)
    assert caught.value.code == "expired"


@pytest.mark.parametrize(
    ("now", "options"),
    [
        pytest.param(11_000, {}, id="now-equals-exp"),
        pytest.param(9_500, {}, id="before-iat-within-default-skew"),
        pytest.param(9_000, {"max_skew_ms": 1_000}, id="iat-equals-now-plus-custom-skew"),
        pytest.param(5_000, {"max_skew_ms": 5_000}, id="wide-custom-skew"),
    ],
)
def test_expiry_and_skew_boundaries_are_inclusive(base: dict[str, Any], now: int, options: dict[str, Any]) -> None:
    assert open_envelope(base, hs_key(), now=at(now), **options)["payload"] == {"a": 1}


@pytest.mark.parametrize(("now", "expected"), [(40_000, "ok"), (39_999, "expired")])
def test_default_max_skew_is_60_seconds(now: int, expected: str) -> None:
    env = seal({"a": 1}, hs_key(), now=at(100_000))
    assert code_of(open_envelope, env, hs_key(), now=at(now)) == expected


def test_require_exp_rejects_an_envelope_without_exp_and_default_allows_it() -> None:
    env = seal({"a": 1}, hs_key(), now=at(10_000))
    with pytest.raises(EnvelopeError, match="envelope carries no exp") as caught:
        open_envelope(env, hs_key(), now=at(10_000), require_exp=True)
    assert caught.value.code == "expired"
    assert code_of(open_envelope, env, hs_key(), now=at(10_000)) == "ok"
    assert code_of(open_envelope, env, hs_key(), now=at(10_000), require_exp=False) == "ok"


def test_require_exp_accepts_an_envelope_with_exp(base: dict[str, Any]) -> None:
    assert code_of(open_envelope, base, hs_key(), now=at(10_500), require_exp=True) == "ok"


def test_default_clock_and_default_skew_are_the_wall_clock_and_a_minute() -> None:
    now = int(time.time() * 1000)
    near = seal({"a": 1}, hs_key(), now=at(now + 30_000))
    far = seal({"a": 1}, hs_key(), now=at(now + 3_600_000))
    assert code_of(open_envelope, near, hs_key()) == "ok"
    assert code_of(open_envelope, far, hs_key()) == "expired"


@pytest.mark.parametrize(
    ("changes", "keys", "now", "seen", "expected"),
    [
        pytest.param({"v": 2}, [], 10_500, False, "malformed", id="malformed-before-key"),
        pytest.param({"kid": "k9", "payload": {"x": 2}}, hs_key(), 10_500, False, "unknown-kid", id="key-before-sig"),
        pytest.param({"payload": {"x": 2}}, hs_key(), 20_000, False, "bad-signature", id="signature-before-expiry"),
        pytest.param({}, hs_key(), 20_000, True, "expired", id="expiry-before-nonce"),
        pytest.param({}, hs_key(), 10_500, True, "replayed", id="nonce-last"),
    ],
)
def test_check_order(
    base: dict[str, Any], changes: dict[str, Any], keys: Any, now: int, seen: bool, expected: str
) -> None:
    nonces = create_nonce_store()
    if seen:
        nonces.add(base["nonce"])
    assert code_of(open_envelope, mutate(base, **changes), keys, now=at(now), nonces=nonces) == expected


# --- replay protection -------------------------------------------------------------------------------------


def test_replay_is_rejected_after_one_successful_open(base: dict[str, Any]) -> None:
    nonces = create_nonce_store()
    assert open_envelope(base, hs_key(), now=at(10_500), nonces=nonces)["payload"] == {"a": 1}
    with pytest.raises(EnvelopeError, match="nonce already seen") as caught:
        open_envelope(base, hs_key(), now=at(10_500), nonces=nonces)
    assert caught.value.code == "replayed"
    assert nonces.size == 1


def test_without_a_store_the_same_envelope_opens_twice(base: dict[str, Any]) -> None:
    assert [code_of(open_envelope, base, hs_key(), now=at(10_500)) for _ in range(2)] == ["ok", "ok"]


def test_distinct_envelopes_share_one_store() -> None:
    nonces = create_nonce_store()
    envs = [seal({"i": i}, hs_key(), now=at(1)) for i in range(3)]
    assert [code_of(open_envelope, e, hs_key(), now=at(1), nonces=nonces) for e in envs] == ["ok"] * 3
    assert nonces.size == 3


@pytest.mark.parametrize(
    ("changes", "now", "options"),
    [
        pytest.param({"nonce": "forged"}, 10_500, {}, id="bad-signature"),
        pytest.param({"kid": "k9"}, 10_500, {}, id="unknown-kid"),
        pytest.param({}, 11_001, {}, id="expired"),
        pytest.param({}, 9_000, {"max_skew_ms": 999}, id="future-iat"),
    ],
)
def test_a_rejected_envelope_never_reaches_the_nonce_store(
    base: dict[str, Any], changes: dict[str, Any], now: int, options: dict[str, Any]
) -> None:
    env = mutate(base, **changes)
    nonces = create_nonce_store()
    assert code_of(open_envelope, env, hs_key(), now=at(now), nonces=nonces, **options) != "ok"
    assert (nonces.size, nonces.has(env["nonce"])) == (0, False)


def test_a_require_exp_rejection_never_reaches_the_nonce_store() -> None:
    env = seal({"a": 1}, hs_key(), now=at(10_000))
    nonces = create_nonce_store()
    assert code_of(open_envelope, env, hs_key(), now=at(10_000), nonces=nonces, require_exp=True) == "expired"
    assert nonces.size == 0


def test_nonce_store_drops_the_oldest_past_its_max() -> None:
    store = create_nonce_store(2)
    for nonce in ("a", "b", "c"):
        store.add(nonce)
    assert (store.has("a"), store.has("b"), store.has("c"), store.size) == (False, True, True, 2)


def test_nonce_store_default_max_is_1024() -> None:
    store = create_nonce_store()
    for i in range(1025):
        store.add(f"n{i}")
    assert (store.size, store.has("n0"), store.has("n1"), store.has("n1024")) == (1024, False, True, True)


def test_a_fresh_nonce_store_is_empty() -> None:
    store = create_nonce_store()
    assert (store.size, store.has("x")) == (0, False)


# --- key selection -----------------------------------------------------------------------------------------


def test_open_selects_a_key_by_kid_among_several() -> None:
    k1, k2 = hs_key("k1", "first-secret-of-length"), hs_key("k2", "second-secret-of-length")
    env = seal({"a": 1}, k2, now=at(1))
    assert open_envelope(env, [k1, k2], now=at(1))["kid"] == "k2"
    assert open_envelope(env, (k1, k2), now=at(1))["kid"] == "k2"


def test_a_kidless_envelope_matches_only_kidless_keys() -> None:
    bare = hs_key(None, "bare-secret-of-some-length")
    env = seal({"a": 1}, bare, now=at(1))
    assert code_of(open_envelope, env, [hs_key("k1"), hs_key("k2")], now=at(1)) == "unknown-kid"
    assert code_of(open_envelope, env, [hs_key("k1"), bare], now=at(1)) == "ok"


# --- generate_key, EnvelopeError ---------------------------------------------------------------------------


def test_generate_key_hs256_is_a_random_32_byte_secret() -> None:
    first, second = generate_key("HS256"), generate_key("HS256")
    assert set(first) == {"alg", "secret"}
    assert first["alg"] == "HS256"
    assert isinstance(first["secret"], bytes)
    assert len(first["secret"]) == 32
    assert first["secret"] != second["secret"]


def test_generate_key_keeps_the_kid_and_the_key_seals_and_opens() -> None:
    key = generate_key("HS256", "gen-1")
    assert key["kid"] == "gen-1"
    assert open_envelope(seal({"a": 1}, key, now=at(1)), key, now=at(1))["payload"] == {"a": 1}


@pytest.mark.parametrize("args", [("EdDSA",), ("EdDSA", "ed-1")])
def test_generate_key_eddsa_is_deferred(args: tuple[str, ...]) -> None:
    with pytest.raises(DeferredFeatureError):
        generate_key(*args)


def test_open_with_an_eddsa_key_is_deferred(base: dict[str, Any]) -> None:
    for keys in ({"alg": "EdDSA", "kid": "k1"}, [{"alg": "EdDSA", "kid": "k1"}]):
        with pytest.raises(DeferredFeatureError):
            open_envelope(base, keys, now=at(10_500))


def test_envelope_error_carries_code_and_message() -> None:
    err = EnvelopeError("replayed", "nonce already seen")
    assert (err.code, str(err)) == ("replayed", "nonce already seen")
    assert isinstance(err, Exception)


# --- base64url helpers -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "text"),
    [
        (bytes([0, 1, 2, 250, 251, 252, 253, 254, 255]), "AAEC-vv8_f7_"),
        (b"", ""),
        (b"\xff", "_w"),
        (b"\xff\xfe", "__4"),
        (b"\xff\xfe\xfd", "__79"),
        (b"\xff\xfe\xfd\xfc", "__79_A"),
    ],
)
def test_base64url_encodes_without_padding_and_decodes_back(data: bytes, text: str) -> None:
    assert to_base64_url(data) == text
    assert from_base64_url(text) == data


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("AB", b"\x00"),
        ("ABC", b"\x00\x10"),
        ("ab-_", bytes([105, 191, 191])),
        ("A-_B", bytes([3, 239, 193])),
        ("AAAAAB", bytes(4)),
        ("", b""),
        ("A", None),
        ("AAAAA", None),
        ("AB==", None),
        ("ab+/", None),
        ("not base64!", None),
        ("é", None),
        ("AAAA\n", None),
        ("AB\n", None),
        ("٣AAA", None),
        ("ＡＢＣＤ", None),
    ],
)
def test_base64url_decode_matches_the_js_helper(text: str, expected: bytes | None) -> None:
    assert from_base64_url(text) == expected
