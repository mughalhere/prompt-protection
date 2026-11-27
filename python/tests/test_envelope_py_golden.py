"""RED tests for the Python envelope golden.

python/tests/__fixtures__/envelope.py.golden.json is what Python sealed from the JS golden's inputs, in the JS
schema, so the JS interop suite can open it. make_envelope_golden.build() reseals; write() and main() persist it.
Handoff, memory and lock vectors sit at their own recorded wall-clock time, never header.now
(AgDR:envelope-golden-wall-clock-iat-for-guard-seals). EdDSA vectors are absent because Python defers EdDSA.
"""

import importlib
import json
import re
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from prompt_protection.envelope import EnvelopeError
from prompt_protection.envelope import open as open_envelope
from prompt_protection.guard import create_guard

ROOT = Path(__file__).resolve().parents[2]
JS_PATH = ROOT / "tests" / "guard" / "__fixtures__" / "envelope.golden.json"
PY_PATH = Path(__file__).resolve().parent / "__fixtures__" / "envelope.py.golden.json"
PY_KINDS = ("hs256", "handoff", "memory", "lock", "error")
JS = json.loads(JS_PATH.read_text(encoding="utf-8"))
JS_VECTORS = [v for v in JS["vectors"] if v["kind"] in PY_KINDS]
NONCE = re.compile(r"[0-9a-f]{32}")


def named(*kinds: str) -> list[Any]:
    return [pytest.param(v["name"], id=v["name"]) for v in JS_VECTORS if v["kind"] in kinds]


def js_vector(name: str) -> dict[str, Any]:
    return next(v for v in JS["vectors"] if v["name"] == name)


def hs_key(inputs: dict[str, Any]) -> dict[str, Any]:
    return {"alg": "HS256", "secret": JS["header"]["secret"], **({"kid": inputs["kid"]} if "kid" in inputs else {})}


def at(ms: int) -> Callable[[], int]:
    return lambda: ms


def without_random(env: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in env.items() if k not in ("nonce", "sig")}


def without_sig(entry: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in entry.items() if k != "sig"}


def stable(vector: dict[str, Any]) -> dict[str, Any]:
    """The output with its random nonce and its signature taken out, so two sealings of one input compare equal."""
    out = vector["output"]
    if vector["kind"] == "memory":
        return {**without_sig(out), "sig": without_random(json.loads(out["sig"]))}
    if vector["kind"] == "error":
        return {**out, "envelope": without_random(out["envelope"])}
    return without_random(out) if vector["kind"] in ("hs256", "handoff") else out  # type: ignore[no-any-return]


def envelope_of(vector: dict[str, Any]) -> dict[str, Any]:
    out = vector["output"]
    if vector["kind"] == "memory":
        return json.loads(out["sig"])  # type: ignore[no-any-return]
    return out["envelope"] if vector["kind"] == "error" else out  # type: ignore[no-any-return]


@pytest.fixture(scope="module")
def maker() -> ModuleType:
    return importlib.import_module("make_envelope_golden")


@pytest.fixture(scope="module")
def py_golden() -> dict[str, Any]:
    assert PY_PATH.is_file(), f"missing fixture {PY_PATH}"
    return json.loads(PY_PATH.read_text(encoding="utf-8"))  # type: ignore[no-any-return]


@pytest.fixture(scope="module")
def built(maker: ModuleType) -> dict[str, Any]:
    return maker.build()  # type: ignore[no-any-return]


@pytest.fixture
def py_vector(py_golden: dict[str, Any]) -> Callable[[str], dict[str, Any]]:
    def find(name: str) -> dict[str, Any]:
        return next(v for v in py_golden["vectors"] if v["name"] == name)

    return find


def test_the_python_fixture_exists() -> None:
    assert PY_PATH.is_file()


def test_the_header_equals_the_js_header(py_golden: dict[str, Any]) -> None:
    assert py_golden["header"] == JS["header"]


def test_the_vectors_are_the_js_vectors_of_the_python_kinds_in_order(py_golden: dict[str, Any]) -> None:
    assert [(v["name"], v["kind"]) for v in py_golden["vectors"]] == [(v["name"], v["kind"]) for v in JS_VECTORS]
    assert {v["kind"] for v in py_golden["vectors"]}.isdisjoint({"eddsa", "eddsa-handoff"})


@pytest.mark.parametrize("name", named(*PY_KINDS))
def test_inputs_equal_the_js_inputs(name: str, py_vector: Callable[[str], dict[str, Any]]) -> None:
    assert py_vector(name)["inputs"] == js_vector(name)["inputs"]


@pytest.mark.parametrize("name", named("hs256", "handoff", "memory", "error"))
def test_every_envelope_carries_a_32_hex_nonce(name: str, py_vector: Callable[[str], dict[str, Any]]) -> None:
    assert NONCE.fullmatch(envelope_of(py_vector(name))["nonce"])


@pytest.mark.parametrize("name", named("hs256"))
def test_an_hs256_vector_opens_at_header_now_with_its_inputs(
    name: str, py_vector: Callable[[str], dict[str, Any]]
) -> None:
    vector = py_vector(name)
    inputs, env = vector["inputs"], vector["output"]
    opened = open_envelope(env, hs_key(inputs), now=at(JS["header"]["now"]))
    assert (opened["payload"], opened["label"], opened.get("kid"), opened.get("from")) == (
        inputs["payload"],
        inputs["label"],
        inputs.get("kid"),
        inputs.get("from"),
    )
    assert env["iat"] == JS["header"]["now"]
    assert env.get("exp") == (env["iat"] + inputs["ttlMs"] if "ttlMs" in inputs else None)


@pytest.mark.parametrize("name", named("handoff"))
def test_a_handoff_vector_opens_and_absorbs_at_its_own_iat(
    name: str, py_vector: Callable[[str], dict[str, Any]]
) -> None:
    vector = py_vector(name)
    inputs, env = vector["inputs"], vector["output"]
    assert env["label"] == "tool"
    assert env.get("exp") == (env["iat"] + inputs["ttlMs"] if "ttlMs" in inputs else None)
    child = create_guard()
    result = child.absorb_sealed(env, hs_key(inputs), now=at(env["iat"]))
    assert (result.opened, result.error) == (True, None)
    assert {s.id: s.label for s in child.sources} == {
        s["id"]: s["label"] for s in js_vector(name)["output"]["payload"]["sources"]
    }


@pytest.mark.parametrize("name", named("memory"))
def test_a_memory_vector_opens_at_its_inner_iat_and_reads_back_unblocked(
    name: str, py_vector: Callable[[str], dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    vector = py_vector(name)
    entry, inner = vector["output"], envelope_of(vector)
    assert open_envelope(inner, hs_key(vector["inputs"]), now=at(inner["iat"]))["payload"] == without_sig(entry)
    monkeypatch.setattr(time, "time", lambda: inner["iat"] / 1000)
    monkeypatch.setattr(time, "time_ns", lambda: inner["iat"] * 1_000_000)
    result = create_guard(memory={"key": hs_key(vector["inputs"])}).memory_read_sealed([entry])
    assert (result.label, entry["label"]) == ("tool", "tool")


@pytest.mark.parametrize("name", named("lock"))
def test_a_lock_vector_installs_and_the_same_tools_verify_clean(
    name: str, py_vector: Callable[[str], dict[str, Any]]
) -> None:
    vector = py_vector(name)
    guard = create_guard()
    guard.lock(vector["output"])
    assert guard.lock_state.lock == vector["output"]
    assert guard.verify(vector["inputs"]["tools"]) == []


@pytest.mark.parametrize("name", named("error"))
def test_an_error_vector_fails_to_open_with_its_recorded_code(
    name: str, py_vector: Callable[[str], dict[str, Any]]
) -> None:
    vector = py_vector(name)
    out = vector["output"]
    assert out["code"] == vector["inputs"]["code"]
    with pytest.raises(EnvelopeError) as raised:
        open_envelope(out["envelope"], hs_key(vector["inputs"]), now=at(out["now"]))
    assert raised.value.code == out["code"]


@pytest.mark.parametrize("name", named(*PY_KINDS))
def test_build_reproduces_every_non_random_field_of_the_fixture(
    name: str, built: dict[str, Any], py_vector: Callable[[str], dict[str, Any]]
) -> None:
    rebuilt = next(v for v in built["vectors"] if v["name"] == name)
    assert stable(rebuilt) == stable(py_vector(name))


@pytest.mark.parametrize("name", named(*PY_KINDS))
def test_the_fixture_equals_the_js_golden_apart_from_nonce_and_signature(
    name: str, py_vector: Callable[[str], dict[str, Any]]
) -> None:
    assert stable(py_vector(name)) == stable(js_vector(name))


def test_build_draws_a_fresh_nonce_on_every_call(maker: ModuleType, built: dict[str, Any]) -> None:
    again = maker.build()
    assert envelope_of(again["vectors"][0])["nonce"] != envelope_of(built["vectors"][0])["nonce"]


def check_layout(text: str, written: dict[str, Any]) -> None:
    lines = text.split("\n")
    count = len(written["vectors"])
    assert len(lines) == count + 6
    assert (lines[0], lines[2], lines[-3], lines[-2], lines[-1]) == ("{", '  "vectors": [', "  ]", "}", "")
    assert lines[1].startswith('  "header": ') and lines[1].endswith(",")
    assert json.loads(lines[1].removeprefix('  "header": ').removesuffix(",")) == written["header"]
    assert [json.loads(line.strip().rstrip(",")) for line in lines[3 : 3 + count]] == written["vectors"]


def test_write_persists_the_built_golden_in_the_js_layout(maker: ModuleType, tmp_path: Path) -> None:
    target = tmp_path / "out" / "envelope.py.golden.json"
    maker.write(target)
    text = target.read_text(encoding="utf-8")
    written = json.loads(text)
    check_layout(text, written)
    assert written["header"] == JS["header"]
    assert [(v["name"], v["kind"], v["inputs"]) for v in written["vectors"]] == [
        (v["name"], v["kind"], v["inputs"]) for v in JS_VECTORS
    ]


def test_the_script_writes_to_the_path_given_by_out(tmp_path: Path) -> None:
    target = tmp_path / "cli.json"
    script = Path(__file__).resolve().parent / "make_envelope_golden.py"
    done = subprocess.run(
        [sys.executable, str(script), "--out", str(target)], capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    assert [v["name"] for v in json.loads(target.read_text(encoding="utf-8"))["vectors"]] == [
        v["name"] for v in JS_VECTORS
    ]
