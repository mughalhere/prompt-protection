"""Write tests/__fixtures__/envelope.py.golden.json: the JS envelope golden's inputs, resealed with Python.

Run from the repo root or from python/: ``python tests/make_envelope_golden.py [--out PATH]``.
Handoff, memory and lock vectors are sealed at the wall-clock time the JS golden recorded for them.
The hs256 and error vectors are sealed at header.now. EdDSA vectors are skipped because Python defers EdDSA.
"""

import argparse
import calendar
import json
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any
from unittest import mock

from prompt_protection.envelope import seal
from prompt_protection.guard import create_guard

ROOT = Path(__file__).resolve().parents[2]
JS_PATH = ROOT / "tests" / "guard" / "__fixtures__" / "envelope.golden.json"
PY_PATH = Path(__file__).resolve().parent / "__fixtures__" / "envelope.py.golden.json"
PY_KINDS = ("hs256", "handoff", "memory", "lock", "error")


@contextmanager
def clock_at(ms: int) -> Iterator[None]:
    """Pin the wall clock to ``ms``. time.time sits half a millisecond in, so int(t * 1000) never rounds down."""
    with (
        mock.patch.object(time, "time", lambda: (ms + 0.5) / 1000),
        mock.patch.object(time, "time_ns", lambda: ms * 1_000_000),
    ):
        yield


def iso_to_ms(stamp: str) -> int:
    parsed = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S.%fZ")
    return calendar.timegm(parsed.utctimetuple()) * 1000 + parsed.microsecond // 1000


def hs_key(header: dict[str, Any], inputs: dict[str, Any]) -> dict[str, Any]:
    return {"alg": "HS256", "secret": header["secret"], **({"kid": inputs["kid"]} if "kid" in inputs else {})}


def seal_inputs(header: dict[str, Any], inputs: dict[str, Any]) -> dict[str, Any]:
    return {
        "label": inputs["label"],
        "ttl_ms": inputs.get("ttlMs"),
        "from_": inputs.get("from"),
        "now": lambda: header["now"],
    }


def seal_error(header: dict[str, Any], inputs: dict[str, Any]) -> dict[str, Any]:
    env = dict(seal(inputs["payload"], hs_key(header, inputs), **seal_inputs(header, inputs)))
    if inputs["code"] != "bad-signature":
        return {"envelope": env, "code": inputs["code"], "now": env["exp"] + 1}
    flipped = "B" if env["sig"][0] == "A" else "A"
    return {"envelope": {**env, "sig": flipped + env["sig"][1:]}, "code": inputs["code"], "now": header["now"]}


def seal_handoff(header: dict[str, Any], inputs: dict[str, Any], recorded: Any) -> Any:
    guard = create_guard()
    for taint in inputs["taints"]:
        guard.taint(taint["tool"], taint["text"])
    with clock_at(recorded["iat"]):
        return guard.seal_handoff(hs_key(header, inputs), ttl_ms=inputs.get("ttlMs"), from_=inputs.get("from"))


def seal_memory(header: dict[str, Any], inputs: dict[str, Any], recorded: Any) -> Any:
    guard = create_guard()
    with clock_at(iso_to_ms(recorded["ts"])):
        entry = guard.taint_memory_write(inputs["tool"], inputs["value"]).entry
    with clock_at(json.loads(recorded["sig"])["iat"]):
        return guard.seal_memory_entry(entry, hs_key(header, inputs))


def seal_lock(inputs: dict[str, Any], recorded: Any) -> Any:
    with clock_at(iso_to_ms(recorded["createdAt"])):
        return create_guard().pin(inputs["tools"])


def output_of(header: dict[str, Any], vector: dict[str, Any]) -> Any:
    kind, inputs, recorded = vector["kind"], vector["inputs"], vector["output"]
    if kind == "hs256":
        return seal(inputs["payload"], hs_key(header, inputs), **seal_inputs(header, inputs))
    if kind == "handoff":
        return seal_handoff(header, inputs, recorded)
    if kind == "memory":
        return seal_memory(header, inputs, recorded)
    return seal_lock(inputs, recorded) if kind == "lock" else seal_error(header, inputs)


def build(js_path: Path = JS_PATH) -> dict[str, Any]:
    """Reseal every JS vector of a Python kind, keeping the JS header, names, kinds and inputs."""
    js = json.loads(js_path.read_text(encoding="utf-8"))
    vectors = [
        {"name": v["name"], "kind": v["kind"], "inputs": v["inputs"], "output": output_of(js["header"], v)}
        for v in js["vectors"]
        if v["kind"] in PY_KINDS
    ]
    return {"header": js["header"], "vectors": vectors}


def golden_text(golden: dict[str, Any]) -> str:
    def dump(value: Any) -> str:
        return json.dumps(value, separators=(",", ":"))

    rows = ",\n".join(f"    {dump(v)}" for v in golden["vectors"])
    return f'{{\n  "header": {dump(golden["header"])},\n  "vectors": [\n{rows}\n  ]\n}}\n'


def write(path: Path = PY_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(golden_text(build()), encoding="utf-8")
    return path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--out", type=Path, default=PY_PATH, help="where to write the fixture")
    print(f"wrote {write(parser.parse_args(argv).out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
