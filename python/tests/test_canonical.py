"""RED tests for prompt_protection.canonical. Port of src/utils/canonical.ts.

Oracle: Node 22 against the built dist. Run from the prompt-protection root:
  node -e "import('./dist/guard/index.js').then(m => console.log(m.canonicalJson(<js>)))"
  node -e "import('./dist/guard/index.js').then(async m => console.log(await m.digest(<js>), m.digestSyncWeak(<js>)))"
`<js>` is the `js` argument of each case. `fnv1a64Hex` is not exported, so its body is lifted from dist/guard/index.js.
"""

import math
import re
from collections.abc import Callable

import pytest

from prompt_protection.canonical import (
    CanonicalJsonError,
    canonical_json,
    digest,
    digest_sync_weak,
    fnv1a64_hex,
)


class Boxed:
    """A Python stand-in for a JS object with ``toJSON``."""

    def __init__(self, payload: object) -> None:
        self.payload = payload

    def to_dict(self) -> object:
        return self.payload


class Plain:
    """A class instance with neither ``to_dict`` nor a JSON form."""


def case(name: str, value: object, js: str, expected: str) -> object:
    """Build one parametrized row; ``js`` is the oracle expression and is documentation only."""
    return pytest.param(value, expected, id=name)


def nest(levels: int, wrap: Callable[[object], object]) -> object:
    value: object = 1
    for _ in range(levels):
        value = wrap(value)
    return value


def self_dict() -> dict[str, object]:
    cyclic: dict[str, object] = {}
    cyclic["self"] = cyclic
    return cyclic


def self_list() -> list[object]:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    return cyclic


def mutual_dicts() -> dict[str, object]:
    first: dict[str, object] = {}
    first["second"] = {"first": first}
    return first


SHARED = {"x": 1}
CTL_STRING = 'a"b\\c\n\t\b\f\r\x01\x1f\x7f'

CANONICAL_CASES = [
    case(
        "keys-utf16-surrogate-before-fullwidth",
        {"\uff5e": 1, "\U0001f600": 2},
        r"{'\uff5e':1,'\ud83d\ude00':2}",
        '{"\U0001f600":2,"\uff5e":1}',
    ),
    case(
        "keys-rfc8785-euro-before-emoji",
        {"\U0001f600": 1, "\u20ac": 2, "a": 3},
        r"{'\ud83d\ude00':1,'\u20ac':2,a:3}",
        '{"a":3,"\u20ac":2,"\U0001f600":1}',
    ),
    case(
        "keys-digit-strings-sort-as-text",
        {"10": 1, "9": 2, "A": 3, "a": 4},
        "{'10':1,'9':2,A:3,a:4}",
        '{"10":1,"9":2,"A":3,"a":4}',
    ),
    case(
        "keys-sorted-recursively",
        {"b": 1, "a": [{"d": 1, "c": 2}]},
        "{b:1,a:[{d:1,c:2}]}",
        '{"a":[{"c":2,"d":1}],"b":1}',
    ),
    case(
        "nested-objects-and-arrays",
        {"z": [1, [2, {"y": "q"}]], "a": {"b": {"c": []}}},
        "{z:[1,[2,{y:'q'}]],a:{b:{c:[]}}}",
        '{"a":{"b":{"c":[]}},"z":[1,[2,{"y":"q"}]]}',
    ),
    case("empty-object", {}, "{}", "{}"),
    case("empty-array", [], "[]", "[]"),
    case("tuple-is-array", (1, (2, 3)), "[1,[2,3]]", "[1,[2,3]]"),
    case("empty-tuple", (), "[]", "[]"),
    case("zero-int", 0, "0", "0"),
    case("negative-zero-folds", -0.0, "-0", "0"),
    case("float-0.1", 0.1, "0.1", "0.1"),
    case("float-1.5", 1.5, "1.5", "1.5"),
    case("float-negative", -1.5, "-1.5", "-1.5"),
    case("integral-float-has-no-point", 100.0, "100", "100"),
    case("float-1e21-uses-exponent", 1e21, "1e21", "1e+21"),
    case("float-1e20-stays-positional", 1e20, "1e20", "100000000000000000000"),
    case("float-1e-7-uses-exponent", 1e-7, "1e-7", "1e-7"),
    case("float-1e-6-stays-positional", 1e-6, "1e-6", "0.000001"),
    case("float-denormal-min", 5e-324, "5e-324", "5e-324"),
    case("float-1e300", 1e300, "1e300", "1e+300"),
    case("float-max", 1.7976931348623157e308, "Number.MAX_VALUE", "1.7976931348623157e+308"),
    case("int-2^53", 2**53, "2**53", "9007199254740992"),
    case("int-2^53+1-rounds-like-js", 2**53 + 1, "2**53+1", "9007199254740992"),
    case("int-negative-2^53", -(2**53), "-(2**53)", "-9007199254740992"),
    case("int-2^63", 2**63, "2**63", "9223372036854776000"),
    case("int-2^64", 2**64, "2**64", "18446744073709552000"),
    case("int-1e20", 10**20, "1e20", "100000000000000000000"),
    case("int-1e21-uses-exponent", 10**21, "1e21", "1e+21"),
    case("int-beyond-float-precision", 123456789012345680000, "123456789012345680000", "123456789012345680000"),
    case(
        "numbers-in-one-object",
        {"a": 1e21, "b": 1e-7, "c": 0.1, "d": -0.0, "e": 100},
        "{a:1e21,b:1e-7,c:0.1,d:-0,e:100}",
        '{"a":1e+21,"b":1e-7,"c":0.1,"d":0,"e":100}',
    ),
    case("true", True, "true", "true"),
    case("false", False, "false", "false"),
    case("bool-before-int-in-array", [True, 1, False], "[true,1,false]", "[true,1,false]"),
    case(
        "bool-before-int-in-object",
        {"t": True, "f": False, "one": 1, "zero": 0},
        "{t:true,f:false,one:1,zero:0}",
        '{"f":false,"one":1,"t":true,"zero":0}',
    ),
    case("bool-in-tuple", (True, 1), "[true,1]", "[true,1]"),
    case("none-is-null", None, "null", "null"),
    case("none-member-kept", {"a": None}, "{a:null}", '{"a":null}'),
    case("none-in-arrays", [None, [None]], "[null,[null]]", "[null,[null]]"),
    case("string-empty", "", "''", '""'),
    case(
        "string-escapes-like-json-stringify",
        CTL_STRING,
        r"'a\"b\\c\n\t\b\f\r\u0001\u001f\u007f'",
        '"a\\"b\\\\c\\n\\t\\b\\f\\r\\u0001\\u001f\x7f"',
    ),
    case("string-u2028-stays-raw", "\u2028", r"'\u2028'", '"\u2028"'),
    case("string-astral-stays-raw", "a\U0001f600b", r"'a\ud83d\ude00b'", '"a\U0001f600b"'),
    case(
        "string-non-ascii-stays-raw",
        "caf\u00e9 \u65e5\u672c\u8a9e",
        r"'caf\u00e9 \u65e5\u672c\u8a9e'",
        '"caf\u00e9 \u65e5\u672c\u8a9e"',
    ),
    case("string-lone-high-surrogate-escaped", "\ud83d", r"'\ud83d'", '"\\ud83d"'),
    case("string-lone-low-surrogate-escaped", "x\ude00", r"'x\ude00'", '"x\\ude00"'),
    case("key-lone-surrogate-escaped", {"\ud83d": 1}, r"{'\ud83d':1}", '{"\\ud83d":1}'),
    case("to_dict-object-then-sorted", Boxed({"z": 1, "y": 2}), "{toJSON:()=>({z:1,y:2})}", '{"y":2,"z":1}'),
    case("to_dict-scalar", Boxed(5), "{toJSON:()=>5}", "5"),
    case("to_dict-none", Boxed(None), "{toJSON:()=>null}", "null"),
    case("to_dict-string", Boxed("x"), "{toJSON:()=>'x'}", '"x"'),
    case(
        "to_dict-nested-in-object-and-array",
        {"b": Boxed({"q": 1, "p": 2}), "a": [Boxed("hi")]},
        "{b:{toJSON:()=>({q:1,p:2})},a:[{toJSON:()=>'hi'}]}",
        '{"a":["hi"],"b":{"p":2,"q":1}}',
    ),
    case(
        "shared-reference-is-not-a-cycle",
        {"a": SHARED, "b": SHARED},
        "(s=>({a:s,b:s}))({x:1})",
        '{"a":{"x":1},"b":{"x":1}}',
    ),
    case("depth-65-lists-is-allowed", nest(65, lambda x: [x]), "65 nested arrays", "[" * 65 + "1" + "]" * 65),
    case("depth-65-dicts-is-allowed", nest(65, lambda x: {"k": x}), "65 nested {k:}", '{"k":' * 65 + "1" + "}" * 65),
]

ERROR_CASES = [
    pytest.param(lambda: {"a": math.nan}, "non-finite", id="nan-member"),
    pytest.param(lambda: math.nan, "non-finite", id="nan-top-level"),
    pytest.param(lambda: [math.inf], "non-finite", id="inf-in-list"),
    pytest.param(lambda: -math.inf, "non-finite", id="negative-inf"),
    pytest.param(lambda: 10**400, "non-finite", id="int-too-large-for-a-float"),
    pytest.param(lambda: -(10**400), "non-finite", id="negative-int-too-large-for-a-float"),
    pytest.param(lambda: {"a": Boxed(math.nan)}, "non-finite", id="nan-returned-by-to_dict"),
    pytest.param(self_dict, "cycle", id="cycle-dict"),
    pytest.param(self_list, "cycle", id="cycle-list"),
    pytest.param(mutual_dicts, "cycle", id="cycle-two-dicts"),
    pytest.param(lambda: nest(66, lambda x: [x]), "depth", id="depth-66-lists"),
    pytest.param(lambda: nest(66, lambda x: {"k": x}), "depth", id="depth-66-dicts"),
    pytest.param(lambda: nest(66, lambda x: (x,)), "depth", id="depth-66-tuples"),
    pytest.param(lambda: nest(100, lambda x: [x]), "depth", id="depth-100-lists"),
    pytest.param(lambda: {1, 2}, "unsupported", id="set"),
    pytest.param(lambda: frozenset({1}), "unsupported", id="frozenset"),
    pytest.param(lambda: {"a": b"x"}, "unsupported", id="bytes-member"),
    pytest.param(lambda: {1: "a"}, "unsupported", id="int-key"),
    pytest.param(lambda: {None: 1}, "unsupported", id="none-key"),
    pytest.param(lambda: {True: 1}, "unsupported", id="bool-key"),
    pytest.param(lambda: {("a",): 1}, "unsupported", id="tuple-key"),
    pytest.param(lambda: {"a": [{1: 2}]}, "unsupported", id="non-str-key-nested"),
    pytest.param(Plain, "unsupported", id="class-instance-without-to_dict"),
    pytest.param(object, "unsupported", id="bare-object"),
    pytest.param(lambda: {"a": Boxed({1, 2})}, "unsupported", id="set-returned-by-to_dict"),
]

DIGEST_CASES = [
    ("empty-string", "", "''", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "cbf29ce484222325"),
    (
        "ascii-string-hashed-raw",
        "hello",
        "'hello'",
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "a430d84680aabd0b",
    ),
    (
        "astral-string",
        "a\U0001f600b",
        r"'a\ud83d\ude00b'",
        "6fba5b2ea783ded096fc2444d540ffbdf49168df30993b155b7efb683313f110",
        "33c526094d790e49",
    ),
    (
        "cjk-string",
        "\u65e5\u672c\u8a9e",
        r"'\u65e5\u672c\u8a9e'",
        "77710aedc74ecfa33685e33a6c7df5cc83004da1bdcef7fb280f5c2b2e97e0a5",
        "ee9ee2b5c854ef87",
    ),
    (
        "lone-high-surrogate-string",
        "\ud83d",
        r"'\ud83d'",
        "83d544ccc223c057d2bf80d3f2a32982c32c3c0db8e2674820da5064783fb097",
        "6f6d661b9658624a",
    ),
    (
        "lone-low-surrogate-inside-string",
        "x\ude00y",
        r"'x\ude00y'",
        "0b37743370331e33808c0dd0167563798a3c324504cf0055d2b0ac81578d2c58",
        "f4236479d8aa3f03",
    ),
    (
        "nul-string",
        "\x00",
        r"'\u0000'",
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "af63bd4c8601b7df",
    ),
    (
        "long-string",
        "a" * 1000,
        "'a'.repeat(1000)",
        "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3",
        "3c835852fbac676d",
    ),
    (
        "json-text-string",
        '{"a":2,"b":1}',
        '\'{"a":2,"b":1}\'',
        "d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772",
        "f85f5878cbf2dc03",
    ),
    (
        "object-hashed-via-canonical-form",
        {"b": 1, "a": 2},
        "{b:1,a:2}",
        "d3626ac30a87e6f7a6428233b3c68299976865fa5508e4267c5415c76af7a772",
        "f85f5878cbf2dc03",
    ),
    (
        "nested-object-with-astral-string",
        {"z": [1, [2, {"y": "\U0001f600"}]], "a": {"b": None}},
        r"{z:[1,[2,{y:'\ud83d\ude00'}]],a:{b:null}}",
        "47fb3d546d039dff6178e8ad558f9853e7a4c767a4fbb801875ea4b80293361d",
        "9fbb4c002df8a856",
    ),
    (
        "object-with-utf16-key-order",
        {"\uff5e": 1, "\U0001f600": 2},
        r"{'\uff5e':1,'\ud83d\ude00':2}",
        "c44a324298283d910e4120a2ff3c2d7746b4a5c9f2d9625c67f6abb58748cf31",
        "f4d7ea483ee7e33d",
    ),
    (
        "array",
        [1, 2, 3],
        "[1,2,3]",
        "a615eeaee21de5179de080de8c3052c8da901138406ba71c38c032845f7d54f4",
        "28bbee4398699f19",
    ),
    ("none", None, "null", "74234e98afe7498fb5daf1f36ac2d78acc339464f950703b8c019892f982b90b", "5b9bc4ba528108e4"),
    ("int", 42, "42", "73475cb40a568e8da8a045ced110137e159f890ac4da883b6b17dc651b3a8049", "07ee7e07b4b19223"),
    ("float", 0.1, "0.1", "14be4b45f18e0d8c67b4f719b5144eee88497e413709d11d85b096d8e2346310", "4e18dd181d0a2066"),
    ("true", True, "true", "b5bea41b6c623f7c09f1bf24dcae58ebab3c0cdd90ad966bc43a45b44867e12b", "5b5c98ef514dbfa5"),
    (
        "bool-int-mix",
        [True, 1, False],
        "[true,1,false]",
        "af8c4c934948f8e5967d9f98318a8e8caecca65a06904e0a7ccf78405b98363d",
        "7750fdd54f5a001d",
    ),
    ("empty-object", {}, "{}", "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "08f44b07b5901a25"),
]

FNV_CASES = [
    pytest.param("", "cbf29ce484222325", id="offset-basis"),
    pytest.param("a", "af63dc4c8601ec8c", id="a"),
    pytest.param("hello", "a430d84680aabd0b", id="hello"),
    pytest.param("a\U0001f600b", "33c526094d790e49", id="astral"),
    pytest.param("k0", "08be0e07b562230e", id="leading-zero-is-padded"),
    pytest.param("\ud83d", "6f6d661b9658624a", id="lone-surrogate-hashes-as-replacement-char"),
]


def code_of(factory: Callable[[], object]) -> str:
    with pytest.raises(CanonicalJsonError) as info:
        canonical_json(factory())
    assert isinstance(info.value, TypeError)
    return str(info.value.code)


@pytest.mark.parametrize(("value", "expected"), CANONICAL_CASES)
def test_canonical_json_matches_js_oracle(value: object, expected: str) -> None:
    assert canonical_json(value) == expected


@pytest.mark.parametrize(("factory", "code"), ERROR_CASES)
def test_canonical_json_fails_closed_with_the_js_code(factory: Callable[[], object], code: str) -> None:
    assert code_of(factory) == code


def test_error_is_a_type_error_carrying_code_and_message() -> None:
    err = CanonicalJsonError("depth", "nesting deeper than 64")
    assert isinstance(err, TypeError)
    assert err.code == "depth"
    assert str(err) == "nesting deeper than 64"


def test_nan_and_none_do_not_collide() -> None:
    assert canonical_json({"a": None}) == '{"a":null}'
    assert code_of(lambda: {"a": math.nan}) == "non-finite"


@pytest.mark.parametrize(("value", "sha"), [pytest.param(v, sha, id=n) for n, v, _js, sha, _weak in DIGEST_CASES])
def test_digest_matches_js_oracle(value: object, sha: str) -> None:
    assert digest(value) == f"sha256:{sha}"


@pytest.mark.parametrize(("value", "weak"), [pytest.param(v, weak, id=n) for n, v, _js, _sha, weak in DIGEST_CASES])
def test_digest_sync_weak_matches_js_oracle(value: object, weak: str) -> None:
    assert digest_sync_weak(value) == f"fnv1a64:{weak}"


@pytest.mark.parametrize(("text", "expected"), FNV_CASES)
def test_fnv1a64_hex_matches_js_oracle(text: str, expected: str) -> None:
    assert fnv1a64_hex(text) == expected
    assert re.fullmatch(r"[0-9a-f]{16}", fnv1a64_hex(text))


def test_digest_hashes_strings_raw_and_objects_through_canonical_json() -> None:
    assert digest({"b": 1, "a": 2}) == digest('{"a":2,"b":1}')
    assert re.fullmatch(r"sha256:[0-9a-f]{64}", digest({"b": 1, "a": 2}))
    assert digest("x") != digest('"x"')


def test_digest_sync_weak_is_fnv_of_the_canonical_form() -> None:
    canonical_text = '{"a":2,"b":1}'
    assert digest_sync_weak({"b": 1, "a": 2}) == f"fnv1a64:{fnv1a64_hex(canonical_text)}"
    assert digest_sync_weak("x") == f"fnv1a64:{fnv1a64_hex('x')}"


@pytest.mark.parametrize("function", [digest, digest_sync_weak])
def test_digests_reject_what_canonical_json_rejects(function: Callable[[object], str]) -> None:
    with pytest.raises(CanonicalJsonError) as info:
        function({"a": math.nan})
    assert info.value.code == "non-finite"
