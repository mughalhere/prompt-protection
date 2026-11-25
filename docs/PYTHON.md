# Python port: where it differs from the JS package

The Python package in `python/` ports the JS library. Node is the oracle for its decisions.
Exact parity is claimed for the published golden corpus only.

This page covers Unicode drift, custom rules, non-finite scores, `canonical_json`, tool-result text and logging. It gives the Python and JS differences in those areas, and why.

## Unicode drift

Python `unicodedata` can differ from Node ICU across Unicode versions. This affects `NFKC` normalization and `str.lower()`.
The Node reference is `tests/__fixtures__/unicode-node.json`. It was exported on Node 22 with Unicode 17.0 and ICU 78.3.

Each block below lists the code points where one Python minor differs from that table. A code point differs when its `NFKC` form or its lowercase form is not the one Node gives.
A range is `lo-hi` or a single code point. Values are lowercase hex, sorted, and adjacent code points are merged.

`python/tests/test_unicode_drift.py` recomputes the running minor's block on every run. The test fails when this page and the interpreter disagree.

```json
{"python": "3.10", "unidata": "13.0.0", "nfkc": ["a7f1-a7f4", "10781-10785", "10787-107b0", "107b2-107ba", "1ccd6-1ccf9", "1e030-1e06d"], "lower": ["1c89", "2c2f", "a7c0", "a7cb-a7cc", "a7ce", "a7d0", "a7d2", "a7d4", "a7d6", "a7d8", "a7da", "a7dc", "10570-1057a", "1057c-1058a", "1058c-10592", "10594-10595", "10d50-10d65", "16ea0-16eb8"]}
```

```json
{"python": "3.11", "unidata": "14.0.0", "nfkc": ["a7f1", "1ccd6-1ccf9", "1e030-1e06d"], "lower": ["1c89", "a7cb-a7cc", "a7ce", "a7d2", "a7d4", "a7da", "a7dc", "10d50-10d65", "16ea0-16eb8"]}
```

```json
{"python": "3.12", "unidata": "15.0.0", "nfkc": ["a7f1", "1ccd6-1ccf9"], "lower": ["1c89", "a7cb-a7cc", "a7ce", "a7d2", "a7d4", "a7da", "a7dc", "10d50-10d65", "16ea0-16eb8"]}
```

```json
{"python": "3.13", "unidata": "15.1.0", "nfkc": ["a7f1", "1ccd6-1ccf9"], "lower": ["1c89", "a7cb-a7cc", "a7ce", "a7d2", "a7d4", "a7da", "a7dc", "10d50-10d65", "16ea0-16eb8"]}
```

The delta is a known residual risk. The differential corpus measures it, and any delta found is recorded here and not hidden.
A text that holds a listed code point can normalize differently in Python than in Node.

## Custom rules

A custom rule is a dict that holds a compiled `re.Pattern`. The pattern uses Python `re` syntax and semantics.
Only the built-in rules are translated from JS regex syntax. A custom rule is never translated.

`analyze_prompt` and the guard read the pattern's source text and compile it again with `re.ASCII | re.IGNORECASE`. Flags on the pattern you pass are dropped.
JS rebuilds every rule as `new RegExp(source, 'gi')`, so it forces case-insensitive matching too.

With `re.ASCII`, the case-insensitive match covers ASCII letters only. JS `/i` also folds non-ASCII letters.
A pattern that depends on folding a non-ASCII letter can match in JS and not in Python.

A custom rule that matches the empty string terminates in Python. The scorer advances one UTF-16 unit after an empty match.
JS `score()` never returns on the same input. A rule such as `x*` over `hello` hangs a JS call.

The library does not check a custom-rule weight. A non-finite weight reaches the scorer, as the next section describes.

A built-in `Rule.to_dict()` has no `description` key. The JS rule object carries one.

## Non-finite scores

The scorer computes the score as `100 * (1 - exp(-raw / 15))` and rounds it. JS rounds whatever number results.
Python raises `ValueError` from `score()` when that number is not finite before rounding. A Python `int` score cannot hold `NaN` or `-Infinity`.

| Custom-rule weight | JS score | Python |
|---|---|---|
| `-11000` | `-Infinity` | `ValueError` |
| `-Infinity` | `-Infinity` | `ValueError` |
| `NaN` | `NaN` | `ValueError` |
| `+Infinity` | `100` | `100` |

A finite weight such as `-11000` can also overflow `exp`. The scorer treats an overflowing `exp` as infinity, as JS does.
`analyze_prompt` turns the `ValueError` into an `internal-error` analysis failure. The result then follows `fail_mode`.

## `canonical_json`

`canonical_json` raises `CanonicalJsonError` with code `unsupported` for a value that has no JSON form and no `to_dict()`.
This covers a set, `bytes`, a mapping key that is not a `str`, a function, a class and a class instance.

JS treats a function or a class differently. It writes `null` for one in an array, and it drops the key in an object.
JS raises for a class instance with no `toJSON`, as Python does for one with no `to_dict()`.
The Python guard stays fail-closed. A callable inside tool-call arguments makes `check_tool_call` return a block with `internal-error`, or an allow with `internal-error` under `fail_mode="open"`. JS drops the function or class and allows the call.

Two parts of the JS contract have no Python equivalent:

- The `bigint` code. Python has no bigint type. An `int` past float range raises with code `non-finite`.
- The clause that omits `undefined` members. Python has no `undefined`.

The same error text names the type and never prints the value.

## Tool-result text (`stringify_value`)

`stringify_value` returns the text the guard scans for provenance. It decides what a tool result looks like to the scanner.
A `str` stays as it is, `None` gives an empty string, and a JSON-shaped value gives compact JSON as in JS.

Python differs from JS for values that JSON cannot represent. JS gives text such as `{}`, `[object Object]`, `true`, `false`, `null` or a comma-joined list for them. Python prints the content of a set, a non-string key and an out-of-range number, so the scan sees it. It prints a fixed marker for an object it will not read.

### What prints faithfully

The function renders a value faithfully only for these types:

- an exact `dict`, `list`, `tuple`, `set` and `frozenset`
- an exact `str`, `int`, `float`, `bool` and `None`
- `bytes` and `range`, as exact types
- the closed leaf set below

A subclass of `str`, `int`, `float` or `bool` prints its base value. An `IntEnum` prints its number, and `bool` keeps `True` and `False`.
The leaf set prints through the base type's own text: `complex`, `Decimal`, `Fraction`, `date`, `time`, `datetime`, `timedelta`, `timezone`, `UUID` and `PurePath`, with subclasses.
A `re.Pattern` prints its `.pattern`. A function, method or class prints its `__qualname__`.

An `Enum` member prints its value. A member of a `str`, `int`, `float` or leaf mixin prints its base value.
Any other member prints its stored value, read without running class code. A member with no stored value prints the marker.

### What does not render

Every other value prints `<Type not rendered>`, where `Type` is the qualified name of its type. None of its code runs.
This covers a container subclass such as `OrderedDict`, `defaultdict` or `deque`, a `namedtuple`, a class instance, an exception, an iterator and a generator.
The function reads no field, item or element of such a value. A `__str__` or `__repr__` on the object is never called.

`stringify_value` therefore does not walk an object's fields.
A tool result can hide text in the `__str__` or attributes of an object it controls. The marker removes that channel.

`TaintedSource` carries a boolean `unrenderable`. It is `True` when any part of the value printed the marker, including a dict key and a nested value.
It stays `False` for a `<too deep>` cut. Guard decisions never read the flag.

### Numbers

A JSON number past float range stays an exact Python `int`. JS gives `Infinity` at top level and `null` when the number sits inside a container.
A container that holds such an `int` prints in Python text form, with the digits of the number exact.

An `int` over the digit limit prints as `hex()` for that value only. The sign does not count toward the limit.
The limit is `min(4300, sys.get_int_max_str_digits())` when that function exists and returns a non-zero value. Otherwise it is 4300.
The output is the same on every supported Python version.
In a process that lowers the interpreter limit below 4300 on Python 3.11 or later, the hex form starts at the lowered limit.

The rule applies inside every exact container and to the bounds of a `range`. The library never changes the interpreter limit.

### Depth and keys

One cap of 300 serves both the JSON path and the Python text path. A value up to depth 300 prints as JSON, as JS does.
A deeper container prints `<too deep>`. Only the too-deep subtree is replaced, and shallower values stay visible.

Two keys of one `dict` can give the same text, for example `1` and `'1'`. JS holds one key for them.
Python then prints every pair in its own text form, such as `{1: 'a', '1': 'b'}`.

## Logging

`emit_output_log` is deferred. The Python package has no `analyze_output`, which is its only caller, so nothing would use it.
It will return when `analyze_output` is ported.

Loggers are sync-only. A logger that returns an awaitable gets no await and no scheduling.
Python reports every awaitable result through `on_logger_error` as a `TypeError` that names the sync-only contract. It closes a coroutine and never cancels a `Future` or a `Task`.
This report never changes a verdict. A logger that raises synchronously follows the normal logger-error path.
