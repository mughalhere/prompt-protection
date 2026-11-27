"""RED tests for prompt_protection.guard.sinks (twin of src/guard/sinks.ts: Node is the oracle)."""

import pytest

from prompt_protection.guard.sinks import EXEC_SINKS, EXFIL_SINKS, create_sink_resolver, default_sink

# Classified by node: require('./dist/guard/index.cjs').defaultSink(name). Covers every DEFAULT_SINK_PATTERNS entry.
NAMES_BY_SINK = {
    "none": (
        "read_email fetch_url get_record get GET_X getaway getter list listing search_docs query lookup_user "
        "find view browse load open open_file reply_to_user final_answer respond answer answer_42 answerer "
        "fetch_http runner frobnicate Ab"
    ).split(),
    "network": (
        "http_post HTTP_POST curl webhook_fire socket dns_lookup http_pay http_email send_report url request "
        "api send submit call dispatch push sync export download navigate visit connect"
    ).split(),
    "payment": (
        "pay payment_run charge_card transfer checkout purchase_item refund billing invoice wire_funds donate "
        "send_payment stripe_transfer"
    ).split(),
    "exec": (
        "exec shell bash command cmd terminal spawn eval script run run_it sudo process run_email mail_run"
    ).split(),
    "email": ("send_email email mail smtp gmail outlook email_message").split(),
    "message": (
        "slack_post_message discord teams sms whatsapp telegram signal imessage message msg chat dm dm_user "
        "comment tweet post post_it publish notify notification broadcast post_message_write"
    ).split(),
    "file-write": (
        "write_file save create delete remove append upload edit update move rename mkdir rm rm_rf unlink "
        "put_file store persist UPDATE_ROW"
    ).split(),
}

# JS "$" matches only at the very end of the name, so a trailing newline defeats an anchored verb.
TRAILING_NEWLINE_NAMES = {
    "": "none",
    "run\n": "none",
    "dm\n": "none",
    "rm\n": "none",
    "post\n": "none",
    "get_\n": "none",
    "write\n": "file-write",
    "run_\n": "exec",
}

# JS /i without /u folds ASCII only: U+017F (long s), U+0131 (dotless i) and U+212A (Kelvin) never match.
NON_ASCII_FOLD_NAMES = {
    chr(0x17F) + "end_report": "none",
    "d" + chr(0x131) + "scord": "none",
    "soc" + chr(0x212A) + "et": "none",
    "S" + chr(0x17F) + "end": "none",
}

NAME_CASES = (
    [pytest.param(name, sink, id=f"{sink}-{name!r}") for sink, names in NAMES_BY_SINK.items() for name in names]
    + [pytest.param(name, sink, id=f"newline-{name!r}") for name, sink in TRAILING_NEWLINE_NAMES.items()]
    + [
        pytest.param(name, sink, id=f"non-ascii-{name.encode('unicode_escape').decode()}")
        for name, sink in NON_ASCII_FOLD_NAMES.items()
    ]
)

# node: createSinkResolver(undefined | RESOLVER_MAP | function) applied to each name below.
RESOLVER_MAP = {"fetch": "network", "http_post": "none", "send_email": None, "constructor": "exec"}
RESOLVER_FUNCTION_VERDICTS = {"x": "exec", "y": "none"}
# name -> sink from (no sinks, the map, the function)
RESOLVER_ROWS = [
    pytest.param("fetch", ("none", "network", "none"), id="map-overrides-a-read-verb"),
    pytest.param("http_post", ("network", "none", "network"), id="map-overrides-to-none"),
    pytest.param("send_email", ("email", "email", "email"), id="map-entry-that-is-none-falls-back"),
    pytest.param("write_file", ("file-write", "file-write", "file-write"), id="unlisted-uses-defaults"),
    pytest.param("frobnicate", ("none", "none", "none"), id="unknown-tool-is-none"),
    pytest.param("toString", ("none", "none", "none"), id="inherited-object-attribute-is-not-an-entry"),
    pytest.param("constructor", ("none", "exec", "none"), id="own-key-named-like-an-object-attribute"),
    pytest.param("__proto__", ("none", "none", "none"), id="dunder-proto-is-not-an-entry"),
    pytest.param("x", ("none", "none", "exec"), id="function-supplies-a-sink"),
    pytest.param("y", ("none", "none", "none"), id="function-answering-none-is-kept"),
    pytest.param("run_shell", ("exec", "exec", "exec"), id="function-declines-so-defaults-fill-in"),
]


def function_resolver(name: str) -> str | None:
    return RESOLVER_FUNCTION_VERDICTS.get(name)


@pytest.mark.parametrize(("name", "sink"), NAME_CASES)
def test_default_sink_matches_node(name: str, sink: str) -> None:
    assert default_sink(name) == sink


@pytest.mark.parametrize("index", range(3), ids=["no-sinks", "map", "function"])
@pytest.mark.parametrize(("name", "expected"), RESOLVER_ROWS)
def test_create_sink_resolver_matches_node(index: int, name: str, expected: tuple[str, str, str]) -> None:
    resolver = create_sink_resolver((None, RESOLVER_MAP, function_resolver)[index])
    assert resolver(name) == expected[index]


def test_exfil_and_exec_sink_sets_match_node() -> None:
    # node: [...g.EXFIL_SINKS] and [...g.EXEC_SINKS]
    assert set(EXFIL_SINKS) == {"network", "email", "message", "unknown"}
    assert set(EXEC_SINKS) == {"exec", "file-write", "unknown"}
