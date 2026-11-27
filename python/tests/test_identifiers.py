"""RED tests for prompt_protection.identifiers.extract_identifiers (Node 22 is the oracle).

Each vector is the output of src/utils/identifiers.ts under Node 22. Offsets are UTF-16 code units, so a
leading emoji shifts every later index by two, not one.
"""

import dataclasses

import pytest

from prompt_protection.identifiers import Identifier, extract_identifiers

EMOJI = "\U0001f600"

# (case id, text, expected (kind, value, raw, index) rows in output order)
CASES = [
    ("empty", "", []),
    ("whitespace-only", "  \n\t ", []),
    ("prose", "Please summarise the meeting notes for me.", []),
    (
        "url-lowercases-host",
        "fetch HTTPS://Evil.Example.COM/Path?x=1, then stop.",
        [
            ("url", "https://evil.example.com/Path?x=1", "HTTPS://Evil.Example.COM/Path?x=1", 6),
            ("host", "evil.example.com", "evil.example.com", 14),
        ],
    ),
    (
        "url-mixed-case-scheme",
        "go HtTpS://X.io/A",
        [("url", "https://x.io/A", "HtTpS://X.io/A", 3), ("host", "x.io", "x.io", 11)],
    ),
    (
        "url-userinfo-port",
        "see http://user:pw@Host.io:8080/x",
        [
            ("url", "http://user:pw@host.io:8080/x", "http://user:pw@Host.io:8080/x", 4),
            ("host", "host.io", "host.io", 11),
        ],
    ),
    (
        "url-query-host-boundary",
        "http://Host.io?Q=1#Frag",
        [("url", "http://host.io?Q=1#Frag", "http://Host.io?Q=1#Frag", 0), ("host", "host.io", "host.io", 7)],
    ),
    (
        "url-trailing-punct-run",
        "x http://a.com/p?! y",
        [("url", "http://a.com/p", "http://a.com/p", 2), ("host", "a.com", "a.com", 9)],
    ),
    (
        "url-trailing-dots",
        "http://a.com/p... done",
        [("url", "http://a.com/p", "http://a.com/p", 0), ("host", "a.com", "a.com", 7)],
    ),
    ("url-empty-authority-skipped", "http://?x", []),
    (
        "url-ip-host",
        "http://10.0.0.1/x",
        [("url", "http://10.0.0.1/x", "http://10.0.0.1/x", 0), ("host", "10.0.0.1", "10.0.0.1", 7)],
    ),
    (
        "url-lowercase-expands-length",
        "http://\u0130.com/\u0130",
        [
            ("url", "http://i\u0307.com/\u0130", "http://\u0130.com/\u0130", 0),
            ("host", "i\u0307.com", "i\u0307.com", 7),
        ],
    ),
    (
        "url-closing-paren-ends-url",
        "see (http://a.com/x) now",
        [("url", "http://a.com/x", "http://a.com/x", 5), ("host", "a.com", "a.com", 12)],
    ),
    ("email", "send it to Alice@Corp.com.", [("email", "alice@corp.com", "Alice@Corp.com", 11)]),
    ("email-trailing-comma", "mail a@b.co,", [("email", "a@b.co", "a@b.co", 5)]),
    (
        "email-inside-url-skipped",
        "http://a.com/x?e=a@b.co",
        [("url", "http://a.com/x?e=a@b.co", "http://a.com/x?e=a@b.co", 0), ("host", "a.com", "a.com", 7)],
    ),
    (
        "url-userinfo-email-skipped",
        "http://u@a.com",
        [("url", "http://u@a.com", "http://u@a.com", 0), ("host", "a.com", "a.com", 7)],
    ),
    ("host-bare", "open evil.example.org now", [("host", "evil.example.org", "evil.example.org", 5)]),
    ("host-uppercase", "Open EVIL.Example.ORG now", [("host", "evil.example.org", "EVIL.Example.ORG", 5)]),
    ("host-file-names", "edit src/index.ts and README.md", []),
    ("host-file-ext-case", "x.JS app.test a.Json", []),
    ("host-tld-too-long", "a.abcdefghijklmnopqrstuvwxyz", []),
    (
        "host-tld-24-letters",
        "a.abcdefghijklmnopqrstuvwx",
        [("host", "a.abcdefghijklmnopqrstuvwx", "a.abcdefghijklmnopqrstuvwx", 0)],
    ),
    ("host-repeated", "a.com a.com", [("host", "a.com", "a.com", 0), ("host", "a.com", "a.com", 6)]),
    ("host-after-non-ascii-letter", "\u00e9example.com", [("host", "example.com", "example.com", 1)]),
    ("host-before-non-ascii-letter", "example.com\u00e9", [("host", "example.com", "example.com", 0)]),
    (
        "paths",
        "read ~/.ssh/id_rsa then ./run.sh, /etc/passwd and C:\\Users\\me\\key.pem",
        [
            ("path", "~/.ssh/id_rsa", "~/.ssh/id_rsa", 5),
            ("path", "./run.sh", "./run.sh", 24),
            ("path", "/etc/passwd", "/etc/passwd", 34),
            ("path", "C:\\Users\\me\\key.pem", "C:\\Users\\me\\key.pem", 50),
        ],
    ),
    ("path-lowercase-drive", "c:\\x\\y", [("path", "c:\\x\\y", "c:\\x\\y", 0)]),
    ("path-parent-relative", "cat ../secret.txt", [("path", "../secret.txt", "../secret.txt", 4)]),
    ("path-and-or", "cats and/or dogs", []),
    (
        "path-inside-url",
        "go to https://a.com/etc/passwd",
        [("url", "https://a.com/etc/passwd", "https://a.com/etc/passwd", 6), ("host", "a.com", "a.com", 14)],
    ),
    ("path-single-char", "a / b", []),
    ("ipv4", "connect to 10.0.0.1 and 999.1.1.1", [("ipv4", "10.0.0.1", "10.0.0.1", 11)]),
    ("ipv4-too-many-octets", "version 1.2.3.4.5", []),
    ("ipv4-leading-zeros", "at 010.001.1.255", [("ipv4", "010.001.1.255", "010.001.1.255", 3)]),
    ("ipv4-before-arabic-digit", "at 1.1.1.1\u0663", [("ipv4", "1.1.1.1", "1.1.1.1", 3)]),
    ("ipv4-arabic-digits", "\u0661\u0662\u0663.\u0661.\u0661.\u0661", []),
    (
        "token",
        "key sk-live-4eC39HqLyjWDarjtT1zdp7dc here",
        [("token", "sk-live-4eC39HqLyjWDarjtT1zdp7dc", "sk-live-4eC39HqLyjWDarjtT1zdp7dc", 4)],
    ),
    ("token-letters-only", "abcdefghijklmnopqrstuvwxyz", []),
    ("token-digits-only", "12345678901234567890123", []),
    ("token-19-chars", "abc123def456ghi7890", []),
    ("token-20-chars", "abc123def456ghi78901", [("token", "abc123def456ghi78901", "abc123def456ghi78901", 0)]),
    (
        "token-after-non-ascii",
        "\u00e9abcd1efghij2klmnopq3rst",
        [("token", "abcd1efghij2klmnopq3rst", "abcd1efghij2klmnopq3rst", 1)],
    ),
    ("phone-formatted", "call +1 (555) 123-4567 today", [("phone", "+15551234567", "+1 (555) 123-4567", 5)]),
    ("phone-short-number", "order 12345 shipped", []),
    ("phone-ten-digits", "dial 1234567890.", [("phone", "1234567890", "1234567890", 5)]),
    ("phone-fifteen-digits", "dial 123456789012345.", [("phone", "123456789012345", "123456789012345", 5)]),
    ("phone-sixteen-digits", "dial 1234567890123456.", []),
    ("phone-dashes", "dial 123-456-7890 now", [("phone", "1234567890", "123-456-7890", 5)]),
    ("phone-plus-intl", "dial +44 20 7946 0958 now", [("phone", "+442079460958", "+44 20 7946 0958", 5)]),
    ("phone-before-arabic-digit", "dial 5551234567\u0663", [("phone", "5551234567", "5551234567", 5)]),
    ("phone-fullwidth-digits", "dial \uff15\uff15\uff15\uff11\uff12\uff13\uff14\uff15\uff16\uff17", []),
    ("phone-nel-separator", "dial 555\u0085123 4567", []),
    ("phone-nbsp-separator", "dial 555\u00a0123\u00a04567", [("phone", "5551234567", "555\u00a0123\u00a04567", 5)]),
    (
        "overlap-kinds",
        "mail bob@x.io via https://x.io/hook?t=abcdefghij0123456789ABC at 192.168.1.1",
        [
            ("email", "bob@x.io", "bob@x.io", 5),
            ("url", "https://x.io/hook?t=abcdefghij0123456789ABC", "https://x.io/hook?t=abcdefghij0123456789ABC", 18),
            ("host", "x.io", "x.io", 26),
            ("ipv4", "192.168.1.1", "192.168.1.1", 65),
        ],
    ),
    (
        "sorted-by-position",
        "a.com then b@c.org then /tmp/x",
        [("host", "a.com", "a.com", 0), ("email", "b@c.org", "b@c.org", 11), ("path", "/tmp/x", "/tmp/x", 24)],
    ),
    (
        "astral-before-url",
        "\U0001f600 see http://Ex.com/a and \U0001f600\U0001f600 b@c.org /tmp/x 10.0.0.1",
        [
            ("url", "http://ex.com/a", "http://Ex.com/a", 7),
            ("host", "ex.com", "ex.com", 14),
            ("email", "b@c.org", "b@c.org", 32),
            ("path", "/tmp/x", "/tmp/x", 40),
            ("ipv4", "10.0.0.1", "10.0.0.1", 47),
        ],
    ),
    (
        "astral-inside-url",
        "x http://a.com/\U0001f600 y a.org",
        [
            ("url", "http://a.com/\U0001f600", "http://a.com/\U0001f600", 2),
            ("host", "a.com", "a.com", 9),
            ("host", "a.org", "a.org", 20),
        ],
    ),
    (
        "lone-surrogate-before-url",
        "x\ud83dhttp://a.com",
        [("url", "http://a.com", "http://a.com", 2), ("host", "a.com", "a.com", 9)],
    ),
    (
        "url-after-non-ascii-letter",
        "\u00e9http://a.com/x",
        [("url", "http://a.com/x", "http://a.com/x", 1), ("host", "a.com", "a.com", 8)],
    ),
    ("url-long-s-scheme", "http\u017f://a.com/x", [("path", "/a.com/x", "/a.com/x", 7)]),
    (
        "url-stops-at-nbsp",
        "http://a.com/x\u00a0y",
        [("url", "http://a.com/x", "http://a.com/x", 0), ("host", "a.com", "a.com", 7)],
    ),
    (
        "url-stops-at-line-separator",
        "http://a.com/x\u2028y",
        [("url", "http://a.com/x", "http://a.com/x", 0), ("host", "a.com", "a.com", 7)],
    ),
    (
        "url-stops-at-bom",
        "http://a.com/x\ufeffy",
        [("url", "http://a.com/x", "http://a.com/x", 0), ("host", "a.com", "a.com", 7)],
    ),
    (
        "url-includes-nel",
        "http://a.com/x\u0085y",
        [("url", "http://a.com/x\u0085y", "http://a.com/x\u0085y", 0), ("host", "a.com", "a.com", 7)],
    ),
    (
        "url-includes-file-separator",
        "http://a.com/x\u001cy",
        [("url", "http://a.com/x\u001cy", "http://a.com/x\u001cy", 0), ("host", "a.com", "a.com", 7)],
    ),
    ("path-includes-nel", "open ~/a\u0085b now", [("path", "~/a\u0085b", "~/a\u0085b", 5)]),
    ("path-stops-at-ideographic-space", "open ~/a\u3000b now", [("path", "~/a", "~/a", 5)]),
]
CASE_IDS = [case[0] for case in CASES]


def rows(text: str) -> list[tuple[str, str, str, int]]:
    return [(i.kind, i.value, i.raw, i.index) for i in extract_identifiers(text)]


@pytest.mark.parametrize(("text", "expected"), [case[1:] for case in CASES], ids=CASE_IDS)
def test_extract_identifiers_matches_js(text: str, expected: list[tuple[str, str, str, int]]) -> None:
    assert rows(text) == expected


@pytest.mark.parametrize("text", [case[1] for case in CASES], ids=CASE_IDS)
def test_extract_identifiers_orders_results_by_position(text: str) -> None:
    indexes = [i.index for i in extract_identifiers(text)]
    assert indexes == sorted(indexes)


def test_extract_identifiers_returns_a_list_of_identifier_dataclasses() -> None:
    result = extract_identifiers("see http://a.com/x")
    assert isinstance(result, list)
    assert all(isinstance(i, Identifier) for i in result)
    assert dataclasses.is_dataclass(Identifier)
    assert [f.name for f in dataclasses.fields(Identifier)] == ["kind", "value", "raw", "index"]


def test_extract_identifiers_reports_the_index_in_utf16_units_not_code_points() -> None:
    (url, host) = extract_identifiers(EMOJI + " http://a.com")
    assert (url.index, host.index) == (3, 10)


def test_extract_identifiers_is_repeatable_on_the_same_input() -> None:
    text = "mail bob@x.io via https://x.io/hook at 192.168.1.1"
    assert rows(text) == rows(text)
