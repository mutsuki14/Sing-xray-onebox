#!/usr/bin/env python3
"""A strict reader for the YAML the v3 mihomo renderer emits (not a suite).

:func:`load_yaml` accepts exactly the block-style subset of
``src/render/yaml.rs`` (``client mihomo`` / ``client provider``) and rejects
everything whose meaning could differ between YAML parsers.
"""
from __future__ import annotations

import json
import unittest


class YamlError(ValueError):
    """The text is not in the YAML subset the v3 mihomo renderer emits."""


def load_yaml(text: str):
    """Parse the block-style YAML subset of ``src/render/yaml.rs``.

    Accepted: two-space block mappings and sequences (a collection inside a
    sequence starts on the dash line), plain keys ``[A-Za-z_][A-Za-z0-9_.-]*``
    or JSON-quoted keys, JSON double-quoted strings, integers / floats,
    ``true``/``false``/``null``, ``[]`` and ``{}``. Anything else (plain
    string scalars, flow collections, tabs, comments, anchors, duplicate keys,
    odd indentation, a missing final newline) is rejected, so the reader can
    only accept output whose meaning is unambiguous to any YAML parser.
    """
    if not text.endswith("\n") or text.endswith("\n\n"):
        raise YamlError("document must end with exactly one newline")
    lines = []
    for number, raw in enumerate(text[:-1].split("\n"), 1):
        if "\t" in raw or raw != raw.rstrip(" ") or not raw.strip():
            raise YamlError(f"line {number}: tab, trailing space or blank line")
        stripped = raw.lstrip(" ")
        indent = len(raw) - len(stripped)
        if indent % 2:
            raise YamlError(f"line {number}: odd indentation")
        lines.append([indent, stripped, number])
    if len(lines) == 1 and not _is_entry(lines[0][1]) and not lines[0][1].startswith("- "):
        return _scalar(lines[0][1], lines[0][2])
    reader = _YamlLines(lines)
    value = reader.block(0)
    if reader.pos != len(lines):
        raise YamlError(f"line {lines[reader.pos][2]}: unexpected indentation")
    return value


class _YamlLines:
    def __init__(self, lines):
        self.lines = lines
        self.pos = 0

    def peek(self):
        return self.lines[self.pos] if self.pos < len(self.lines) else None

    def block(self, indent):
        line = self.peek()
        if line is None or line[0] != indent:
            raise YamlError(f"expected a block at indentation {indent}")
        return self.sequence(indent) if line[1].startswith("- ") else self.mapping(indent)

    def sequence(self, indent):
        items = []
        while (line := self.peek()) and line[0] == indent and line[1].startswith("- "):
            content = line[1][2:]
            if content.startswith("- ") or _is_entry(content):
                # The nested collection starts on the dash line: re-read
                # that line as if it were indented past the dash.
                self.lines[self.pos] = [indent + 2, content, line[2]]
                items.append(self.block(indent + 2))
            else:
                items.append(_scalar(content, line[2]))
                self.pos += 1
        return items

    def mapping(self, indent):
        result = {}
        while (line := self.peek()) and line[0] == indent and not line[1].startswith("- "):
            key, rest = _split_key(line[1], line[2])
            if key in result:
                raise YamlError(f"line {line[2]}: duplicate key {key!r}")
            self.pos += 1
            if rest == "":
                child = self.peek()
                if child is None or child[0] != indent + 2:
                    raise YamlError(f"line {line[2]}: missing block for {key!r}")
                result[key] = self.block(indent + 2)
            elif rest.startswith(" ") and not rest.startswith("  "):
                result[key] = _scalar(rest[1:], line[2])
            else:
                raise YamlError(f"line {line[2]}: expected one space after the colon")
        return result


_PLAIN_KEY_FIRST = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_PLAIN_KEY_REST = _PLAIN_KEY_FIRST | set("0123456789.-")
_YAML11_WORDS = {"y", "n", "yes", "no", "on", "off", "true", "false", "null", "~", "<<", "="}


def _is_entry(text: str) -> bool:
    try:
        _split_key(text, 0)
    except YamlError:
        return False
    return True


def _quoted_end(text: str) -> int | None:
    escaped = False
    for index, char in enumerate(text[1:], 1):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            return index + 1
    return None


def _split_key(text: str, number: int) -> tuple[str, str]:
    if text.startswith('"'):
        end = _quoted_end(text)
        if end is None or text[end:end + 1] != ":":
            raise YamlError(f"line {number}: not a mapping entry")
        return _json_string(text[:end], number), text[end + 1:]
    key, colon, rest = text.partition(":")
    plain = (key and key[0] in _PLAIN_KEY_FIRST and set(key) <= _PLAIN_KEY_REST
             and key.lower() not in _YAML11_WORDS)
    if not colon or not plain:
        raise YamlError(f"line {number}: not a mapping entry")
    return key, rest


def _json_string(text: str, number: int) -> str:
    try:
        value = json.loads(text)
    except ValueError as error:
        raise YamlError(f"line {number}: invalid quoted string: {error}") from error
    if not isinstance(value, str):
        raise YamlError(f"line {number}: expected a string")
    return value


def _scalar(text: str, number: int):
    fixed = {"null": None, "true": True, "false": False}
    if text in fixed:
        return fixed[text]
    if text == "[]":
        return []
    if text == "{}":
        return {}
    if text.startswith('"'):
        if _quoted_end(text) != len(text):
            raise YamlError(f"line {number}: text after a quoted string")
        return _json_string(text, number)
    try:
        value = json.loads(text)
    except ValueError:
        value = None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return value
    raise YamlError(f"line {number}: plain scalar {text!r} is never emitted")


# ---------------------------------------------------------------------------
# Self-tests (python3 tests/e2e/_selftest.py)


class YamlReaderTests(unittest.TestCase):
    def test_documents_round_trip(self):
        cases = [
            ("a: 1\n", {"a": 1}),
            ("- 1\n- \"x\"\n", [1, "x"]),
            (("proxies:\n  - name: \"n\"\n    port: 443\n    tls: true\n    alpn:\n      - \"h2\"\n"
              "rules:\n  - \"MATCH,n\"\n"),
             {"proxies": [{"name": "n", "port": 443, "tls": True, "alpn": ["h2"]}],
              "rules": ["MATCH,n"]}),
            ("- - 1\n  - 2\n- {}\n- []\n", [[1, 2], {}, []]),
            ("\"yes\": null\n\"a b\": -1.5\n", {"yes": None, "a b": -1.5}),
            ("k: \"\\u0007\\\"q\\\\\"\n", {"k": "\u0007\"q\\"}),
            ("\"x\"\n", "x"),
            ("ws-opts:\n  headers:\n    Host: \"h.test\"\n", {"ws-opts": {"headers": {"Host": "h.test"}}}),
        ]
        for text, expected in cases:
            with self.subTest(text=text):
                self.assertEqual(load_yaml(text), expected)

    def test_rejects_ambiguous_or_malformed_text(self):
        bad = [
            "a: 1",                 # no final newline
            "a: 1\n\n",             # blank line
            "a: plain\n",           # plain string scalar
            "a: yes\n",             # YAML 1.1 boolean
            "yes: 1\n",             # keyword key
            "a: [1]\n",             # flow sequence
            "a: 1\na: 2\n",         # duplicate key
            "a:\n   b: 1\n",        # odd indentation
            "a:\n    b: 1\n",       # skipped level
            "a:  1\n",              # two spaces
            "a: 1 # c\n",           # comment
            "\ta: 1\n",             # tab
            "a: \"x\" y\n",         # text after string
            "a:\n",                 # missing block
            "- 1\nb: 2\n",          # mixed collection kinds
            "a: 1 \n",              # trailing space
            "a: ~\n",               # YAML null word
            "a: &x 1\n",            # anchor
            "a: *x\n",              # alias
            "a: {b: 1}\n",          # flow mapping
            "- plain\n",            # plain string in a sequence
            "a: 'x'\n",             # single-quoted string
            "a:\n- 1\n",            # sequence not indented under its key
            "\"a\" : 1\n",          # space before the colon
        ]
        for text in bad:
            with self.subTest(text=text), self.assertRaises(YamlError):
                load_yaml(text)


if __name__ == "__main__":
    unittest.main()
