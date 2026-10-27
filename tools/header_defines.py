from __future__ import annotations

import re
from pathlib import Path

_TOKEN = re.compile(r'\s*(?:"([^"]*)"|([A-Za-z_]\w*))')


def _define_body(text: str, name: str) -> str:
    return re.search(r"^\s*#define\s+" + re.escape(name) + r"\s+(.*?)\s*$", text, re.MULTILINE).group(1)


def _string_value(text: str, name: str) -> str:
    body = _define_body(text, name)
    value = ""
    position = 0
    while position < len(body):
        token = _TOKEN.match(body, position)
        literal, macro = token.groups()
        value += _string_value(text, macro) if macro else literal
        position = token.end()
    return value


def int_define(path: Path, name: str) -> int:
    return int(_define_body(Path(path).read_text(encoding="utf-8"), name))


def str_define(path: Path, name: str) -> str:
    return _string_value(Path(path).read_text(encoding="utf-8"), name)
