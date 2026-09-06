#!/usr/bin/env python3

_STRING_PREFIXES = ("", "r", "u", "f", "b", "rb", "br", "fr", "rf")


def scan_hash_comments(line, triple_quote):
    parts = []
    if triple_quote:
        close = line.find(triple_quote)
        if close < 0:
            return parts, triple_quote
        line = line[close + 3:]
        triple_quote = None
    i, n = 0, len(line)
    in_str = None
    while i < n:
        c = line[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if line.startswith('"""', i) or line.startswith("'''", i):
            delim = line[i:i + 3]
            close = line.find(delim, i + 3)
            if close < 0:
                return parts, delim
            i = close + 3
            continue
        if c in ('"', "'"):
            in_str = c
            i += 1
            continue
        if c == "#":
            parts.append(line[i + 1:])
            return parts, None
        i += 1
    return parts, triple_quote


def find_docstrings(src):
    blocks = []
    lines = src.splitlines()
    n = len(lines)
    i = 0
    while i < n:
        stripped = lines[i].strip()
        delim = None
        for prefix in _STRING_PREFIXES:
            for quote in ('"""', "'''"):
                if stripped.lower().startswith(prefix + quote):
                    delim = quote
                    break
            if delim:
                break
        if delim is None:
            i += 1
            continue

        start = i
        head = lines[i][lines[i].find(delim) + 3:]
        close = head.find(delim)
        if close >= 0:
            body = [head[:close]]
            end = i
        else:
            body = [head]
            end = None
            j = i + 1
            while j < n:
                close = lines[j].find(delim)
                if close >= 0:
                    body.append(lines[j][:close])
                    end = j
                    break
                body.append(lines[j])
                j += 1
            if end is None:
                break

        blocks.append((start + 1, end + 1, body))
        i = end + 1
    return blocks
