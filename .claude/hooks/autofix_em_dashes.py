#!/usr/bin/env python3
import json
import os
import sys

import _hookpath

SCAN_EXTS = (".py", ".cpp", ".c", ".h", ".hpp", ".ps1", ".cmd", ".bat", ".md")

DASHES = (chr(0x2014), chr(0x2013), chr(0x2015))


def main() -> int:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return 0

    tool_input = payload.get("tool_input") or {}
    tool_response = payload.get("tool_response") or {}
    file_path = _hookpath.normalize(tool_response.get("filePath") or tool_input.get("file_path"))
    if not file_path:
        return 0
    if not file_path.lower().endswith(SCAN_EXTS):
        return 0

    try:
        if os.path.abspath(file_path) == os.path.abspath(__file__):
            return 0
    except OSError:
        pass

    if not os.path.isfile(file_path):
        return 0

    try:
        with open(file_path, "rb") as f:
            raw = f.read()
    except OSError:
        return 0

    if raw.startswith(b"\xef\xbb\xbf"):
        bom, enc, body = b"\xef\xbb\xbf", "utf-8", raw[3:]
    elif raw.startswith(b"\xff\xfe"):
        bom, enc, body = b"\xff\xfe", "utf-16-le", raw[2:]
    elif raw.startswith(b"\xfe\xff"):
        bom, enc, body = b"\xfe\xff", "utf-16-be", raw[2:]
    else:
        bom, enc, body = b"", "utf-8", raw

    try:
        text = body.decode(enc)
    except UnicodeDecodeError:
        return 0

    count = sum(text.count(d) for d in DASHES)
    if count == 0:
        return 0

    for d in DASHES:
        text = text.replace(d, "-")

    try:
        with open(file_path, "wb") as f:
            f.write(bom + text.encode(enc))
    except OSError:
        return 0

    try:
        rel = os.path.relpath(file_path).replace("\\", "/")
    except ValueError:
        rel = file_path.replace("\\", "/")

    msg = (
        f"EM-DASH-AUTOFIX: {count} non-ASCII dash(es) detected in {rel} "
        f"and replaced automatically with ASCII '-'. Unicode dashes are "
        f"destructive in Windows CE; they are stripped on every edit. No "
        f"action needed."
    )
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": msg,
        },
        "systemMessage": f"[CLAUDE.md hook] em dashes auto-replaced in {rel}",
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
