#!/usr/bin/env python3
import json
import os
import re
import sys

import _hookpath


CAP = 500
SOURCE_RE = re.compile(r"\.(cpp|h|hpp|cc|c|py)$", re.IGNORECASE)


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

    root = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    try:
        rel = os.path.relpath(file_path, root).replace("\\", "/")
    except ValueError:
        rel = file_path.replace("\\", "/")

    if not SOURCE_RE.search(rel) or "tracing/" in rel or rel.startswith(".claude/hooks/") or rel.endswith("_data.h"):
        return 0

    try:
        with open(file_path, "rb") as f:
            lines = f.read().count(b"\n")
    except OSError:
        return 0
    if lines <= CAP:
        return 0

    msg = (
        f"{rel} has {lines} lines. The pre-commit hook rejects a source file "
        f"over {CAP} lines. Split it by responsibility before you continue."
    )

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": msg,
        },
        "systemMessage": f"[CLAUDE.md hook] line count over {CAP}: {rel} ({lines})",
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
