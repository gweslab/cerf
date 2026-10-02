#!/usr/bin/env python3
import json
import os
import re
import sys

import _hookpath


BUNDLED_DEVICE_RE = re.compile(r"^bundled/devices/[^/]+/", re.IGNORECASE)


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

    try:
        rel = os.path.relpath(file_path).replace("\\", "/")
    except ValueError:
        rel = file_path.replace("\\", "/")

    if not BUNDLED_DEVICE_RE.match(rel):
        return 0

    msg = (
        f"You edited {rel}. bundled/devices/ is temporary, gitignored storage "
        f"that the build copies into build/Release/<platform>/devices/. A "
        f"necessary change to cerf.json is a schema migration. That work "
        f"happens outside this project."
    )

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": msg,
        },
        "systemMessage": f"[CLAUDE.md hook] bundled device edited: {rel}",
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
