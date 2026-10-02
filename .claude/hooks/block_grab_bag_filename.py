#!/usr/bin/env python3
import json
import os
import re
import sys

import _hookpath

SOURCE_EXTS = (".cpp", ".h", ".hpp", ".cc", ".c")

GRAB_BAG_WORD_RE = re.compile(
    r"(misc|helpers?|utils?|extras?(?!ct)|others?)",
    re.IGNORECASE,
)


def main() -> int:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return 0

    tool_input = payload.get("tool_input") or {}
    file_path = _hookpath.normalize(tool_input.get("file_path", ""))
    if not file_path:
        return 0

    if not file_path.lower().endswith(SOURCE_EXTS):
        return 0

    basename = os.path.basename(file_path)
    stem, _ext = os.path.splitext(basename)

    m = GRAB_BAG_WORD_RE.search(stem)
    if not m:
        return 0

    word = m.group(1)

    if not os.path.isfile(file_path):
        reason = (
            f"BLOCKED: '{basename}' is a grab-bag name ('{word}'). This "
            f"repository has no grab-bag files. Give each function its own "
            f"file, with a name that tells what the function does."
        )
        out = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            },
            "systemMessage": f"[CLAUDE.md hook] BLOCKED: grab-bag file '{basename}'",
        }
    else:
        msg = (
            f"CAUTION: Do not add code to '{basename}'. It is a grab-bag file "
            f"('{word}'). Give each function its own file, with a name that "
            f"tells what the function does."
        )
        out = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": msg,
            },
            "systemMessage": f"[CLAUDE.md hook] WARN: grab-bag file '{basename}'",
        }

    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
