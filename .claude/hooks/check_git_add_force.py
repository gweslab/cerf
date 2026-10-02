#!/usr/bin/env python3
import json
import re
import sys

GIT_ADD_FORCE_RE = re.compile(
    r"(?:^|[;&|]\s*)git\s+add\b(?:\s+\S+)*?\s(?:-[a-zA-Z]*f[a-zA-Z]*|--force)\b"
)


def main() -> int:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return 0

    cmd = (payload.get("tool_input") or {}).get("command", "")
    if not cmd:
        return 0

    if not GIT_ADD_FORCE_RE.search(cmd):
        return 0

    msg = (
        "CAUTION: Do not force-add an ignored path with `git add -f`. This "
        "command can do that. An agent that force-adds is most likely wrong."
    )

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": msg,
        },
        "systemMessage": "[CLAUDE.md hook] WARN: git add -f",
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
