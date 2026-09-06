#!/usr/bin/env python3
import json
import re
import sys

CERF_AT_COMMAND_RE = re.compile(
    r"(?:^|[;&|]\s*)(?:\S*/)?cerf\.exe\b",
    re.IGNORECASE,
)


def main() -> int:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return 0

    cmd = (payload.get("tool_input") or {}).get("command", "")
    if not cmd:
        return 0

    if not CERF_AT_COMMAND_RE.search(cmd):
        return 0

    msg = (
        "MISSING-TIMEOUT: cerf.exe was invoked without GNU `timeout` "
        "ahead of it. Per CLAUDE.md: 'Always use GNU timeout for "
        "cerf.exe - prefer optimal timeout looking at logs, unless "
        "user has different purposes of this run.' A bare cerf.exe "
        "run can hang on a boot regression or runaway loop and burn "
        "wall-clock that's hard to recover. If the user explicitly "
        "asked for a no-timeout run (long-term stability test, "
        "interactive debugging, perf bench), ignore this. Otherwise: "
        "prepend `timeout Xs` where X is chosen from observed boot "
        "time in cerf.log."
    )

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": msg,
        },
        "systemMessage": "[CLAUDE.md hook] cerf.exe ran without timeout",
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
