#!/usr/bin/env python3
import json
import sys

REASON = (
    "BLOCKED: This repository disables AskUserQuestion, because it blocks "
    "autonomous execution. Do not hand options to the user. Resolve them "
    "yourself with /verify-options and the project rules."
)


def main() -> int:
    try:
        sys.stdin.buffer.read()
    except OSError:
        pass

    json.dump({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": REASON,
        },
        "systemMessage": "[CLAUDE.md hook] BLOCKED: AskUserQuestion",
    }, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
