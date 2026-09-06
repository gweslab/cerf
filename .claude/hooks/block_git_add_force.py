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

    reason = (
        "BLOCKED: `git add -f` / `--force` bypasses .gitignore. There is no "
        "adequate situation where an agent should force-add an ignored path. "
        ".gitignore exists specifically to keep paths out of history - "
        "confidential checklists under docs/ai_checklists/, build artifacts, "
        "references/, secrets, local configs. Per user memory § 'Never "
        "force past gitignore': .gitignore is a STOP signal. If a path "
        "genuinely belongs in git history, edit .gitignore to un-ignore it, "
        "then `git add` it normally - never bypass the ignore itself."
    )

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        "systemMessage": "[CLAUDE.md hook] BLOCKED: git add -f",
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
