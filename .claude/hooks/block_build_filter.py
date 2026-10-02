#!/usr/bin/env python3
import json
import re
import sys

BUILD_RE = re.compile(r"\bbuild\.ps1\b", re.IGNORECASE)

SUBST_RE = re.compile(r"\$\(|`")

FORBIDDEN_TAIL_RE = re.compile(r"[;|\n]|&&|(?<!>)&(?![&\d])")


def main() -> int:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return 0

    cmd = (payload.get("tool_input") or {}).get("command", "")
    if not cmd:
        return 0

    matches = list(BUILD_RE.finditer(cmd))
    if not matches:
        return 0

    subst = SUBST_RE.search(cmd)
    tail = cmd[matches[-1].end():]
    tail_hit = FORBIDDEN_TAIL_RE.search(tail)

    if not subst and not tail_hit:
        return 0

    bad = (subst or tail_hit).group(0).replace("\n", "\\n")
    reason = (
        f"BLOCKED: `{bad}` after build.ps1 masks the build exit code. Run "
        f"build.ps1 last, with nothing after it but an output redirect. Read "
        f"the log in a separate call."
    )

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        "systemMessage": "[CLAUDE.md hook] BLOCKED: command after build.ps1",
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
