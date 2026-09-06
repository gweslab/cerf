#!/usr/bin/env python3
import json
import re
import sys

DRIFT_PATTERNS = [
    (
        re.compile(r"\bgit\s+stash\b"),
        "git stash - putting work aside. Often 'let me look at something "
        "else first'. If user did NOT ask to stash, return to the current "
        "task instead.",
    ),
    (
        re.compile(r"\bgit\s+log\b"),
        "git log - inspecting commit history. Often 'who did this change' "
        "drift. Per CLAUDE.md § 'Communication Patterns': 'you ARE the one "
        "who wrote this code, this is on your responsibility'.",
    ),
    (
        re.compile(r"\bgit\s+show\b"),
        "git show - inspecting a specific commit. Often drift ('let me see "
        "what this old commit did'). The bug is in current code, not in "
        "history.",
    ),
    (
        re.compile(r"\bgit\s+blame\b"),
        "git blame - asking 'who wrote this line'. Per CLAUDE.md: 'It "
        "doesn't matter if something was written not by you... you ARE "
        "the one who wrote this code'. Debug the current code instead.",
    ),
    (
        re.compile(r"\bgit\s+reflog\b"),
        "git reflog - exploring repo history beyond the current branch. "
        "Almost always drift unless user explicitly asked.",
    ),
]


def main() -> int:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return 0

    tool_input = payload.get("tool_input") or {}
    cmd = tool_input.get("command", "")
    if not cmd:
        return 0

    hits = [advice for pattern, advice in DRIFT_PATTERNS if pattern.search(cmd)]
    if not hits:
        return 0

    msg = (
        "WORKFLOW-DRIFT POSSIBLE - the bash command just run is a known "
        "drift smell. MIGHT be exactly what the user asked for, in which "
        "case ignore this and proceed. Otherwise: stop, return to the "
        "actual task. Per agent_docs/workflow.md § 'When Your Fix Crashes': "
        "the next step after a failure is a LOG diagnostic, NOT a git "
        "archaeology session. Per CLAUDE.md § 'NEVER say \"pre-existing "
        "issue\"': YOUR changes caused the current state, not someone "
        "else's commit.\n\n"
        + "\n\n".join(f"  - {h}" for h in hits)
    )

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": msg,
        },
        "systemMessage": "[CLAUDE.md hook] possible git workflow drift",
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
