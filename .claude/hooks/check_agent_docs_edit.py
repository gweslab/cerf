#!/usr/bin/env python3
import json
import os
import sys

import _hookpath


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

    if rel == "CLAUDE.md":
        category = "CLAUDE-MD"
        body = (
            "CLAUDE.md is the source of truth for the entire project. Your "
            "edit reshapes every future agent's system prompt. Per user "
            "memory § 'CLAUDE.md is source of truth': edits require "
            "explicit user direction."
        )
    elif rel.startswith("agent_docs/"):
        category = "AGENT-DOCS"
        body = (
            "Per CLAUDE.md: 'All agent_docs/ pages are user-curated. Do NOT "
            "edit them drive-by because a filename looks like where your "
            "note belongs - these files land in every future agent's system "
            "prompt and a stray edit silently reshapes it. Edits happen "
            "only when the user directs one or when an approved skill "
            "(e.g. session-feedback) runs with explicit user sign-off.'"
        )
    else:
        return 0

    msg = (
        f"{category}-EDIT: you just modified {rel}. {body} If the user did "
        f"NOT explicitly authorize THIS specific edit in this turn, REVERT "
        f"immediately and surface the deviation back to the user. Silent "
        f"agent rewrites of project documentation are how rules get "
        f"rewritten without the user noticing."
    )

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": msg,
        },
        "systemMessage": f"[CLAUDE.md hook] {category} edited: {rel}",
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
