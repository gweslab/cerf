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

    normalized = file_path.replace("\\", "/").lower()
    if "docs/ai_checklists/" not in normalized:
        return 0

    try:
        rel = os.path.relpath(file_path).replace("\\", "/")
    except ValueError:
        rel = file_path.replace("\\", "/")

    msg = (
        f"CHECKLIST-EDIT: you just modified {rel}. Per CLAUDE.md "
        f"§ 'NEVER edit the checklist without user approval': the "
        f"checklist is the user's document. Per-edit authorization is "
        f"REQUIRED - a prior 'yes, edit X' does NOT carry over to THIS "
        f"edit. If the user did NOT explicitly authorize THIS specific "
        f"edit in this turn, REVERT immediately and surface the "
        f"deviation back to the user. Silent agent rewrites of the "
        f"plan are explicitly named in CLAUDE.md as how prior agent "
        f"sessions damaged the project."
    )

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": msg,
        },
        "systemMessage": f"[CLAUDE.md hook] checklist edited: {rel}",
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
