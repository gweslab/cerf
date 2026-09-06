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

    device = rel.split("/", 3)[2] if rel.count("/") >= 2 else "<dir>"

    msg = (
        f"BUNDLED-DEVICE-EDIT: you just modified {rel}. This path is "
        f"inside the downloaded ROM bundle for device '{device}' - it "
        f"is NOT CERF built-in source. The directory was populated by "
        f"the CERF launcher (launcher.exe) from the upstream ROMs "
        f"repository.\n\n"
        f"Your local edit will be OVERWRITTEN the next time the user "
        f"re-syncs this device (the launcher pulls the bundle fresh "
        f"from the manifest and overwrites the local copy). "
        f"Even if the user never re-syncs, anyone else with the same "
        f"device locally will not see your change - there is no "
        f"propagation path from this checkout back to other users.\n\n"
        f"If the change is genuinely needed, the FIX BELONGS UPSTREAM "
        f"in the ROMs repository the launcher pulls from. Tell the "
        f"user explicitly:\n"
        f"  1. WHICH file in the upstream bundle to change.\n"
        f"  2. WHAT the change is (concrete diff or new content).\n"
        f"  3. WHY - what CERF behaviour depends on it.\n"
        f"The user can then update the upstream ROMs repo, republish, "
        f"and re-sync - at which point every checkout reflects the "
        f"fix.\n\n"
        f"If this IS a one-shot local diagnostic / scratch edit and "
        f"the user explicitly directed it, ignore this and proceed."
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
