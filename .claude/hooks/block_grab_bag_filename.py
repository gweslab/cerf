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

    matched_word = m.group(1)
    file_exists = os.path.isfile(file_path)

    if not file_exists:
        reason = (
            f"BLOCKED: creating '{basename}' violates CLAUDE.md / "
            f"agent_docs/code_style.md § 'No misc/grab-bag files' - "
            f"basename contains grab-bag word '{matched_word}'.\n\n"
            f"Per the rule: 'never create files named misc.cpp, "
            f"helpers.cpp, others.cpp, misc2.cpp, or any similar "
            f"catch-all. Every file must have a clear, specific name "
            f"describing its responsibility. If code has no obvious "
            f"home, create a properly named file or ask the user - "
            f"never dump it in a junk drawer.'\n\n"
            f"The rule is filename-shape, not agent-judgement: if "
            f"the basename contains misc / helpers / util / extras / "
            f"others anywhere, it's caught. Compound names with the "
            f"word embedded (arm_neon_2regmisc.cpp, "
            f"foo_misc_decoder.cpp, cli_helpers.h) are not exempt - "
            f"those are the exact shapes that have repeatedly turned "
            f"into 20+-unrelated-op dumping grounds.\n\n"
            f"Pick a name that describes the file's single "
            f"responsibility in one sentence WITHOUT using any of "
            f"those words. If you can't, the file shouldn't exist - "
            f"STOP and ask the user where this code belongs."
        )
        out = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            },
            "systemMessage": (
                f"[CLAUDE.md hook] BLOCKED: creating grab-bag file "
                f"'{basename}'"
            ),
        }
    else:
        msg = (
            f"GRAB-BAG-EDIT-WARNING: you are editing '{basename}', a "
            f"forbidden grab-bag filename per CLAUDE.md / "
            f"agent_docs/code_style.md § 'No misc/grab-bag files' - "
            f"basename contains grab-bag word '{matched_word}'.\n\n"
            f"The file ALREADY exists - likely a legacy / pre-hook "
            f"landing, or the user is paying for a refactor to "
            f"DELETE it. Edits ARE allowed here because the agent "
            f"must be able to read it, move content out, and "
            f"empty/delete it. Creation of NEW grab-bag files is "
            f"separately hard-blocked.\n\n"
            f"END GOAL: move every piece of code in this file into "
            f"a properly-named file describing one responsibility, "
            f"then DELETE this file. Do NOT extend it - every new "
            f"piece you add here is one more thing the next "
            f"refactor session has to migrate out. If you are "
            f"adding code to a misc/helpers/util file 'just because "
            f"it already exists', STOP and create the properly-"
            f"named file instead."
        )
        out = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": msg,
            },
            "systemMessage": (
                f"[CLAUDE.md hook] WARN: editing grab-bag file "
                f"'{basename}'"
            ),
        }

    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
