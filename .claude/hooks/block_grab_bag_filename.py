#!/usr/bin/env python3
"""
PreToolUse hook for Write|Edit. Two behaviours, picked by whether the
target file already exists on disk:

  - File does NOT exist → HARD BLOCK creation. The agent is about to
    create a new file whose basename contains a grab-bag word.
  - File ALREADY exists → ADVISORY WARN only. Edits proceed so the
    agent can read the file, move content out, and ultimately delete
    it. Blocking edits on legacy grab-bag files traps the cleanup
    task itself.

Detection is SUBSTRING-based, NOT whole-stem. If the basename
contains any of these words anywhere, the file is caught:

    misc, helpers, helper, utils, util, extras, extra, others, other

That catches every shape of grab-bag the rule warns against:
  - misc.cpp / misc2.cpp                       (bare)
  - cli_helpers.h / foo_utils.cpp              (suffix)
  - arm_neon_2regmisc.cpp                      (compound — embedded)
  - arm_neon_2regmisc_decoder.cpp              (compound — embedded)
  - emit_neon_data_2regmisc_absneg.cpp         (multi-segment)

If your file's name happens to contain one of these words even
though it describes a single specific responsibility, you still
have to rename it. The rule is filename-shape, not agent-judgment.
"""
import json
import os
import re
import sys

SOURCE_EXTS = (".cpp", ".h", ".hpp", ".cc", ".c")

# Substring match — any of these words anywhere in the basename.
# `extras?(?!ct)` — match `extra` / `extras` only when NOT followed by
# `ct`, so `extract` / `extracted` / `extractor` / `extraction` pass
# through. Those are legitimate technical verbs (the codebase has
# extract-* scripts and extraction-pipeline names).
GRAB_BAG_WORD_RE = re.compile(
    r"(misc|helpers?|utils?|extras?(?!ct)|others?)",
    re.IGNORECASE,
)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0

    tool_input = payload.get("tool_input") or {}
    file_path = tool_input.get("file_path", "")
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
            f"agent_docs/code_style.md § 'No misc/grab-bag files' — "
            f"basename contains grab-bag word '{matched_word}'.\n\n"
            f"Per the rule: 'never create files named misc.cpp, "
            f"helpers.cpp, others.cpp, misc2.cpp, or any similar "
            f"catch-all. Every file must have a clear, specific name "
            f"describing its responsibility. If code has no obvious "
            f"home, create a properly named file or ask the user — "
            f"never dump it in a junk drawer.'\n\n"
            f"The rule is filename-shape, not agent-judgement: if "
            f"the basename contains misc / helpers / util / extras / "
            f"others anywhere, it's caught. Compound names with the "
            f"word embedded (arm_neon_2regmisc.cpp, "
            f"foo_misc_decoder.cpp, cli_helpers.h) are not exempt — "
            f"those are the exact shapes that have repeatedly turned "
            f"into 20+-unrelated-op dumping grounds.\n\n"
            f"Pick a name that describes the file's single "
            f"responsibility in one sentence WITHOUT using any of "
            f"those words. If you can't, the file shouldn't exist — "
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
            f"agent_docs/code_style.md § 'No misc/grab-bag files' — "
            f"basename contains grab-bag word '{matched_word}'.\n\n"
            f"The file ALREADY exists — likely a legacy / pre-hook "
            f"landing, or the user is paying for a refactor to "
            f"DELETE it. Edits ARE allowed here because the agent "
            f"must be able to read it, move content out, and "
            f"empty/delete it. Creation of NEW grab-bag files is "
            f"separately hard-blocked.\n\n"
            f"END GOAL: move every piece of code in this file into "
            f"a properly-named file describing one responsibility, "
            f"then DELETE this file. Do NOT extend it — every new "
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
