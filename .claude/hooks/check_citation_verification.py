#!/usr/bin/env python3
"""
PostToolUse hook for Write|Edit on C/C++ source. Fires when the WRITE
or EDIT introduces a citation trigger word — "ARM ARM" or "§" — and
demands explicit verification from the agent in their next message.

Scope is the DIFF (the agent's own additions), NOT the whole file:
  - Write tool: scans `tool_input.content` (full new content the
    agent is authoring).
  - Edit tool: scans `tool_input.new_string` (the addition only;
    `old_string` is what's being removed and is NOT scanned).
Edits that don't touch citation lines stay silent — only the agent's
own newly-authored content triggers the verification demand.

Trigger words:
  - "ARM ARM" — bare reference to the ARM Architecture Reference
    Manual. Overwhelmingly the training-memory-fabrication shape:
    real citations name a specific section number.
  - "§" — section symbol. If the agent is dropping a § into code,
    they're writing a citation, and must be able to name where they
    read it.
"""
import json
import os
import re
import sys

SOURCE_EXTS = (".cpp", ".h", ".hpp", ".cc", ".c")

CITATION_TRIGGER_RE = re.compile(r"\bARM ARM\b|§")


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0

    tool_input = payload.get("tool_input") or {}
    file_path = tool_input.get("file_path", "")
    if not file_path.lower().endswith(SOURCE_EXTS):
        return 0

    # Only the agent's own authoring — never pre-existing content.
    blobs = []
    if isinstance(tool_input.get("content"), str):
        blobs.append(tool_input["content"])
    if isinstance(tool_input.get("new_string"), str):
        blobs.append(tool_input["new_string"])
    if not blobs:
        return 0

    hits = []
    for blob in blobs:
        for line in blob.splitlines():
            m = CITATION_TRIGGER_RE.search(line)
            if m:
                hits.append((line.strip(), m.group(0)))
    if not hits:
        return 0

    try:
        rel_path = os.path.relpath(file_path).replace("\\", "/")
    except ValueError:
        rel_path = file_path.replace("\\", "/")

    sample = "\n".join(
        f"  trigger='{trigger}': {line[:140]}"
        for line, trigger in hits[:5]
    )
    more = f"\n  ... and {len(hits) - 5} more" if len(hits) > 5 else ""

    msg = (
        f"CITATION-VERIFICATION: this {rel_path} write/edit added "
        f"{len(hits)} line(s) containing a citation trigger "
        f"('ARM ARM' or '§'). Trigger lines:\n\n{sample}{more}\n\n"
        f"FALSE-POSITIVE GATE: if those lines were ALREADY in the "
        f"file and you are just moving / relocating them — not "
        f"authoring a new citation — ignore the rest of this "
        f"message and proceed.\n\n"
        f"OTHERWISE — VERIFICATION REQUIRED in your NEXT MESSAGE. "
        f"The 'citation written from training memory' failure mode "
        f"has shipped wrong bit fields / wrong offsets / wrong "
        f"encodings into CERF in roughly 9 of 10 incidents. The "
        f"hook exists to force the verification step before the "
        f"downstream bug lands.\n\n"
        f"YOUR NEXT MESSAGE MUST name the reference path "
        f"(or path + line) you sourced the citation from. Example "
        f"shapes:\n"
        f"  - 'references/arm/DDI0406C_arm_arm.pdf page 1042 "
        f"section A8.8.384'\n"
        f"  - 'references/WINCE600/PLATFORM/DEVICEEMULATOR/SRC/INC/"
        f"s3c2410x_lcd.h line 87'\n\n"
        f"IF YOU CANNOT NAME A PATH, OR YOU NEVER OPENED THE "
        f"REFERENCE THIS SESSION: the code you just wrote is "
        f"fabricated from training memory. In 9 of 10 such cases "
        f"the bit-fields / offsets / encodings are MANGLED vs the "
        f"real document. Continuing on it is shipping a bug. In "
        f"that case:\n"
        f"  1. INSTANTLY REVERT the code change you just made.\n"
        f"  2. Perform end-to-end verification per "
        f"agent_docs/workflow.md and CLAUDE.md — open the "
        f"reference, find the section, paste the relevant passage "
        f"into the conversation BEFORE writing code.\n"
        f"  3. Re-author the code from the verified reference.\n"
        f"  4. AFTER verification, SHOW THE USER explicitly how "
        f"much your training-memory version differed from the "
        f"official document — list the specific bits / offsets / "
        f"encodings that were wrong.\n\n"
        f"NEITHER PATH STOPS THE WORKFLOW. The procedure is "
        f"established in agent_docs/workflow.md and rules.md — you "
        f"know how to proceed. Do NOT ask the user 'should I "
        f"continue?' / 'do you want me to verify?'. Just do the "
        f"right thing: verify and continue, or revert + reverify + "
        f"continue."
    )

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": msg,
        },
        "systemMessage": (
            f"[CLAUDE.md hook] CITATION-VERIFICATION required in {rel_path}"
        ),
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
