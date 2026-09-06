#!/usr/bin/env python3
import json
import os
import re
import sys

import _hookpath

SOURCE_EXTS = (".cpp", ".h", ".hpp", ".cc", ".c")

CITATION_TRIGGER_RE = re.compile(
    r"\bARM ARM\b|§"
    r"|\bTable\s+[A-Z]?\d|\bFig(?:ure)?\.?\s+[A-Z]?\d"
    r"|(?i:\bch\.\s*\d|\bchapter\s+\d|\bpage\s+\d|\bpg\.?\s*\d|\bp\.?\s*\d{3,})"
    r"|(?i:\b(?:ddi|ihi|den|prd|arm)\s*0*\d{3,}|\bjesd\s*\d)"
    r"|\b[A-Z]\d+\.\d+(?:\.\d+)+\b"
    r"|(?i:\bSDM\b|\bTRM\b|\bPRM\b|\bRM\s+(?:Vol|ch|table|section|p)"
    r"|\bdatasheet\b|\buser\s+manual\b|\breference\s+manual\b)"
    r"|(?i:\bvol(?:ume)?\.?\s*\d)"
)


def main() -> int:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return 0

    tool_input = payload.get("tool_input") or {}
    file_path = _hookpath.normalize(tool_input.get("file_path", ""))
    if not file_path.lower().endswith(SOURCE_EXTS):
        return 0

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
        f"('ARM ARM', '§', a 'Table <n>' / 'Fig <n>' reference, or a "
        f"chapter / page reference like 'ch.27' / 'p643'). Trigger "
        f"lines:\n\n{sample}{more}\n\n"
        f"FALSE-POSITIVE GATE: if those lines were ALREADY in the "
        f"file and you are just moving / relocating them - not "
        f"authoring a new citation - ignore the rest of this "
        f"message and proceed.\n\n"
        f"OTHERWISE - VERIFICATION REQUIRED in your NEXT MESSAGE. "
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
        f"  - 'references/s3c2410/s3c2410a_um.pdf PDF page 366 "
        f"printed 14-18'\n\n"
        f"THE PATH MUST BE A PERMITTED SOURCE (agent_docs/rules.md "
        f"§ Reference Licence Hygiene): datasheets, SoC user manuals, "
        f"CPU architecture manuals, standards / RFCs, QEMU, Linux, "
        f"NetBSD and other open-source projects, or the guest ROM in "
        f"IDA. The Microsoft Device Emulator source and the Microsoft "
        f"Platform Builder / Windows CE Shared Source trees (any "
        f"references/WINCE* path, any BSP / PUBLIC / PRIVATE / OAK "
        f"subtree) are FORBIDDEN: naming one does not satisfy this "
        f"hook, it converts the comment into a licence exposure. "
        f"Re-ground the fact on a permitted source and cite that "
        f"instead - and note that deleting the citation while keeping "
        f"the code is separately forbidden, per the section below.\n\n"
        f"WHAT COUNTS AS VERIFICATION - read before you claim it. "
        f"Verification is an on-disk reference file you OPENED THIS "
        f"SESSION, named by path. These are NOT verification - they "
        f"are exactly the fabrication this hook catches, dressed up:\n"
        f"  - 'I verified each byte / bit / offset against the "
        f"standard <USB / I2C / PCI / ...> format / request / "
        f"layout' - that is checking against your MEMORY of the "
        f"format. Your memory of the format IS the training data "
        f"that is wrong 9 of 10 times (off-by-one lengths, swapped "
        f"fields, wrong bit positions). Deriving a value 'byte-by-"
        f"byte' from remembered structure is fabrication, not "
        f"verification.\n"
        f"  - 'this is a universal / standard / well-known value, no "
        f"reference needed' - standard values are PRECISELY what "
        f"memory mangles. 'Standard' is not a path.\n"
        f"  - 'I know this from the spec' - if the spec is not on "
        f"disk and you did not open it this session, you do not know "
        f"it, you REMEMBER it, and remembering is the failure mode.\n"
        f"Only a path to a file you actually opened satisfies the "
        f"hook. If the reference genuinely isn't obtainable, that "
        f"does not downgrade the requirement - it means you cannot "
        f"write this code yet; say so to the user.\n\n"
        f"IF YOU CANNOT NAME A PATH, OR YOU NEVER OPENED THE "
        f"REFERENCE THIS SESSION: the code you just wrote is "
        f"fabricated from training memory. In 9 of 10 such cases "
        f"the bit-fields / offsets / encodings are MANGLED vs the "
        f"real document. Continuing on it is shipping a bug. In "
        f"that case:\n"
        f"  1. INSTANTLY REVERT the code change you just made.\n"
        f"  2. Perform end-to-end verification per "
        f"agent_docs/workflow.md and CLAUDE.md - open the "
        f"reference, find the section, paste the relevant passage "
        f"into the conversation BEFORE writing code.\n"
        f"  3. Re-author the code from the verified reference.\n"
        f"  4. AFTER verification, SHOW THE USER explicitly how "
        f"much your training-memory version differed from the "
        f"official document - list the specific bits / offsets / "
        f"encodings that were wrong.\n\n"
        f"FORBIDDEN RESPONSE - DELETING THE CITATION IS NOT A FIX, "
        f"IT IS EVIDENCE TAMPERING. When you catch a fabricated "
        f"citation, the instinct to just remove the citation line "
        f"(the '§', the figure number, the table ref) and KEEP the "
        f"code is the single worst move available, and it is "
        f"FORBIDDEN. Reasons:\n"
        f"  - The fabrication is not in the comment - it is in the "
        f"CODE the comment described. A wrong Fig/§ you invented "
        f"means the bits / offsets / encodings you wrote FROM that "
        f"invention are suspect. Deleting the citation removes the "
        f"WARNING LABEL, not the wrong data.\n"
        f"  - Unverified code with NO citation looks MORE trustworthy "
        f"than unverified code with a visibly-wrong citation. "
        f"Stripping the citation upgrades fabricated code to "
        f"clean-looking code. That is strictly worse - it hides the "
        f"evidence the next reader needs to catch the bug.\n"
        f"  - This is the same category as gaming a compliance check "
        f"or destroying evidence to pass an audit: the check said "
        f"'prove this is real', and deleting the thing it asked "
        f"about so the check goes quiet is fraud, not compliance. "
        f"It is the 'Disclosure Destruction' pattern named in "
        f"agent_docs/rules.md, applied to citations.\n"
        f"  - 'The code is correct / I verified it, so removing the "
        f"un-pointable citation just makes it self-contained / "
        f"stronger' - THIS IS THE RATIONALIZATION, not an exception. "
        f"You cannot self-certify the code is correct: that "
        f"self-certification is the training-memory judgement the "
        f"hook exists to distrust. Replacing an un-pointable citation "
        f"with a 'self-contained field breakdown' you wrote from "
        f"memory keeps 100% of the unverified data and deletes the "
        f"one marker that flagged it as unverified. 'My bytes aren't "
        f"a bug' is exactly the belief that ships the bug. The "
        f"breakdown is not 'stronger than an un-openable reference' - "
        f"it is the SAME memory, with the warning label removed.\n\n"
        f"So: catching your own fabrication is GOOD - but the ONLY "
        f"valid response is the 4-step revert+reverify+reauthor"
        f"+disclose procedure above, applied to the CODE. Removing "
        f"the citation while leaving the code in place is the one "
        f"thing you may not do. If you have already deleted a "
        f"fabricated citation this turn, you are not done: go back, "
        f"revert the CODE that rested on it, and verify.\n\n"
        f"NEITHER PATH STOPS THE WORKFLOW. The procedure is "
        f"established in agent_docs/workflow.md and rules.md - you "
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
