#!/usr/bin/env python3
import json
import os
import sys

import _hookpath
import _pyscan

SOURCE_EXTS = (".cpp", ".c", ".h", ".hpp", ".cc", ".cxx", ".py")

PY_EXTS = (".py",)


def scan_line(line, in_block):
    parts = []
    i, n = 0, len(line)
    in_str = None
    while i < n:
        c = line[i]
        if in_block:
            j = line.find("*/", i)
            if j >= 0:
                parts.append(line[i:j])
                in_block = False
                i = j + 2
            else:
                parts.append(line[i:])
                i = n
            continue
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == in_str:
                in_str = None
            i += 1
            continue
        if c in ('"', "'"):
            in_str = c
            i += 1
            continue
        if c == "/" and i + 1 < n:
            if line[i + 1] == "/":
                parts.append(line[i + 2:])
                i = n
                continue
            if line[i + 1] == "*":
                in_block = True
                i += 2
                continue
        i += 1
    return parts, in_block


def extract_comments(src, is_py=False):
    out = []
    state = None if is_py else False
    lines = src.splitlines()
    for idx, line in enumerate(lines, start=1):
        if is_py:
            if idx == 1 and line.startswith("#!"):
                continue
            parts, state = _pyscan.scan_hash_comments(line, state)
        else:
            parts, state = scan_line(line, state)
        text = " ".join(p.strip() for p in parts if p.strip())
        if text:
            out.append((idx, line.strip(), text))

    if is_py:
        for start, _end, body in _pyscan.find_docstrings(src):
            for offset, text in enumerate(body):
                if text.strip():
                    ln = start + offset
                    raw = lines[ln - 1].strip() if ln <= len(lines) else text
                    out.append((ln, raw, text.strip()))
        out.sort()
    return out


def main() -> int:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return 0

    tool_input = payload.get("tool_input") or {}
    file_path = _hookpath.normalize(tool_input.get("file_path", ""))
    if not file_path.lower().endswith(SOURCE_EXTS):
        return 0

    new_blob = tool_input.get("content")
    if not isinstance(new_blob, str):
        new_blob = tool_input.get("new_string")
    if not isinstance(new_blob, str) or not new_blob:
        return 0

    is_py = file_path.lower().endswith(PY_EXTS)

    old_blob = tool_input.get("old_string")
    old_texts = set()
    if isinstance(old_blob, str) and old_blob:
        old_texts = {t for _, _, t in extract_comments(old_blob, is_py)}

    added = [
        c for c in extract_comments(new_blob, is_py) if c[2] not in old_texts
    ]
    if not added:
        return 0

    try:
        rel = os.path.relpath(file_path).replace("\\", "/")
    except ValueError:
        rel = file_path.replace("\\", "/")

    sample = "\n".join(f"  {raw[:110]}" for _, raw, _ in added[:8])
    more = f"\n  ... and {len(added) - 8} more" if len(added) > 8 else ""

    msg = (
        f"COMMENTS-FORBIDDEN: this write/edit of {rel} authored "
        f"{len(added)} comment line(s):\n\n{sample}{more}\n\n"
        f"THE RULE (CLAUDE.md, agent_docs/code_style.md § Comments): a "
        f"comment is a CITATION, or it does not exist. There is no "
        f"third kind.\n\n"
        f"APPLY THE TEST TO EACH COMMENT ABOVE. It survives ONLY if it "
        f"is one of these two:\n"
        f"  1. PERMITTED-SOURCE CITATION - names an external source of "
        f"truth from the permitted set (agent_docs/rules.md "
        f"§ Reference Licence Hygiene): a chip datasheet / SoC user "
        f"manual section, table or figure, a register name + offset + "
        f"bit field, a CPU architecture reference manual section, a "
        f"standard / RFC clause, or an open-source model CERF "
        f"reimplemented - QEMU, the Linux kernel, NetBSD and the like, "
        f"named as path + function, with the project recorded in "
        f"THIRD_PARTY_NOTICES.md. The datasheet can be e.g. a PDF. A "
        f"project document and ANYTHING within the project itself "
        f"(another .cpp file, etc) is not a citation but a rotting "
        f"comment. MSDN citation Requires a LINK and this link has to "
        f"be opened by agent itself otherwise it is a fabricated tech "
        f"spec and the logic you are doing is based on fabrication "
        f"(even if you delete the comment)\n"
        f"  2. REVERSE-ENGINEERING CITATION - names the decompiled "
        f"guest it is derived from, and it MUST start with the ROM "
        f"BUNDLE NAME: bundle + module + address / VA + function name "
        f"(for example 'jornada720 gwes.exe DrawText 0x0301A4C8'). The "
        f"bundle name is the directory under bundled/devices/. A board "
        f"has many ROMs and one address means a different thing in "
        f"each, so an address with no bundle name is ambiguous and "
        f"usually impossible to resolve later. A bare address is NOT a "
        f"citation. The ROM must also be FIXED - an OEM device firmware "
        f"image, or an image an SDK ships (a Windows Mobile Device "
        f"Emulator image qualifies). NEVER cite a ROM a user compiles "
        f"from a board support package: Device Emulator Windows CE "
        f"builds, ODO builds, OMAP 3530 EVM builds, NEC Rockhopper "
        f"builds. Two builders get different addresses and the image "
        f"can vanish, so that citation rots immediately - write no "
        f"comment instead.\n\n"
        f"FORBIDDEN SOURCES - a citation naming one of these never "
        f"survives, however accurate it is: the Microsoft Device "
        f"Emulator source, and the Microsoft Platform Builder / "
        f"Windows CE Shared Source trees (any BSP / PUBLIC / PRIVATE / "
        f"OAK subtree, any references/WINCE* path). Deleting the "
        f"comment alone is NOT the fix - that strips the label and "
        f"keeps the information. Re-ground the fact on a permitted "
        f"source (the ROM in IDA, the datasheet, the standard) and "
        f"cite THAT, or hand it to the user.\n\n"
        f"A permitted citation names a model CERF REIMPLEMENTED. "
        f"Copying code is forbidden from every source whatever its "
        f"licence - QEMU and Linux are GPL-2.0, and pasting or "
        f"line-by-line translating them into MIT CERF breaches those "
        f"licences.\n\n"
        f"IF IT IS NEITHER, DELETE IT. Not reword. Not shorten. Not "
        f"'distill'. DELETE.\n\n"
        f"Deleted by definition (non-exhaustive): what the code does, "
        f"why an approach was chosen, what was considered and "
        f"rejected, 'do not do X', design rationale, invariant "
        f"restatement, section banners, summaries of the function "
        f"below, narration of the edit, anything a reader could get "
        f"from the code itself.\n\n"
        f"A citation with no NAMED source is not a citation. Delete "
        f"it.\n\n"
        f"FALSE-POSITIVE GATE: if a listed line is not actually a "
        f"comment you authored (pre-existing text carried through the "
        f"edit unchanged), ignore that line."
    )

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": msg,
        },
        "systemMessage": (
            f"[CLAUDE.md hook] COMMENTS-FORBIDDEN: {len(added)} authored "
            f"comment line(s) in {rel}"
        ),
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
