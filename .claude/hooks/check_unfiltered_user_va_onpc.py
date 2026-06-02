#!/usr/bin/env python3
"""
PostToolUse hook for Write|Edit on cerf/tracing/**/*.cpp files. Detects
unfiltered `tm.OnPc(VA, ...)` calls where VA is a user-mode address
(< 0x80000000).

On every Windows CE family CERF supports, every guest process maps its
EXE image at user-VA 0x10000 and shared user-mode DLLs (coredll,
ceshell, commctrl, …) at 0x40000000+. Those VAs ALIAS across every
process running through them — FCSE on CE5/v5, ASID on CE6/CE7/v7, the
collision shape is the same: a bare `tm.OnPc(<user-VA>, ...)` fires
for ANY process executing that VA, not just the one the hook's name
claims. Findings drawn from such fires are unreliable across sessions.

Fix: use `tm.OnPcFiltered(VA, predicate, handler)` where `predicate`
comes from the device-specific resolver under the same tracing
subdirectory (e.g. `<bundle>_resolver::PidPredicateForName("<exe>")`),
so the fire is attributable to one specific process's TTBR0.

Kernel-VA hooks (VA >= 0x80000000) are FCSE/ASID-immune and DO NOT
need filtering. This hook only flags user-VA bare `OnPc`.

Reads tool I/O JSON from stdin and emits hookSpecificOutput JSON to
stdout. Silent (exit 0) when the file has no unfiltered user-VA OnPc.
"""
import json
import os
import re
import sys


# Match `tm.OnPc(0x...hex...u?, ...` where the hex address starts with
# a digit 0-7 (i.e. < 0x80000000 = user-mode). The leading whitespace
# anchor + `tm.` prefix matches every call site in cerf/tracing/.
USER_VA_ONPC_RE = re.compile(
    r"^\s*tm\.OnPc\(\s*(0x[0-7][0-9A-Fa-f]+u?)\b",
    re.MULTILINE,
)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0

    tool_input = payload.get("tool_input") or {}
    file_path = tool_input.get("file_path") or ""

    # Only fire on cerf/tracing/**/*.cpp.
    norm = file_path.replace("\\", "/")
    if "/cerf/tracing/" not in norm:
        return 0
    if not norm.endswith(".cpp"):
        return 0

    # Read current file content.
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return 0

    hits = []
    for m in USER_VA_ONPC_RE.finditer(content):
        # Locate the line number.
        line_no = content.count("\n", 0, m.start()) + 1
        va = m.group(1)
        # Recover the matched line (up to newline).
        line_start = content.rfind("\n", 0, m.start()) + 1
        line_end = content.find("\n", m.end())
        if line_end < 0:
            line_end = len(content)
        line_text = content[line_start:line_end].strip()
        hits.append((line_no, va, line_text))

    if not hits:
        return 0

    msg_lines = [
        "UNFILTERED-USER-VA-ONPC: this file has tm.OnPc(VA, ...) calls "
        "where VA is in the user-mode range (< 0x80000000) WITHOUT a "
        "process filter. On every Windows CE family CERF supports, "
        "guest processes share user-mode VAs (EXE images at 0x10000, "
        "shared DLLs at 0x40000000+) — an unfiltered OnPc fires for "
        "ANY process executing that VA, not just the one this hook's "
        "name claims. Findings drawn from such fires are unreliable.",
        "",
        "Fix: replace `tm.OnPc(VA, handler)` with",
        "  `tm.OnPcFiltered(VA, predicate, handler)`",
        "where `predicate` comes from the device-specific resolver",
        "under the same tracing subdirectory (look for a *_resolver.h",
        "exposing `PidPredicateForName(\"<exe>\")` or equivalent).",
        "",
        "If you genuinely want to observe every process executing this "
        "VA, document WHY in a comment naming the specific multi-process "
        "use case — but the default expectation under this rule is that "
        "every user-VA OnPc is filtered.",
        "",
        f"  Hits: {file_path}",
    ]
    for line_no, va, line_text in hits[:20]:
        msg_lines.append(f"    line {line_no}: {va}  — `{line_text}`")
    if len(hits) > 20:
        msg_lines.append(f"    … and {len(hits) - 20} more")

    output = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "\n".join(msg_lines),
        }
    }
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    sys.exit(main())
