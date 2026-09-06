#!/usr/bin/env python3
import json
import os
import re
import sys

import _hookpath


USER_VA_ONPC_RE = re.compile(
    r"^\s*tm\.OnPc\(\s*(0x[0-7][0-9A-Fa-f]+u?)\b",
    re.MULTILINE,
)


def main() -> int:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except Exception:
        return 0

    tool_input = payload.get("tool_input") or {}
    file_path = _hookpath.normalize(tool_input.get("file_path") or "")

    norm = file_path.replace("\\", "/")
    if "/cerf/tracing/" not in norm:
        return 0
    if not norm.endswith(".cpp"):
        return 0

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return 0

    hits = []
    for m in USER_VA_ONPC_RE.finditer(content):
        line_no = content.count("\n", 0, m.start()) + 1
        va = m.group(1)
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
        "shared DLLs at 0x40000000+) - an unfiltered OnPc fires for "
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
        "use case - but the default expectation under this rule is that "
        "every user-VA OnPc is filtered.",
        "",
        f"  Hits: {file_path}",
    ]
    for line_no, va, line_text in hits[:20]:
        msg_lines.append(f"    line {line_no}: {va}  - `{line_text}`")
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
