#!/usr/bin/env python3
import json
import re
import sys

BUILD_RE = re.compile(r"\bbuild\.ps1\b", re.IGNORECASE)

SUBST_RE = re.compile(r"\$\(|`")

FORBIDDEN_TAIL_RE = re.compile(r"[;|\n]|&&|(?<!>)&(?![&\d])")


def main() -> int:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return 0

    cmd = (payload.get("tool_input") or {}).get("command", "")
    if not cmd:
        return 0

    matches = list(BUILD_RE.finditer(cmd))
    if not matches:
        return 0

    subst = SUBST_RE.search(cmd)
    tail = cmd[matches[-1].end():]
    tail_hit = FORBIDDEN_TAIL_RE.search(tail)

    if not subst and not tail_hit:
        return 0

    bad = (subst or tail_hit).group(0).replace("\n", "\\n")
    reason = (
        f"BLOCKED: something runs after build.ps1 in this call "
        f"(found `{bad}` after the build.ps1 token). build.ps1 must be "
        f"the LAST thing that runs - anything chained after it masks "
        f"its exit code, so a failed build reports success.\n\n"
        f"Only output redirection may follow build.ps1. A trailing "
        f"command, pipe, `&&`/`||`/`;`/newline, `echo $?`, command "
        f"substitution (`$( )` / backticks), or another program after "
        f"build is blocked - each makes the exit status come from the "
        f"trailing construct instead of build, or hides build's "
        f"output.\n\n"
        f"Use exactly one of these two forms:\n"
        f"  1. Run build.ps1 with nothing after it - full output and "
        f"exit code reach you directly.\n"
        f"  2. `build.ps1 > build.log 2>&1` with nothing after the "
        f"redirection, then Read build.log in a SEPARATE call.\n\n"
        f"Running the build and inspecting its result are TWO separate "
        f"calls. If you run the build in the background, the same rule "
        f"holds: nothing may follow build.ps1, or the completion "
        f"notification's exit code is the trailing command's, not the "
        f"build's."
    )

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        "systemMessage": (
            f"[CLAUDE.md hook] BLOCKED: command runs after build.ps1 "
            f"(masks exit code)"
        ),
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
