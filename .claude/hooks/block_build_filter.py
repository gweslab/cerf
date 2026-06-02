#!/usr/bin/env python3
"""
PreToolUse hook for Bash. HARD-BLOCKS any Bash call that runs build.ps1
AND also invokes `head`, `tail`, or `grep` ANYWHERE in the same call,
regardless of whether the filter is piped, newline-separated, semicolon-
chained, or `&&`-chained.

The failure mode this catches — verified in bash:
  $ (false        # equivalent to a failed build.ps1
     true);       # equivalent to `tail build.log` succeeding
  $ echo $?       # → 0
The COMPOUND command's exit code is the LAST command's, so a successful
`tail build.log` after a failed `build.ps1 > build.log 2>&1` overwrites
build's real exit code with 0. Agents have used the newline-separator
form to dodge a previous version of this hook that only matched the
`|`-pipe shape — same exit-code-suppression effect, different syntax.

  - `head` / `tail` overwrite the compound exit code with their own
    (both return 0 the moment they read any input), so $? after the
    Bash call reports 'succeeded' even when build.ps1 itself failed.
  - `grep` filters out diagnostic lines that don't match the chosen
    regex, hiding the actual cause of failure and forcing a re-run
    with a different filter — wasting compile time.

Raw build output goes directly to the agent. Redirection IS still
allowed (`build.ps1 > build.log 2>&1` alone, no follow-up filter):
redirection preserves the build's exit code in $?, so failure is
still visible to the caller — the agent just needs a Read tool call
to see WHY it failed. Pairing the redirect with head/tail/grep in
the same Bash call is what re-introduces the exit-code masking.
"""
import json
import re
import sys

BUILD_RE = re.compile(r"\bbuild\.ps1\b", re.IGNORECASE)
FILTER_RE = re.compile(r"\b(head|tail|grep)\b", re.IGNORECASE)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0

    cmd = (payload.get("tool_input") or {}).get("command", "")
    if not cmd:
        return 0

    if not BUILD_RE.search(cmd):
        return 0

    m = FILTER_RE.search(cmd)
    if not m:
        return 0

    filter_name = m.group(1).lower()
    reason = (
        f"BLOCKED: this Bash call runs build.ps1 AND invokes "
        f"`{filter_name}` in the same call. This is the exact pattern "
        f"that has hidden multiple real build failures:\n\n"
        f"  - In a compound bash command, the LAST command's exit code "
        f"becomes the whole call's $?. So `build.ps1 > log 2>&1` "
        f"followed (by newline / ; / && / |) by `{filter_name} log` "
        f"masks build's real exit code with `{filter_name}`'s 0 — "
        f"failure is silently reported as success.\n"
        f"  - `grep` additionally filters out diagnostic lines that "
        f"don't match the chosen regex, hiding the actual cause of "
        f"failure and forcing a re-run with a different filter.\n\n"
        f"Run build.ps1 raw — the full output goes to the tool result "
        f"as-is. Pure redirection IS still allowed "
        f"(`build.ps1 > build.log 2>&1` alone, no follow-up "
        f"`{filter_name}` in the same Bash call): redirection alone "
        f"preserves build's exit code in $?. If you need to inspect "
        f"the log, do it in a SEPARATE Bash call after the build "
        f"call has returned its real exit code, OR use the Read tool "
        f"on build.log — Read can scroll, `head` / `tail` cannot."
    )

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        "systemMessage": (
            f"[CLAUDE.md hook] BLOCKED: build.ps1 piped to {filter_name}"
        ),
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
