#!/usr/bin/env python3
import sys


REASON = (
    "BLOCKED: AskUserQuestion (the menu tool) is disabled on this project. "
    "Agents use it to bail out - stopping mid-task to blast a menu whose "
    "options are 'continue per rules' vs. hidden-bomb alternatives, which "
    "freezes the autonomous flow and often blocks the user from even replying.\n\n"
    "Do this instead:\n"
    "1. If you were about to ask because the next step is genuinely obvious "
    "from the task, checklist, or investigation - DON'T ASK. Continue per "
    "project rules (CLAUDE.md: 'Never propose to stop, pause, or ask whether "
    "to continue obvious next work').\n"
    "2. If you were about to present OPTIONS - run /verify-options on your own "
    "option list now. It detects the bailout signature and collapses any "
    "rule-violating / scope-cut / hack-as-equal option to a FORBIDDEN "
    "one-liner. Usually it shows the honest answer was 'continue per rules'.\n"
    "3. If a TRULY unresolvable architecture fork remains after /verify-options "
    "(a real design decision only the user can make), present it as plain text "
    "in chat - the user can answer inline. Never a blocking menu.\n\n"
    "You may NOT use AskUserQuestion to ask the user how obscure hardware "
    "behaves (board/SoC/peripheral registers, timings, GPIO wiring) - that is "
    "a bailout; get the answer from RE / datasheet / BSP."
)


def main() -> int:
    try:
        sys.stdin.buffer.read()
    except Exception:
        pass

    out = (
        '{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
        '"permissionDecision":"deny","permissionDecisionReason":'
        + _json_str(REASON)
        + '},"systemMessage":"[CLAUDE.md hook] BLOCKED: AskUserQuestion '
        'menu \\u2014 run /verify-options or continue per rules"}'
    )
    sys.stdout.write(out)
    return 0


def _json_str(s: str) -> str:
    import json
    return json.dumps(s)


if __name__ == "__main__":
    sys.exit(main())
