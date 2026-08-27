#!/usr/bin/env python3
import json
import os
import re
import shlex
import sys

RELATIVE_ROOTS = {".", "./", "*", "**", ""}
REFERENCES_ROOTS = {"references", "references/*", "references/**"}
PATTERN_TOOLS = ("grep", "rg", "select-string", "sls")

RECURSIVE_BASH = re.compile(
    r"(?:^|[;&|]\s*)(?:sudo\s+)?(grep|rg|find|ls|du)\b([^;&|]*)")
RECURSIVE_PS = re.compile(
    r"(?:^|[;&|]\s*)(Get-ChildItem|gci|Select-String|sls)\b([^;&|]*)",
    re.IGNORECASE)
GIT_GREP = re.compile(r"(?:^|[;&|]\s*)git\s+grep\b")


def normalize(path):
    q = path.strip("'\"").replace("\\", "/")
    while q.startswith("./"):
        q = q[2:]
    return q.rstrip("/").lower()


def project_root(payload):
    return normalize(os.environ.get("CLAUDE_PROJECT_DIR")
                     or payload.get("cwd") or "")


def strip_root(path, root):
    q = normalize(path)
    if root and q.startswith(root + "/"):
        return q[len(root) + 1:]
    return q


def is_repo_root(path, root):
    q = normalize(path)
    return q in RELATIVE_ROOTS or (bool(root) and q == root)


def is_references_root(path, root):
    return strip_root(path, root) in REFERENCES_ROOTS


def operands(argstr):
    try:
        tokens = shlex.split(argstr, posix=True)
    except ValueError:
        tokens = argstr.split()
    return [t for t in tokens if not t.startswith("-")]


def recursive_bash(tool, flags):
    if tool in ("find", "du", "rg"):
        return True
    if tool == "ls":
        return bool(re.search(r"-[a-zA-Z]*R", flags))
    return bool(re.search(r"-[a-zA-Z]*[rR]", flags) or "--recursive" in flags)


def offending(cmd, powershell, root):
    if GIT_GREP.search(cmd):
        return None
    rx = RECURSIVE_PS if powershell else RECURSIVE_BASH
    for match in rx.finditer(cmd):
        tool, args = match.group(1), match.group(2)
        low = tool.lower()
        if powershell:
            if not re.search(r"-Recurse\b", args, re.IGNORECASE):
                continue
        elif not recursive_bash(low, args):
            continue
        ops = operands(args)
        if low in PATTERN_TOOLS and ops:
            ops = ops[1:]
        if not ops:
            return (tool, "the repo root")
        for path in ops:
            if is_references_root(path, root):
                return (tool, "references/")
            if is_repo_root(path, root):
                return (tool, "the repo root")
    return None


def main():
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return 0

    tool_name = payload.get("tool_name", "")
    tool_input = payload.get("tool_input") or {}
    root = project_root(payload)

    if tool_name == "Glob":
        pattern = tool_input.get("pattern", "")
        path = tool_input.get("path", "") or ""
        if not (is_references_root(pattern, root)
                or strip_root(pattern, root).startswith("references/")
                or is_references_root(path, root)):
            return 0
        hit = ("Glob", "references/")
    else:
        cmd = tool_input.get("command", "")
        if not cmd:
            return 0
        hit = offending(cmd, tool_name == "PowerShell", root)
        if not hit:
            return 0

    reason = (
        "BLOCKED: `%s` would recurse into %s, which walks references/. "
        "CLAUDE.md: 'NEVER DO GLOB IN REFERENCES/ DIRECTORY! ALWAYS DO ls "
        "FIRST' and 'Narrow the path before globbing'.\n"
        "Use instead:\n"
        "  - `git grep <pat>` for tracked files (references/ is gitignored)\n"
        "  - the Grep tool, which honours .gitignore\n"
        "  - `ls references/`, then scan the one subdirectory you need"
    ) % hit

    json.dump({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        },
        "systemMessage": "[CLAUDE.md hook] BLOCKED: recursive scan into references/",
    }, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
