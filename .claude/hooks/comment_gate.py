#!/usr/bin/env python3
import ast
import json
import os
import re
import subprocess
import sys

import _hookpath

MAX_LINES = 3
C_EXTS = (".cpp", ".c", ".h", ".hpp", ".cc", ".cxx")
PY_EXTS = (".py",)
PROJECT_PATH_RE = re.compile(
    r"\b(?:cerf|ce_apps|launcher|tools|docs|agent_docs|bundled|\.claude)"
    r"/[\w./-]*",
    re.IGNORECASE,
)
REFERENCES_PATH_RE = re.compile(r"\breferences/[\w./-]+", re.IGNORECASE)
PATH_TOKEN_RE = re.compile(r"[\w.-]+(?:/[\w.-]+)*/?")
LEADING_DOTS_RE = re.compile(r"^(?:\.\.?/)+")

CITATION_RE = re.compile(
    r"\bARM ARM\b|§"
    r"|\bTable\s+[A-Z]?\d|\bFig(?:ure)?\.?\s+[A-Z]?\d"
    r"|(?i:\bch\.\s*[A-Z]?\d|\bchapter\s+[A-Z]?\d"
    r"|\bpage\s+[A-Z]?\d|\bpg\.?\s*[A-Z]?\d"
    r"|\bp\.\s*[A-Z]?\d|\bp\s*\d{3,})"
    r"|(?i:\b(?:ddi|ihi|den|prd|arm)\s*0*\d{3,}|\bjesd\s*\d|\brfc\s*\d)"
    r"|\b[A-Z]\d+\.\d+(?:\.\d+)+\b"
    r"|(?i:\bvol(?:ume)?\.?\s*\d)"
    r"|\b[\w][\w.-]*\.(?:c|h|cc|cpp|cxx|s|S|py)\b"
    r"|\b\w+\.(?:exe|dll)\b"
    r"|\b(?:sub|loc|off|unk|byte|word|dword|qword|stru|jpt)_[0-9A-Fa-f]{3,}\b"
    r"|0x[0-9A-Fa-f]{4,}"
)


def cited(text):
    return bool(CITATION_RE.search(PROJECT_PATH_RE.sub(" ", text)))


def repo_tree(file_path):
    files, dirs, names = set(), set(), set()
    try:
        res = subprocess.run(
            ["git", "-C", os.path.dirname(os.path.abspath(file_path)),
             "ls-files", "-z", "--full-name", "--cached", "--others",
             "--exclude-standard", "--", ":/"],
            capture_output=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return files, dirs, names
    if res.returncode != 0:
        return files, dirs, names
    for entry in res.stdout.decode("utf-8", "replace").split("\0"):
        path = entry.lower()
        if not path:
            continue
        files.add(path)
        parts = path.split("/")
        names.add(parts[-1])
        for i in range(1, len(parts)):
            dirs.add("/".join(parts[:i]))
    return files, dirs, names


def names_repo_path(text, tree):
    files, dirs, names = tree
    for m in PATH_TOKEN_RE.finditer(text.replace("\\", "/")):
        tok = LEADING_DOTS_RE.sub("", m.group(0).lower().rstrip("."))
        if "/" not in tok:
            if "." in tok and tok in names:
                return True
            continue
        tok = tok.rstrip("/")
        if tok in files or tok in dirs:
            return True
        if "." in tok.rsplit("/", 1)[-1] and any(
                f.endswith("/" + tok) for f in files):
            return True
    return False


def c_block_comments(lines):
    blocks = []
    in_block = False
    start = None
    for idx, line in enumerate(lines, start=1):
        i, n = 0, len(line)
        in_str = None
        while i < n:
            c = line[i]
            if in_block:
                j = line.find("*/", i)
                if j < 0:
                    i = n
                    continue
                blocks.append((start[0], start[1], idx, j + 2))
                in_block = False
                i = j + 2
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
                    i = n
                    continue
                if line[i + 1] == "*":
                    in_block = True
                    start = (idx, i)
                    i += 2
                    continue
            i += 1
    return blocks


def whole_line_runs(lines, marker, covered, skip_shebang):
    runs = []
    start = None
    for idx, line in enumerate(lines, start=1):
        whole = line.strip().startswith(marker) and idx not in covered
        if whole and skip_shebang and idx == 1 and line.startswith("#!"):
            whole = False
        if whole:
            if start is None:
                start = idx
        elif start is not None:
            runs.append((start, idx - 1))
            start = None
    if start is not None:
        runs.append((start, len(lines)))
    return runs


def py_docstrings(src):
    found = []
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return found
    holders = (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(node, holders) or not body:
            continue
        first = body[0]
        if (isinstance(first, ast.Expr)
                and isinstance(first.value, ast.Constant)
                and isinstance(first.value.value, str)):
            sole = len(body) == 1 and not isinstance(node, ast.Module)
            found.append((first.lineno, first.end_lineno, sole))
    return found


def comment_blocks(lower, lines, src):
    spans = []
    if lower.endswith(PY_EXTS):
        covered = set()
        for start, end, sole in py_docstrings(src):
            for ln in range(start, end + 1):
                covered.add(ln)
            spans.append((start, end, "pass" if sole else None))
        for start, end in whole_line_runs(lines, "#", covered, True):
            spans.append((start, end, None))
        return spans

    covered = set()
    for sl, sc, el, ec in c_block_comments(lines):
        for ln in range(sl, el + 1):
            covered.add(ln)
        keep = (lines[sl - 1][:sc] + lines[el - 1][ec:]).rstrip()
        spans.append((sl, el, keep if keep.strip() else None))
    for start, end in whole_line_runs(lines, "//", covered, False):
        spans.append((start, end, None))
    return spans


def apply_wipe(lines, doomed, is_py):
    drop = set()
    replace = {}
    for start, end, keep in doomed:
        for ln in range(start, end + 1):
            drop.add(ln)
        if keep is None:
            continue
        if is_py:
            pad = len(lines[start - 1]) - len(lines[start - 1].lstrip())
            replace[start] = " " * pad + keep
        else:
            replace[start] = keep
    out = []
    for idx, line in enumerate(lines, start=1):
        if idx in replace:
            out.append(replace[idx])
        elif idx not in drop:
            out.append(line)
    return "\n".join(out)


def verification_text(rel_path, sample):
    return (
        f"CITATION-VERIFICATION: {rel_path} gained these comments with "
        f"citations:\n\n{sample}\n\n"
        f"In your next message, name the reference that you opened in this "
        f"session for each one. If you did not open one, revert the code. "
        f"Then open the reference. Write the code again from that reference. "
        f"Do not delete the citation and keep the code. If you only moved "
        f"existing comment lines, ignore this."
    )


def where(blocks):
    return ", ".join(f"{s}-{e}" for s, e, _ in blocks)


def main() -> int:
    try:
        payload = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        return 0

    tool_input = payload.get("tool_input") or {}
    tool_response = payload.get("tool_response") or {}
    file_path = _hookpath.normalize(
        tool_response.get("filePath") or tool_input.get("file_path"))
    if not file_path:
        return 0
    lower = file_path.lower()
    if not lower.endswith(C_EXTS + PY_EXTS):
        return 0
    if os.path.abspath(file_path) == os.path.abspath(__file__):
        return 0
    if not os.path.isfile(file_path):
        return 0

    blob = tool_input.get("content")
    if not isinstance(blob, str):
        blob = tool_input.get("new_string")
    if not isinstance(blob, str) or not blob:
        return 0
    old_blob = tool_input.get("old_string")
    old_blob = old_blob if isinstance(old_blob, str) else ""

    try:
        with open(file_path, encoding="utf-8", newline="") as fh:
            raw = fh.read()
    except OSError:
        return 0
    eol = "\r\n" if "\r\n" in raw else "\n"
    src = raw.replace("\r\n", "\n")
    lines = src.split("\n")
    is_py = lower.endswith(PY_EXTS)

    too_long = []
    ref_paths = []
    repo_paths = []
    no_citation = []
    verify = []
    tree = None
    for start, end, keep in comment_blocks(lower, lines, src):
        text = "\n".join(lines[start - 1:end])
        if text not in blob:
            continue
        if old_blob and text in old_blob:
            continue
        if end - start + 1 > MAX_LINES:
            too_long.append((start, end, keep))
            continue
        if REFERENCES_PATH_RE.search(text):
            ref_paths.append((start, end, keep))
            continue
        if tree is None:
            tree = repo_tree(file_path)
        if names_repo_path(text, tree):
            repo_paths.append((start, end, keep))
        elif not cited(text):
            no_citation.append((start, end, keep))
        else:
            verify.append((start, end, text))

    try:
        rel = os.path.relpath(file_path).replace("\\", "/")
    except ValueError:
        rel = file_path.replace("\\", "/")

    doomed = sorted(too_long + ref_paths + repo_paths + no_citation)
    wiped = False
    if doomed:
        new = apply_wipe(lines, doomed, is_py)
        ok = True
        if is_py:
            try:
                ast.parse(new)
            except SyntaxError:
                ok = False
        if ok:
            try:
                with open(file_path, "w", encoding="utf-8", newline="") as fh:
                    fh.write(new.replace("\n", eol))
                wiped = True
            except OSError:
                pass

    parts = []
    if wiped:
        reasons = [f"WIPED {len(doomed)} comment block(s) from {rel}."]
        if too_long:
            reasons.append(
                f"Lines {where(too_long)} were over {MAX_LINES} lines long.")
        if ref_paths:
            reasons.append(f"Lines {where(ref_paths)} named a references/ path.")
        if repo_paths:
            reasons.append(
                f"Lines {where(repo_paths)} named a file or directory of this "
                f"repository.")
        if no_citation:
            reasons.append(f"Lines {where(no_citation)} had no citation.")
        reasons.append("If the gate missed a real citation shape, tell the user.")
        parts.append(" ".join(reasons))

    if verify:
        sample = "\n".join(
            f"  {rel}:{s}: " + t.splitlines()[0].strip()[:100]
            for s, _e, t in verify[:5])
        parts.append(verification_text(rel, sample))

    if not parts:
        return 0

    if wiped and verify:
        headline = f"wiped {len(doomed)}, verify {len(verify)} in {rel}"
    elif wiped:
        headline = f"wiped {len(doomed)} comment block(s) from {rel}"
    else:
        headline = f"CITATION-VERIFICATION required in {rel}"

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": "\n\n".join(parts),
        },
        "systemMessage": f"[CLAUDE.md hook] {headline}",
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
