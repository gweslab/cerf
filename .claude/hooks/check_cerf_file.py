#!/usr/bin/env python3
"""
PostToolUse hook for Write|Edit on C/C++ source files (.cpp/.h/.hpp/.cc/.c).
Warns about:
  1. LINE-COUNT      — file > 500 lines (the pre-commit hook will reject it).
  2. BAILOUT-COMMENT — TODO / FIXME / HACK / XXX / "for now" / "temporary" /
                       "deferred" / "placeholder" / "good enough" /
                       "clean up later" / "fix later" / etc. — in comments only.
  3. LEAK-DEV-EMU    — "dev_emu_src" anywhere in the file. This is an internal
                       reference-tree path and must never appear in source.
  4. LEAK-CHECKLIST  — "docs/ai_checklists" path or any *.md filename under
                       that dir. Checklists are confidential per
                       agent_docs/code_style.md § Comments and
                       agent_docs/rules.md.
  5. REFERENCE-COMMENT — a comment references another `cerf/...path...\.cpp`
                       (or .h) file. Often dead-weight narration ("Body lives
                       in X", "moved to Y", "out-of-line in Z") per
                       agent_docs/code_style.md § Comments. Advisory — agent
                       must self-check whether the reference adds technical
                       substance or is pointer-only narration.
  6. BLOATED-COMMENT — /* ... */ block comments that are ≥5 lines OR contain
                       internal blank lines (multi-paragraph essays). Forces
                       the agent to evaluate each block: real technical
                       comment or rotten yapping. Pre-existing comments are
                       NOT excluded — touching the file means owning its rot.
  7. REFERENCE-TREE-PATH — a comment cites a path under references/. That
                       tree is a gigabytes-scale external reference dump
                       (chip datasheets, BSP source archives, ARM ARM
                       excerpts). Pointing to a path in it is dead-weight
                       narration; the comment should inline the SUBSTANCE
                       (specific bits, register fields, BSP behaviour) or
                       not exist.
  8. ALWAYS-BAILOUT — scheduling-verb phrasings ("deferred to/until/for",
                       "placeholder until X", "to/will be implemented",
                       "TODO: implement X", "implement X later", etc.).
                       The BAILOUT-COMMENT FP gate does NOT rescue these —
                       there's no "specific technical mechanism" defence
                       because the phrasing IS the deferral. Exists to
                       close the dodge where agents invoke the FP gate
                       by naming something technical near the matched
                       word.

Comment extraction is state-aware across lines, so naked-continuation lines
inside a /* ... */ block (no leading `*`) are still recognised as comment
text. That matters for Doxygen-light style where the path lands on a
continuation line below the opener.

Reads tool I/O JSON from stdin and emits hookSpecificOutput JSON to stdout to
inject the warning back into the model's context for the next turn. Silent
(no output, exit 0) when the file is clean or the matcher doesn't apply.
"""
import json
import os
import re
import sys

CAP = 500

BAILOUT_WORDS_RE = re.compile(
    r"\b(?:TODO|FIXME|HACK|XXX|for now|temporary|temporarily|deferred|"
    r"placeholder|good enough|clean up later|fix later|wire up later|"
    r"will be needed later|will add later|come back later)|next iteration|scope expansion\b",
    re.IGNORECASE,
)

# Scheduling-verb phrasings that document FUTURE WORK in a comment.
# Unconditional bailouts — the BAILOUT-COMMENT FP gate does NOT apply
# (there is no "specific technical mechanism" defence because the
# phrasing itself IS the deferral, not a technical term that happens
# to share a word). This category exists because agents repeatedly
# dodged BAILOUT-COMMENT by naming something technical nearby and
# claiming the matched word referred to that, not to deferral.
ALWAYS_BAILOUT_RE = re.compile(
    r"\b(?:"
    r"deferred\s+(?:to|until|for|in)\b|"
    r"placeholder\s+(?:until|for\s+(?:real|the|actual|future|next))\b|"
    r"(?:to|will)\s+be\s+(?:implemented|added|wired|handled)\b|"
    r"yet\s+to\s+be\s+(?:implemented|added|wired)\b|"
    r"TODO\s*:?\s*implement\b|"
    r"implement(?:ed|s|ing)?\s+(?:later|next|soon)\b"
    r")",
    re.IGNORECASE,
)

DEV_EMU_RE = re.compile(r"\bdev_emu_src\b", re.IGNORECASE)

CHECKLIST_PATH_RE = re.compile(r"docs/ai_checklists\b", re.IGNORECASE)

# Path under the references/ tree mentioned in a comment. The tree is
# gitignored and gigabytes-scale (chip datasheets, BSP archives, ARM
# manual excerpts) — enumerating filenames is impractical, so just
# match the literal `references/<something>` shape. The substance the
# referenced doc contains belongs inline; the path itself does not.
REFERENCES_TREE_RE = re.compile(r"\breferences/[\w./_-]+", re.IGNORECASE)

# Source-file reference in a comment, matched by basename (path prefix
# optional). Requires at least one underscore in the basename — that's
# the CERF naming convention (`arm_jit.cpp`, `emit_ldr_word.cpp`,
# `s3c2410_intc.cpp`, …) and it also automatically excludes common
# system headers that have no underscore (`windows.h`, `stdio.h`,
# `commctrl.h`, `aygshell.h`, `ceshell.h`, etc.). Trade-off: misses
# single-word CERF files like `mmu.cpp` — acceptable, those are rare.
CERF_FILE_REF_RE = re.compile(r"\b[\w-]*_[\w_-]*\.(?:cpp|h)\b")


def extract_comment_text(line: str, in_block: bool) -> tuple:
    """Return (comment_text_from_this_line, new_in_block_state).

    Handles // line comments, /* ... */ block comments spanning multiple
    lines, and naked-continuation lines (no leading `*`). When `in_block`
    is True on entry, the line is treated as comment-continuation until a
    `*/` is found.
    """
    parts = []
    pos = 0
    n = len(line)
    while pos < n:
        if in_block:
            close = line.find("*/", pos)
            if close >= 0:
                parts.append(line[pos:close])
                in_block = False
                pos = close + 2
            else:
                parts.append(line[pos:])
                pos = n
        else:
            open_block = line.find("/*", pos)
            line_comment = line.find("//", pos)
            if line_comment >= 0 and (open_block < 0 or line_comment < open_block):
                parts.append(line[line_comment + 2:])
                pos = n
            elif open_block >= 0:
                pos = open_block + 2
                in_block = True
            else:
                pos = n
    return " ".join(parts), in_block


def find_bloated_blocks(content: str) -> list:
    """Return [(start_line, num_lines, multi_paragraph), ...] for /* ... */
    block comments that look like bloat: >=5 lines, or contain at least one
    internal blank line (multi-paragraph essay structure)."""
    hits = []
    for m in re.finditer(r"/\*.*?\*/", content, re.DOTALL):
        block = m.group(0)
        num_lines = block.count("\n") + 1
        lines = block.splitlines()
        multi_paragraph = False
        if len(lines) > 2:
            for line in lines[1:-1]:
                stripped = line.strip().lstrip("*").strip()
                if not stripped:
                    multi_paragraph = True
                    break
        if num_lines >= 5 or multi_paragraph:
            start_line = content[:m.start()].count("\n") + 1
            hits.append((start_line, num_lines, multi_paragraph))
    return hits


def collect_checklist_filenames() -> list:
    """Enumerate *.md basenames under docs/ai_checklists/, like the pre-commit hook."""
    root = "docs/ai_checklists"
    if not os.path.isdir(root):
        return []
    names = set()
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f.endswith(".md"):
                names.add(f)
    return sorted(names)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return 0

    tool_input = payload.get("tool_input") or {}
    tool_response = payload.get("tool_response") or {}
    file_path = tool_response.get("filePath") or tool_input.get("file_path")

    if not file_path:
        return 0
    if not file_path.lower().endswith((".cpp", ".h", ".hpp", ".cc", ".c")):
        return 0
    if not os.path.isfile(file_path):
        return 0

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError:
        return 0

    try:
        rel_path = os.path.relpath(file_path).replace("\\", "/")
    except ValueError:
        rel_path = file_path.replace("\\", "/")

    warnings = []

    # Check 1: line-count cap. Skip trace files, mirroring .githooks/pre-commit.
    if "tracing/" not in rel_path:
        line_count = content.count("\n")
        if content and not content.endswith("\n"):
            line_count += 1
        if line_count > CAP:
            warnings.append(
                f"LINE-COUNT: {rel_path} is now {line_count} lines (cap={CAP}). "
                f"The pre-commit hook will reject the commit. Split by "
                f"responsibility BEFORE continuing — coupling grows fast, "
                f"refactor while it's still cheap. See agent_docs/code_style.md "
                f'"File & Symbol Style".'
            )

    bailout_hits = []
    dev_emu_hits = []
    checklist_path_hits = []
    checklist_name_hits = []
    cerf_ref_hits = []
    references_tree_hits = []
    always_bailout_hits = []

    checklist_names = collect_checklist_filenames()
    checklist_name_re = (
        re.compile(r"\b(?:" + "|".join(re.escape(n) for n in checklist_names) + r")\b")
        if checklist_names
        else None
    )

    in_block = False
    for ln_idx, line in enumerate(content.splitlines(), start=1):
        comment_text, in_block = extract_comment_text(line, in_block)

        if comment_text and BAILOUT_WORDS_RE.search(comment_text):
            bailout_hits.append(f"  {rel_path}:{ln_idx}: {line.strip()}")

        if comment_text and ALWAYS_BAILOUT_RE.search(comment_text):
            always_bailout_hits.append(f"  {rel_path}:{ln_idx}: {line.strip()}")

        if DEV_EMU_RE.search(line):
            dev_emu_hits.append(f"  {rel_path}:{ln_idx}: {line.strip()}")

        if CHECKLIST_PATH_RE.search(line):
            checklist_path_hits.append(f"  {rel_path}:{ln_idx}: {line.strip()}")

        if checklist_name_re and checklist_name_re.search(line):
            checklist_name_hits.append(f"  {rel_path}:{ln_idx}: {line.strip()}")

        if comment_text and CERF_FILE_REF_RE.search(comment_text):
            cerf_ref_hits.append(f"  {rel_path}:{ln_idx}: {line.strip()}")

        if comment_text and REFERENCES_TREE_RE.search(comment_text):
            references_tree_hits.append(f"  {rel_path}:{ln_idx}: {line.strip()}")

    def fmt_block(label: str, hits: list, advice: str) -> str:
        sample = "\n".join(hits[:5])
        more = f"\n  ... and {len(hits) - 5} more" if len(hits) > 5 else ""
        return f"{label}: {rel_path} has {len(hits)} hit(s). {advice}\n\n{sample}{more}"

    if always_bailout_hits:
        warnings.append(fmt_block(
            "ALWAYS-BAILOUT",
            always_bailout_hits,
            "THE BAILOUT-COMMENT FALSE-POSITIVE GATE DOES NOT APPLY TO "
            "THIS CATEGORY. The phrasings caught here document FUTURE "
            "WORK being scheduled in a comment — there is no 'specific "
            "technical mechanism' defence because the phrasing IS the "
            "deferral, not a technical term that happens to share a "
            "word. The canonical dodge — agent naming something "
            "technical nearby (a NEON instruction, a register, a Win32 "
            "API) and claiming the matched word referred to that "
            "instead of to deferral — is explicitly closed for these "
            "phrasings.\n\n"
            "Caught shapes (all unconditional bailouts):\n"
            "  'deferred to next batch' / 'deferred until X is wired'\n"
            "  'placeholder until real impl' / 'placeholder for future'\n"
            "  '(to|will) be implemented / added / wired / handled'\n"
            "  'yet to be implemented'\n"
            "  'TODO: implement X' / 'implement X later/next/soon'\n\n"
            "ONLY TWO LEGITIMATE RESPONSES (same as BAILOUT-COMMENT):\n"
            "  (a) IMPLEMENT the missing logic NOW, in full, so the "
            "deferral phrasing is no longer needed AND the code is "
            "complete.\n"
            "  (b) STOP the task, REVERT the incomplete code, and "
            "surface the blocker to the user.\n\n"
            "There is no 'next batch' in CLAUDE.md. There is no 'next "
            "session'. There is no scheduled-for-later. The comment "
            "documenting it is the disclosure that the code is "
            "incomplete — fix the code or stop, but the phrasing "
            "itself must not survive into the committed file.\n\n"
            "REPHRASING the comment to drop the deferral verb while "
            "leaving the code unchanged is the Euphemism Smuggling / "
            "Disclosure Destruction pattern explicitly named in "
            "agent_docs/rules.md and is even worse than the original "
            "phrasing. Pre-existing comments are NOT excluded.",
        ))

    if bailout_hits:
        warnings.append(fmt_block(
            "BAILOUT-COMMENT",
            bailout_hits,
            "FALSE-POSITIVE GATE — READ FIRST: this is a regex, not a "
            "semantic analyzer. Words matched here ('deferred', 'placeholder', "
            "'temporary', 'for now', 'later', etc.) have legitimate technical "
            "uses in CE / Win32 / JIT code: CE Deferred Procedure Calls "
            "(DPCs); Win32 cue-banner placeholder text (EM_SETCUEBANNER, "
            "Edit Control placeholder); ephemeral / temporary buffers in an "
            "algorithm; 'later' as sequencing in a narrative (\"the cache is "
            "flushed later\"). If you can name the SPECIFIC technical "
            "mechanism the matched word is describing in this exact spot, "
            "this is a false positive — ignore the rest of this message and "
            "proceed. If you CANNOT point to a specific mechanism, the "
            "warning applies and the remainder below is for you.\n\n"
            "SEVERE: this bailout token in a comment is the VISIBLE TIP of "
            "HIDDEN INCOMPLETE CODE below it. The bug is NOT the comment — "
            "the bug is whatever the comment is admitting is unfinished. "
            "This anti-pattern has shipped broken JIT / SoC code more than "
            "TEN times in CERF history, with downstream debugging costing "
            "WEEKS per function once the half-finished path actually fires.\n\n"
            "TWO RESPONSES TO THIS HOOK ARE FORBIDDEN — they are how the "
            "ten prior incidents landed:\n"
            "  (1) REPHRASING the comment to drop the bailout token while "
            "      leaving the code unchanged. 'For now: foo' → 'Currently: "
            "      foo' / 'Implemented here: foo' / etc. is the exact "
            "      'Euphemism smuggling' + 'Disclosure destruction' pattern "
            "      named in agent_docs/rules.md § Bailout Patterns. The "
            "      smell is preserved; only the disclosure is gone.\n"
            "  (2) DELETING the comment entirely while leaving the code "
            "      unchanged. WORSE than the original bailout — the "
            "      disclosure was protecting future readers from "
            "      rediscovering the bug under a fresh debugging budget. "
            "      A silently-stripped comment turns the eventual "
            "      rediscovery into an unattributable multi-week debug.\n\n"
            "ONLY TWO LEGITIMATE RESPONSES:\n"
            "  (a) IMPLEMENT the missing logic NOW, in full, so the "
            "      comment is no longer needed AND the code is complete.\n"
            "  (b) STOP the task, REVERT the incomplete code, and surface "
            "      the blocker to the user as a direction request — "
            "      'I cannot complete X because Y, here are the options'.\n\n"
            "If you find yourself about to reword OR delete this comment "
            "without ALSO completing the code beneath it: STOP. You are "
            "reproducing incident #11. Read agent_docs/rules.md § Bailout "
            "Patterns end-to-end before touching anything else.",
        ))

    if dev_emu_hits:
        warnings.append(fmt_block(
            "LEAK-DEV-EMU",
            dev_emu_hits,
            "'dev_emu_src' is an internal reference-tree path and must NEVER "
            "appear in CERF source. Remove the mention; if you need to cite "
            "an external behavior, cite the chip datasheet section / BSP "
            "source path / ARM ARM section per agent_docs/workflow.md § "
            "'Reference Citations In Code'.",
        ))

    if checklist_path_hits:
        warnings.append(fmt_block(
            "LEAK-CHECKLIST-PATH",
            checklist_path_hits,
            "Checklists under docs/ai_checklists/ are CONFIDENTIAL design "
            "material per agent_docs/code_style.md § Comments. The path "
            "must never appear in committed source. Inline the WHY as a "
            "self-contained technical note about the code below, or delete "
            "the reference entirely.",
        ))

    if checklist_name_hits:
        warnings.append(fmt_block(
            "LEAK-CHECKLIST-NAME",
            checklist_name_hits,
            "A *.md filename from docs/ai_checklists/ appears in this file. "
            "Checklist filenames are confidential (see pre-commit hook). The "
            "fix is NOT to reword — re-read agent_docs/code_style.md § "
            "Comments and reconsider whether the comment should exist at all.",
        ))

    if references_tree_hits:
        warnings.append(fmt_block(
            "REFERENCE-TREE-PATH",
            references_tree_hits,
            "A comment cites a path under references/. That tree is a "
            "gigabytes-scale external reference dump (chip datasheets, "
            "BSP source archives, ARM manual excerpts) and is gitignored. "
            "Pointing to a path in it is dead-weight narration — the "
            "comment should inline the SUBSTANCE the doc says at that "
            "point (specific bits, register fields, BSP function "
            "behaviour) or not exist at all. The PATH itself helps "
            "nobody: it can't be opened from a fresh clone, and even "
            "where the tree exists locally, the reader needs the "
            "claim, not the pointer.\n\n"
            "Three legitimate responses:\n"
            "  1. Inline the specific technical claim the doc makes "
            "(\"only bits 29:28 are RES0\" / \"DMA channel 0 must be "
            "primed before SDC1\" / etc.) and DELETE the path mention.\n"
            "  2. If the surrounding code is already self-explanatory "
            "without the doc claim, DELETE the whole comment.\n"
            "  3. (Rare) if the comment ALREADY inlines the substance "
            "and the path was just decoration, DELETE only the path.\n\n"
            "Common shape this catches: 'we use X instead of Y; see "
            "references/foo/bar.txt' — both halves are bloat. The 'we "
            "use X instead of Y' is design narration (the FAIL example "
            "in BLOATED-COMMENT), and the references/ pointer is "
            "dead-weight redirection.",
        ))

    if cerf_ref_hits:
        warnings.append(fmt_block(
            "REFERENCE-COMMENT",
            cerf_ref_hits,
            "A comment references another cerf/ source file by path. Per "
            "agent_docs/code_style.md § Comments: 'A comment that still "
            "makes sense moved to a random file is dead weight — useful "
            "comments are glued to the specific code below them. Generic "
            "narration (\"lives in X\", \"moved to Y\", \"out-of-line in Z\") "
            "reads the same anywhere because it says nothing about what's "
            "actually there.' Self-check: does THIS comment add a "
            "non-obvious WHY about the code right below it, or is it "
            "dead-weight narration redirecting the reader to another file? "
            "Sibling-source references ARE allowed when they convey specific "
            "technical info; they are NOT allowed as standalone 'see X' / "
            "'body in X' pointers. If the WHY would be the same whether the "
            "code lived here or in the referenced file, delete the comment.",
        ))

    bloat_hits = find_bloated_blocks(content)
    if bloat_hits:
        sample_lines = [
            f"  {rel_path}:{ln}: {n} lines, multi_paragraph={mp}"
            for ln, n, mp in bloat_hits[:5]
        ]
        more = (
            f"\n  ... and {len(bloat_hits) - 5} more"
            if len(bloat_hits) > 5
            else ""
        )
        sample = "\n".join(sample_lines) + more
        warnings.append(
            f"BLOATED-COMMENT: {rel_path} has {len(bloat_hits)} comment "
            f"block(s) that are ≥5 lines OR have multi-paragraph "
            f"structure (internal blank lines).\n\n"
            f"DEFAULT ACTION IS DELETE. ~99% of multi-line comments in "
            f"CERF are AI-generated bloat. The bar for keeping a comment "
            f"is high and the burden of proof is on you. If you cannot "
            f"pass BOTH tests below for a block, the block goes.\n\n"
            f"TEST 1 — FAILURE: name the SPECIFIC, CONCRETE FAILURE that "
            f"a future agent triggers by ignoring this comment and "
            f"editing the code the way the comment is silently warning "
            f"against. Write it as one sentence: 'if Y, then Z breaks "
            f"because W'. No failure namable → DELETE.\n\n"
            f"TEST 2 — REDUNDANCY: would a competent CERF reader "
            f"(someone who has read CLAUDE.md + agent_docs/) infer this "
            f"from the surrounding code + STANDARD PROJECT CONVENTIONS "
            f"(cfg comes from cerf.json; BSPs only write the registers "
            f"they care about; services resolved via emu_.Get<>; FCSE "
            f"fold below 32 MB; SCTLR-write flushes JIT cache; …)? If "
            f"YES, this is project-knowledge restatement, not real "
            f"signal. DELETE.\n\n"
            f"NON-NEGOTIABLE: 'non-obvious WHY' / 'has a citation' / "
            f"'tied to the code below' are NECESSARY conditions, NOT "
            f"SUFFICIENT ones. The historical dodge has been agents "
            f"ticking off those three phrases and keeping background "
            f"narration. Both tests above must pass.\n\n"
            f"PASS examples (specific failure named, NOT inferrable "
            f"from standard conventions):\n"
            f"  /* MUST be after PinHostState — Mmu::Translate uses the\n"
            f"     host TLB directly and a stale entry from the prior\n"
            f"     process returns the wrong PA. */\n"
            f"  /* Read XSIZE/YSIZE before PDISP_PD=1 — the regs read 0\n"
            f"     once powered down (BSP odo_display.c:142), and the\n"
            f"     renderer would publish a 0-by-0 frame. */\n\n"
            f"FAIL examples (look technical, fail Test 1 or Test 2):\n"
            f"  /* Dims come from DeviceConfig (cerf.json) rather than\n"
            f"     DISP_XSIZE / DISP_YSIZE MMIO: the 2BPP driver\n"
            f"     hardcodes 480/240 (DISPDRVR.C:51-52) and never\n"
            f"     writes the XSIZE/YSIZE registers. */\n"
            f"     → FAILS Test 2: every CERF reader knows cfg comes\n"
            f"       from cerf.json and BSPs may not write all regs.\n"
            f"  /* dim comes from cfg, not regs.XSize, per BSP. */\n"
            f"     → FAILS Test 1: no specific failure named.\n"
            f"  /* why we use approach A rather than B */\n"
            f"  /* we chose RAII here over manual close. */\n"
            f"  /* Implementation note: …  Background: …  Trade-off: … */\n"
            f"  /* Shape S because consumers resolve this exact type. */\n"
            f"  /* see also the parallel handling in foo_bar.cpp. */\n\n"
            f"'Why X not Y' / 'rather than' / 'we chose' framings are "
            f"BANNED EVEN WITH A CITATION. The reader doesn't need "
            f"alternatives history. If picking Y would genuinely break, "
            f"the comment is 'DO NOT switch to Y — Z breaks because W'. "
            f"Otherwise, no comment.\n\n"
            f"If a block fails either test → DELETE the entire block. "
            f"Not 'rephrase', not 'shrink' — DELETE. A 50-line essay "
            f"distilled to 4 lines is acceptable, but ONLY if every "
            f"surviving line passes both tests. If nothing survives, "
            f"the whole block goes.\n\n"
            f"Per agent_docs/code_style.md § Comments: 'Default: no "
            f"comment. Well-named identifiers explain the WHAT. Write a "
            f"comment only when the WHY is non-obvious. Keep it short.'\n\n"
            f"PRE-EXISTING COMMENTS ARE NOT EXCLUDED. You touched this "
            f"file — you own its rot. 'It was already there' / 'another "
            f"session wrote it' is not a defence.\n\n"
            f"Hits:\n{sample}"
        )

    if not warnings:
        return 0

    full = "\n\n".join(warnings)
    headline = warnings[0].split(":", 1)[0]
    out = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": full,
        },
        "systemMessage": f"[CLAUDE.md hook] {headline} in {rel_path}",
    }
    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
