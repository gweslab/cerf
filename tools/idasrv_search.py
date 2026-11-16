"""Search endpoints."""

import re

import idaapi
import idc
import ida_bytes
import ida_funcs
import ida_ida
import ida_nalt
import ida_segment
import ida_ua
import idautils

from idasrv_util import get_name, hex_ea, is_64bit

# Hex-pattern validator for ep_search. IDA's parse_binpat_str pops a
# modal "Bad digit found in the input. Do you want to search for it as
# a text string?" Please-confirm dialog when the pattern contains any
# character outside the hex/wildcard set. The dialog blocks IDA's main
# thread, which blocks every MCP execute_sync caller, which fails every
# subsequent MCP request with read-timeout / connection-refused. Reject
# bad input here in Python so parse_binpat_str never sees it.
_HEX_PATTERN_RE = re.compile(r'^[0-9A-Fa-f?\s]+$')

_TEXT_ENCODINGS = {
    "ascii": "ascii",
    "utf16": "utf-16-le",
}


def _compile_pattern(pattern, start_ea):
    compiled = ida_bytes.compiled_binpat_vec_t()
    encoding = ida_nalt.get_default_encoding_idx(ida_nalt.BPU_1B)
    ida_bytes.parse_binpat_str(compiled, start_ea, pattern, 16, encoding)
    if compiled.size() == 0:
        raise ValueError(
            f"pattern did not compile to any bytes: {pattern!r}. Use hex digit "
            "pairs with optional ?? wildcards, e.g. '4D 5A ?? 10'.")
    return compiled


def _run_search(pattern, start_ea, direction, max_results):
    low = ida_ida.inf_get_min_ea()
    if start_ea is None:
        start_ea = low if direction == "down" else ida_ida.inf_get_max_ea()

    search_flag = ida_bytes.BIN_SEARCH_FORWARD if direction == "down" else ida_bytes.BIN_SEARCH_BACKWARD
    search_flag |= ida_bytes.BIN_SEARCH_CASE

    compiled = _compile_pattern(pattern, start_ea)
    pattern_len = len(compiled[0].bytes)

    results = []
    cur = start_ea
    for _ in range(max_results):
        if direction == "down":
            raw = ida_bytes.bin_search(cur, idaapi.BADADDR, compiled, search_flag)
        else:
            if cur <= low:
                break
            raw = ida_bytes.bin_search(low, cur, compiled, search_flag)
        found = raw[0] if isinstance(raw, tuple) else raw
        if found == idaapi.BADADDR:
            break
        results.append({
            "ea": hex_ea(found),
            "name": get_name(found),
        })
        cur = found + 1 if direction == "down" else found + pattern_len - 1
    return results


def ep_search(pattern, start_ea, direction, max_results):
    """
    Search for a byte pattern.
    *pattern* is a hex string with optional wildcards, e.g. "48 8B ?? 10".
    """
    if not pattern:
        raise ValueError("pattern must not be empty")
    if not _HEX_PATTERN_RE.match(pattern):
        raise ValueError(
            "pattern must contain only hex digits [0-9A-Fa-f], wildcards "
            "(?), and whitespace. Got: " + repr(pattern))
    for token in pattern.split():
        if "?" in token and token.strip("?"):
            raise ValueError(
                f"pattern token {token!r} mixes hex digits with '?'. A wildcard "
                "covers a whole byte ('??'); a half-byte wildcard is not supported. "
                "To match part of an instruction word, use the instruction search "
                "(/api/search_insn) with a VALUE/MASK pattern.")

    results = _run_search(pattern, start_ea, direction, max_results)
    return {
        "pattern": pattern,
        "count": len(results),
        "results": results,
    }


def _text_to_pattern(text, encoding_key):
    codec = _TEXT_ENCODINGS[encoding_key]
    try:
        raw = text.encode(codec)
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"text is not encodable as {encoding_key}: {exc}. Use encoding="
            "'utf16' for wide text, or search the bytes directly.") from exc
    return " ".join("%02X" % b for b in raw)


def ep_search_text(text, encoding, start_ea, direction, max_results):
    """
    Search for literal text, encoded server-side into a byte pattern.

    *encoding* is "ascii", "utf16" or "both". Every Windows CE ROM stores most
    of its strings as UTF-16LE, so "both" is the useful default.

    Matching is case-sensitive: the text is compiled to a raw byte pattern, and
    IDA applies case folding only to patterns built from quoted string literals.
    """
    if not text:
        raise ValueError("text must not be empty")
    if encoding not in ("ascii", "utf16", "both"):
        raise ValueError(f"encoding must be 'ascii', 'utf16' or 'both'. Got: {encoding!r}")

    keys = ["ascii", "utf16"] if encoding == "both" else [encoding]

    hits = []
    errors = {}
    for key in keys:
        try:
            pattern = _text_to_pattern(text, key)
        except ValueError as exc:
            errors[key] = str(exc)
            continue
        for hit in _run_search(pattern, start_ea, direction, max_results):
            hit["encoding"] = key
            hit["pattern"] = pattern
            hits.append(hit)

    if not hits and errors and len(errors) == len(keys):
        raise ValueError("; ".join(errors.values()))

    hits.sort(key=lambda h: int(h["ea"], 16), reverse=(direction == "up"))
    hits = hits[:max_results]

    result = {
        "text": text,
        "encoding": encoding,
        "count": len(hits),
        "results": hits,
    }
    if errors:
        result["skipped_encodings"] = errors
    return result


_MATCH_RANK = {"immediate": 0, "address": 0, "high16": 1, "low16": 2}


def _scan_range(start_ea, end_ea):
    low = start_ea if start_ea is not None else ida_ida.inf_get_min_ea()
    high = end_ea if end_ea is not None else ida_ida.inf_get_max_ea()
    if low >= high:
        raise ValueError(f"start {hex_ea(low)} is not below end {hex_ea(high)}")
    return low, high


def _code_heads(low, high):
    for ea in idautils.Heads(low, high):
        if ida_bytes.is_code(ida_bytes.get_flags(ea)):
            yield ea


def _function_of(ea):
    func = ida_funcs.get_func(ea)
    return {
        "func_ea": hex_ea(func.start_ea) if func else None,
        "func_name": ida_funcs.get_func_name(func.start_ea) if func else None,
    }


def _count(counts, key):
    counts[key] = counts.get(key, 0) + 1


def _page(matches, max_results):
    results = matches[:max_results]
    return {
        "count": len(results),
        "total_matches": len(matches),
        "truncated": len(matches) > len(results),
        "results": results,
    }


def _operand_match(op, target, mask, halves):
    if op.type == ida_ua.o_imm:
        if (op.value & mask) == target:
            return "immediate"
        return halves.get(op.value & 0xFFFF)
    if op.type in (ida_ua.o_mem, ida_ua.o_near, ida_ua.o_far):
        if (op.addr & mask) == target:
            return "address"
    return None


def ep_search_immediate(value, include_halves, start_ea, end_ea, max_results):
    """
    Find instructions whose operands carry *value*.

    Covers immediates and resolved address operands. A 32-bit constant that the
    CPU builds from two instructions (a MIPS lui/ori or addiu pair, an ARM
    literal pair) never appears whole in one operand, so include_halves also
    reports operands matching either 16-bit half.

    A half equal to 0x0000 is never matched: it would match every zero immediate
    while saying nothing about the target, and page-aligned addresses (the usual
    reason to search at all) have exactly that low half.

    The whole range is scanned and the hits are ranked before truncation, so a
    flood of half matches can never crowd out an exact one.
    """
    low, high = _scan_range(start_ea, end_ea)

    mask = 0xFFFFFFFFFFFFFFFF if is_64bit() else 0xFFFFFFFF
    target = value & mask

    halves = {}
    if include_halves:
        lo16 = target & 0xFFFF
        hi16 = (target >> 16) & 0xFFFF
        if lo16:
            halves[lo16] = "low16"
        if hi16:
            halves[hi16] = "high16"

    matches = []
    scanned = 0
    insn = ida_ua.insn_t()

    for ea in _code_heads(low, high):
        if ida_ua.decode_insn(insn, ea) <= 0:
            continue
        scanned += 1
        for index, op in enumerate(insn.ops):
            if op.type == ida_ua.o_void:
                break
            matched = _operand_match(op, target, mask, halves)
            if not matched:
                continue
            matches.append({
                "ea": hex_ea(ea),
                "op_index": index,
                "matched_as": matched,
                **_function_of(ea),
                "disasm": idc.GetDisasm(ea),
            })
            break

    matches.sort(key=lambda m: (_MATCH_RANK[m["matched_as"]], int(m["ea"], 16)))

    by_kind = {}
    for m in matches:
        _count(by_kind, m["matched_as"])

    out = {
        "value": target,
        "value_hex": hex_ea(target),
        "include_halves": include_halves,
        "matches_by_kind": by_kind,
        "scanned_instructions": scanned,
        **_page(matches, max_results),
    }
    if include_halves and not halves:
        out["note"] = ("Both 16-bit halves of this value are zero, so no half "
                       "matching was performed.")
    elif include_halves and (target & 0xFFFF) == 0:
        out["note"] = ("Low half is 0x0000 and was skipped; only the high half "
                       f"0x{(target >> 16) & 0xFFFF:04X} was matched.")
    if not matches and not include_halves:
        out["hint"] = (
            "No operand carries this value whole. On MIPS and ARM a 32-bit "
            "constant is usually built from two instructions, so retry with "
            "include_halves=true to match either 16-bit half.")
    return out


_INSN_PATTERN_RE = re.compile(r'([0-9A-Fa-f]+)/([0-9A-Fa-f]+)')


def _parse_insn_patterns(spec, word_size):
    digits = word_size * 2
    word_limit = 1 << (word_size * 8)
    patterns = []
    for token in spec.replace(",", " ").split():
        parts = _INSN_PATTERN_RE.fullmatch(token)
        if not parts:
            raise ValueError(
                f"pattern {token!r} must have the form VALUE/MASK in hex digits, "
                "e.g. '4014/F0FF'")
        value = int(parts.group(1), 16)
        mask = int(parts.group(2), 16)
        if mask == 0:
            raise ValueError(f"pattern {token!r} has a zero mask, which matches every word")
        if value & ~mask:
            raise ValueError(f"pattern {token!r} has value bits outside its mask")
        if mask >= word_limit:
            raise ValueError(
                f"pattern {token!r} has mask bits outside a word of {word_size} bytes")
        patterns.append(("%0*X/%0*X" % (digits, value, digits, mask), value, mask))
    if not patterns:
        raise ValueError("patterns must not be empty")
    return patterns


def ep_search_insn(patterns_spec, word_size, include_noncode, start_ea, end_ea, max_results):
    if word_size not in (1, 2, 4):
        raise ValueError(f"word_size must be 1, 2 or 4. Got: {word_size!r}")
    patterns = _parse_insn_patterns(patterns_spec, word_size)

    low, high = _scan_range(start_ea, end_ea)
    order = "big" if ida_ida.inf_is_be() else "little"

    matches = []
    by_pattern = {}

    def test(ea, where):
        raw = ida_bytes.get_bytes(ea, word_size)
        if raw is None or len(raw) != word_size:
            return
        word = int.from_bytes(raw, order)
        labels = [label for label, value, mask in patterns if (word & mask) == value]
        if not labels:
            return
        for label in labels:
            _count(by_pattern, label)
        matches.append({
            "ea": hex_ea(ea),
            "word": "0x%0*X" % (word_size * 2, word),
            "pattern": labels[0],
            "where": where,
            **_function_of(ea),
            "disasm": idc.GetDisasm(ea) if where == "code" else None,
        })

    scanned = 0
    for ea in _code_heads(low, high):
        scanned += 1
        test(ea, "code")

    undefined_words = 0
    data_words = 0
    if include_noncode:
        for seg_start in idautils.Segments():
            seg = ida_segment.getseg(seg_start)
            if seg is None or seg.type != ida_segment.SEG_CODE:
                continue
            ea = max(seg.start_ea, low)
            ea += -ea % word_size
            end = min(seg.end_ea, high)
            while ea < end:
                head = ida_bytes.get_item_head(ea)
                flags = ida_bytes.get_flags(head)
                if ida_bytes.is_code(flags):
                    ea = ida_bytes.get_item_end(head)
                    ea += -ea % word_size
                    continue
                if ida_bytes.is_unknown(flags):
                    undefined_words += 1
                    test(ea, "undefined")
                else:
                    data_words += 1
                    test(ea, "data")
                ea += word_size

    matches.sort(key=lambda m: int(m["ea"], 16))
    return {
        "patterns": [label for label, _, _ in patterns],
        "word_size": word_size,
        "include_noncode": include_noncode,
        "matches_by_pattern": by_pattern,
        "scanned_instructions": scanned,
        "scanned_undefined_words": undefined_words,
        "scanned_data_words": data_words,
        **_page(matches, max_results),
    }
