"""Search MCP tools."""

from __future__ import annotations

from typing import Any, Literal, Optional

from mcp.server.fastmcp.exceptions import ToolError

from ida_mcp_app import mcp
from ida_mcp_client import get_or_broadcast, ida_get, normalize_ea


def _require(value: str, name: str) -> None:
    if not value:
        raise ToolError(f"{name} is required")


def _require_direction(direction: str) -> None:
    if direction not in ("down", "up"):
        raise ToolError("direction must be 'down' or 'up'")


def _flag(value: bool) -> str:
    return "1" if value else "0"


def _search_params(max_results: int, start: Optional[str], end: Optional[str],
                   **fields: str) -> dict[str, str]:
    if max_results <= 0:
        raise ToolError("max_results must be positive")
    params = dict(fields, max_results=str(max_results))
    if start:
        params["start"] = normalize_ea(start)
    if end:
        params["end"] = normalize_ea(end)
    return params


@mcp.tool()
def ida_search_bytes(
    target: str,
    pattern: str,
    start: Optional[str] = None,
    direction: Literal["down", "up"] = "down",
    max_results: int = 100,
) -> dict[str, Any]:
    """
    Search for a byte pattern in the binary.

    Broadcast: target="*" or "all:<pattern>" queries every instance in parallel;
    modules with no matches are omitted.

    Args:
        pattern: Hex byte pattern with optional '??' wildcards,
                 e.g. "48 8B ?? 10" or "E8 ?? ?? ?? FF". A wildcard covers a
                 whole byte: a half-byte token such as "4?" is refused. To match
                 part of an instruction word, use ida_search_insn.
        start: Hex address to start searching from. Defaults to min_ea (down) or max_ea (up).
        direction: "down" (forward) or "up" (backward). Default "down".
        max_results: Max matches to return (default 100).
        target: Port, full path, or a unique substring/glob of it (e.g. "ddi.dll", "casio*nk.exe"). Ambiguous matches error and list candidates.

    Returns:
        {"pattern", "count", "results": [{"ea", "name"}, ...]}
    """
    _require(pattern, "pattern")
    _require_direction(direction)
    params = _search_params(max_results, start, None, pattern=pattern, direction=direction)
    return get_or_broadcast(target, "/api/search", params)


@mcp.tool()
def ida_search_text(
    target: str,
    text: str,
    encoding: Literal["ascii", "utf16", "both"] = "both",
    start: Optional[str] = None,
    direction: Literal["down", "up"] = "down",
    max_results: int = 100,
) -> dict[str, Any]:
    """
    Search for literal text. The text is encoded to bytes server-side, so never
    hand-encode it for ida_search_bytes. CE ROMs store strings as UTF-16LE,
    hence "both" by default. Matching is CASE-SENSITIVE (raw byte compare).

    Broadcast: target="*" or "all:<pattern>" queries every instance in parallel;
    modules with no matches are omitted.

    Args:
        text: Literal text, e.g. "Halting system".
        encoding: "ascii", "utf16", or "both" (default, merges both).
        start: Hex address to start from. Defaults to min_ea (down) / max_ea (up).
        direction: "down" (default) or "up".
        max_results: Max matches (default 100).
        target: Port, full path, or a unique substring/glob of it (e.g. "ddi.dll", "casio*nk.exe"). Ambiguous matches error and list candidates.

    Returns:
        {"text", "encoding", "count",
         "results": [{"ea", "name", "encoding", "pattern"}, ...]}
        Matches bytes anywhere, including inside a longer string; to enumerate
        defined string literals use ida_get_strings with content_filter.
    """
    _require(text, "text")
    if encoding not in ("ascii", "utf16", "both"):
        raise ToolError("encoding must be 'ascii', 'utf16' or 'both'")
    _require_direction(direction)
    params = _search_params(max_results, start, None, text=text, encoding=encoding,
                            direction=direction)
    return get_or_broadcast(target, "/api/search_text", params)


@mcp.tool()
def ida_search_immediate(
    target: str,
    value: str,
    include_halves: bool = False,
    start: Optional[str] = None,
    end: Optional[str] = None,
    max_results: int = 100,
) -> dict[str, Any]:
    """
    Find instructions whose operands carry a constant. Answers "what touches
    MMIO 0x0B000018", which xrefs cannot: that address is not inside the IDB.
    Every hit names its containing function.

    MIPS/ARM build a 32-bit constant from two instructions (lui/ori, lui/addiu),
    so it never appears whole in one operand - if an exact search finds nothing,
    retry with include_halves=true. A 0x0000 half is skipped, so a page-aligned
    base matches on its high half only. Hits rank exact/address above high16
    above low16.

    Broadcast: target="*" or "all:<pattern>" queries every instance in parallel;
    modules with no matches are omitted.

    Args:
        value: Constant as hex, e.g. "0x0B000018".
        include_halves: Also match either 16-bit half. Default false.
        start, end: Optional hex bounds on the scan. Default: whole image.
        max_results: Max hits (default 100).
        target: Port, full path, or a unique substring/glob of it (e.g. "ddi.dll", "casio*nk.exe"). Ambiguous matches error and list candidates.

    Returns:
        {"value_hex", "count", "total_matches", "matches_by_kind",
         "scanned_instructions", "truncated",
         "results": [{"ea", "op_index", "matched_as", "func_ea", "func_name", "disasm"}, ...]}
        matched_as is "immediate" | "address" | "high16" | "low16";
        matches_by_kind gives the signal/noise split before you read results.
    """
    _require(value, "value")
    params = _search_params(max_results, start, end, value=normalize_ea(value),
                            include_halves=_flag(include_halves))
    return get_or_broadcast(target, "/api/search_immediate", params)


_SEARCH_INSN_DESCRIPTION = (
    'Find code whose instruction word matches "VALUE/MASK" hex pairs, for example '
    'patterns="4014/F0FF 8200/FF00". Each word is read in the byte order of the image and '
    "matches when (word & MASK) == VALUE. word_size is the size of one instruction word in "
    "bytes: 1, 2 or 4 (SH and Thumb 2, ARM and MIPS 4). The word at the head of each code "
    "item is tested. include_noncode=true also tests every word of the code segments "
    "that is not inside a code item, at addresses aligned to word_size: unexplored bytes "
    'and data items. Such a hit has where "undefined" or "data". It is a literal, a table, '
    'or code that IDA does not decode, so read it before a claim of "no such instruction". '
    'target is a port, a path or a unique substring of it; "*" or "all:<pattern>" queries '
    "every instance. start and end are optional hex bounds. Returns patterns, count, "
    "total_matches, matches_by_pattern, scanned_instructions, scanned_undefined_words, "
    "scanned_data_words, truncated and results [{ea, word, pattern, where, func_ea, "
    "func_name, disasm}]. matches_by_pattern counts a word for each pattern that it "
    "matches, and pattern names the first of them."
)


@mcp.tool(description=_SEARCH_INSN_DESCRIPTION)
def ida_search_insn(
    target: str,
    patterns: str,
    word_size: int,
    include_noncode: bool = False,
    start: Optional[str] = None,
    end: Optional[str] = None,
    max_results: int = 100,
) -> dict[str, Any]:
    _require(patterns, "patterns")
    params = _search_params(max_results, start, end, patterns=patterns,
                            word_size=str(word_size), include_noncode=_flag(include_noncode))

    def ran_requested_pass(reply: dict[str, Any]) -> None:
        if reply.get("include_noncode") is not include_noncode:
            raise ToolError(
                "The reply of this IDA instance does not state the include_noncode pass "
                "that the request asked for. Its server text differs from the text of this "
                "tool. Restart the instance.")

    return get_or_broadcast(target, "/api/search_insn", params, check=ran_requested_pass)
