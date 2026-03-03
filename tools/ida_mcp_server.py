"""
IDA MCP Server
--------------
Exposes IDA Pro analysis capabilities as MCP tools, backed by the
ida_api_server.py HTTP server running inside IDA.

Configure with environment variables:
    IDA_BASE_URL       Base URL of the IDA HTTP server (default: http://127.0.0.1:6000)
    IDA_HTTP_TIMEOUT   Per-request timeout in seconds (default: 30.0)

Run:
    python ida_mcp_server.py
"""

from __future__ import annotations

import logging
import os
from typing import Any, Literal, Optional

import requests
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

# ---------------------------------------------------------------------------
# Logging (stderr, as recommended for stdio MCP servers)
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ida-mcp")

# ---------------------------------------------------------------------------
# MCP server instance
# ---------------------------------------------------------------------------

mcp = FastMCP("ida-tools")

# ---------------------------------------------------------------------------
# Backend configuration
# ---------------------------------------------------------------------------

IDA_BASE_URL = os.getenv("IDA_BASE_URL", "http://127.0.0.1:6000")
IDA_TIMEOUT = float(os.getenv("IDA_HTTP_TIMEOUT", "30.0"))


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _url(path: str) -> str:
    base = IDA_BASE_URL.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


def _handle_response(resp: requests.Response, url: str) -> dict[str, Any]:
    """Check status, parse JSON, raise ToolError on problems."""
    if resp.status_code >= 400:
        text = resp.text.strip()[:500]
        logger.warning("IDA %s %s: %s", resp.status_code, url, text)
        raise ToolError(f"IDA HTTP {resp.status_code} for {url}: {text}")
    try:
        return resp.json()
    except ValueError as exc:
        logger.error("Non-JSON from %s: %s", url, resp.text[:200])
        raise ToolError(f"Non-JSON response from IDA at {url}") from exc


def _ida_get(path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    """GET JSON from the IDA HTTP server."""
    url = _url(path)
    logger.debug("GET %s %s", url, params)
    try:
        resp = requests.get(url, params=params or {}, timeout=IDA_TIMEOUT)
    except requests.RequestException as exc:
        logger.error("HTTP error: %s", exc)
        raise ToolError(f"HTTP error talking to IDA at {url}: {exc}") from exc
    return _handle_response(resp, url)


def _ida_post(path: str, body: dict[str, Any]) -> dict[str, Any]:
    """POST JSON to the IDA HTTP server."""
    url = _url(path)
    logger.debug("POST %s %s", url, body)
    try:
        resp = requests.post(url, json=body, timeout=IDA_TIMEOUT)
    except requests.RequestException as exc:
        logger.error("HTTP error: %s", exc)
        raise ToolError(f"HTTP error talking to IDA at {url}: {exc}") from exc
    return _handle_response(resp, url)


def _normalize_ea(ea: str) -> str:
    """
    Normalize a hex address string.
    Accepts "0x401000", "401000", "0X401000".
    Returns lowercase hex with 0x prefix.
    """
    s = ea.strip().lower()
    if not s:
        raise ToolError("ea must be a non-empty hex string")
    if s.startswith("0x"):
        s = s[2:]
    try:
        value = int(s, 16)
    except ValueError as exc:
        raise ToolError(f"ea must be a hex address, got {ea!r}") from exc
    return f"0x{value:x}"


# ---------------------------------------------------------------------------
# Read tools
# ---------------------------------------------------------------------------


@mcp.tool()
def ida_ping() -> dict[str, Any]:
    """
    Health check. Returns IDA version, Hex-Rays availability, and readonly status.
    """
    return _ida_get("/api/ping")


@mcp.tool()
def ida_info() -> dict[str, Any]:
    """
    Get metadata about the loaded IDB: file path, imagebase, architecture,
    pointer size, segment bounds, Hex-Rays availability, readonly mode.
    """
    return _ida_get("/api/info")


@mcp.tool()
def ida_get_bytes(ea: str, size: int = 256) -> dict[str, Any]:
    """
    Read raw bytes at an address.

    Args:
        ea: Hex address string (e.g. "0x401000").
        size: Number of bytes to read (default 256).

    Returns:
        {"ea", "size", "bytes_hex"} where bytes_hex is a lowercase hex string.
    """
    if size <= 0:
        raise ToolError("size must be positive")
    return _ida_get("/api/bytes", {"ea": _normalize_ea(ea), "size": str(size)})


@mcp.tool()
def ida_get_disasm(ea: str, count: int = 50) -> dict[str, Any]:
    """
    Get disassembly lines starting at an address.

    Args:
        ea: Hex address string.
        count: Max number of instructions (default 50).

    Returns:
        {"start_ea", "count", "disasm": [{"ea", "text"}, ...]}
    """
    if count <= 0:
        raise ToolError("count must be positive")
    return _ida_get("/api/disasm", {"ea": _normalize_ea(ea), "count": str(count)})


@mcp.tool()
def ida_decompile(ea: str) -> dict[str, Any]:
    """
    Decompile the function containing the given address using Hex-Rays.

    Args:
        ea: Hex address string.

    Returns:
        {"ea", "function": {"name", "start_ea", "end_ea"}, "pseudocode"}
    """
    return _ida_get("/api/decompile", {"ea": _normalize_ea(ea)})


@mcp.tool()
def ida_get_function_context(ea: str) -> dict[str, Any]:
    """
    Get rich context for the function containing an address: disassembly,
    pseudocode, callers, callees, xrefs, and comments.

    Args:
        ea: Hex address string.

    Returns:
        {
            "ea", "in_function",
            "function": {"name", "start_ea", "end_ea"} | null,
            "bytes_at_ea", "disasm", "pseudocode",
            "xrefs_from", "xrefs_to", "callers", "callees",
            "function_comment", "function_repeatable_comment",
            "instr_comments"
        }
    """
    return _ida_get("/api/function", {"ea": _normalize_ea(ea)})


@mcp.tool()
def ida_list_functions(
    limit: int = 0,
    name_filter: Optional[str] = None,
    mode: Literal["fast", "full"] = "fast",
) -> dict[str, Any]:
    """
    List functions known to IDA.

    Args:
        limit: Max functions to return. 0 = no limit.
        name_filter: Case-insensitive substring filter on function names.
        mode: "fast" for basic info, "full" to also count xrefs_to and include type.

    Returns:
        {"count", "functions": [{"start_ea", "end_ea", "name", "size", ...}, ...]}
    """
    if limit < 0:
        raise ToolError("limit must be >= 0")
    if mode not in ("fast", "full"):
        raise ToolError("mode must be 'fast' or 'full'")
    params: dict[str, str] = {"limit": str(limit), "mode": mode}
    if name_filter:
        params["filter"] = name_filter
    return _ida_get("/api/functions", params)


@mcp.tool()
def ida_get_xrefs(
    ea: str,
    direction: Literal["from", "to", "both"] = "both",
) -> dict[str, Any]:
    """
    Get cross-references for an address.

    Args:
        ea: Hex address string.
        direction: "from" (outgoing), "to" (incoming), or "both".

    Returns:
        {"ea", "xrefs_from": [...], "xrefs_to": [...]}
        Each xref has {from, to, type, type_name}.
    """
    if direction not in ("from", "to", "both"):
        raise ToolError("direction must be 'from', 'to', or 'both'")
    return _ida_get("/api/xrefs", {"ea": _normalize_ea(ea), "direction": direction})


@mcp.tool()
def ida_get_names(
    limit: int = 0,
    name_filter: Optional[str] = None,
) -> dict[str, Any]:
    """
    List named addresses in the IDB.

    Args:
        limit: Max entries. 0 = no limit.
        name_filter: Case-insensitive substring filter.

    Returns:
        {"count", "names": [{"ea", "name"}, ...]}
    """
    if limit < 0:
        raise ToolError("limit must be >= 0")
    params: dict[str, str] = {"limit": str(limit)}
    if name_filter:
        params["filter"] = name_filter
    return _ida_get("/api/names", params)


@mcp.tool()
def ida_get_strings(
    limit: int = 0,
    min_length: int = 4,
) -> dict[str, Any]:
    """
    List string literals found in the binary.

    Args:
        limit: Max strings to return. 0 = no limit.
        min_length: Minimum string length to include (default 4).

    Returns:
        {"count", "strings": [{"ea", "length", "type", "value"}, ...]}
    """
    if limit < 0:
        raise ToolError("limit must be >= 0")
    return _ida_get("/api/strings", {"limit": str(limit), "min_length": str(min_length)})


@mcp.tool()
def ida_get_segments() -> dict[str, Any]:
    """
    List all segments (sections) in the binary.

    Returns:
        {"count", "segments": [{"start_ea", "end_ea", "name", "class", "size", "perm", "bitness"}, ...]}
    """
    return _ida_get("/api/segments")


@mcp.tool()
def ida_get_imports() -> dict[str, Any]:
    """
    List all imported modules and their functions.

    Returns:
        {"count", "modules": {"dll_name": [{"ea", "name", "ordinal"}, ...], ...}}
    """
    return _ida_get("/api/imports")


@mcp.tool()
def ida_get_exports() -> dict[str, Any]:
    """
    List all exported entry points.

    Returns:
        {"count", "exports": [{"index", "ordinal", "ea", "name"}, ...]}
    """
    return _ida_get("/api/exports")


@mcp.tool()
def ida_list_structs(name_filter: Optional[str] = None) -> dict[str, Any]:
    """
    List structure types defined in the IDB.

    Args:
        name_filter: Case-insensitive substring filter.

    Returns:
        {"count", "structs": [{"index", "id", "name", "size", "is_union"}, ...]}
    """
    params: dict[str, str] = {}
    if name_filter:
        params["filter"] = name_filter
    return _ida_get("/api/structs", params)


@mcp.tool()
def ida_get_struct(name: str) -> dict[str, Any]:
    """
    Get full details of a struct by name, including all members.

    Args:
        name: Exact struct name.

    Returns:
        {"name", "id", "size", "is_union",
         "members": [{"offset", "name", "size", "type", "comment"}, ...]}
    """
    if not name:
        raise ToolError("name is required")
    return _ida_get("/api/struct", {"name": name})


@mcp.tool()
def ida_list_enums(name_filter: Optional[str] = None) -> dict[str, Any]:
    """
    List enum types defined in the IDB.

    Args:
        name_filter: Case-insensitive substring filter.

    Returns:
        {"count", "enums": [{"id", "name", "is_bitfield", "member_count"}, ...]}
    """
    params: dict[str, str] = {}
    if name_filter:
        params["filter"] = name_filter
    return _ida_get("/api/enums", params)


@mcp.tool()
def ida_get_enum(name: str) -> dict[str, Any]:
    """
    Get full details of an enum by name, including all members.

    Args:
        name: Exact enum name.

    Returns:
        {"name", "id", "is_bitfield",
         "members": [{"name", "value", "value_hex"}, ...]}
    """
    if not name:
        raise ToolError("name is required")
    return _ida_get("/api/enum", {"name": name})


@mcp.tool()
def ida_get_vtable(ea: str, count: int = 64) -> dict[str, Any]:
    """
    Read a vtable as an array of pointers at a given address.
    Each pointer is resolved to a function name where possible.
    Stops early if a pointer target looks invalid (null, out of bounds).

    Args:
        ea: Hex address of the vtable start.
        count: Max number of slots to read (default 64).

    Returns:
        {"ea", "pointer_size", "count",
         "entries": [{"index", "slot_ea", "target", "name", "is_function"}, ...]}
    """
    if count <= 0:
        raise ToolError("count must be positive")
    return _ida_get("/api/vtable", {"ea": _normalize_ea(ea), "count": str(count)})


@mcp.tool()
def ida_get_address_info(ea: str) -> dict[str, Any]:
    """
    Get detailed information about a single address: name, type, segment,
    flags (code/data/head/tail), containing function, comments, raw bytes.

    Args:
        ea: Hex address string.

    Returns:
        {"ea", "name", "type", "segment", "is_code", "is_data", "is_head",
         "is_tail", "in_function", "function_name", "function_start",
         "comment", "repeatable_comment", "item_size", "bytes_hex"}
    """
    return _ida_get("/api/address", {"ea": _normalize_ea(ea)})


@mcp.tool()
def ida_search_bytes(
    pattern: str,
    start: Optional[str] = None,
    direction: Literal["down", "up"] = "down",
    max_results: int = 100,
) -> dict[str, Any]:
    """
    Search for a byte pattern in the binary.

    Args:
        pattern: Hex byte pattern with optional '??' wildcards,
                 e.g. "48 8B ?? 10" or "E8 ?? ?? ?? FF".
        start: Hex address to start searching from. Defaults to min_ea (down) or max_ea (up).
        direction: "down" (forward) or "up" (backward). Default "down".
        max_results: Max matches to return (default 100).

    Returns:
        {"pattern", "count", "results": [{"ea", "name"}, ...]}
    """
    if not pattern:
        raise ToolError("pattern is required")
    if direction not in ("down", "up"):
        raise ToolError("direction must be 'down' or 'up'")
    if max_results <= 0:
        raise ToolError("max_results must be positive")
    params: dict[str, str] = {
        "pattern": pattern,
        "direction": direction,
        "max_results": str(max_results),
    }
    if start:
        params["start"] = _normalize_ea(start)
    return _ida_get("/api/search", params)


# ---------------------------------------------------------------------------
# Write tools (will return 403 if the IDA server is in readonly mode)
# ---------------------------------------------------------------------------


@mcp.tool()
def ida_rename(ea: str, name: str) -> dict[str, Any]:
    """
    Rename an address (function, global, label, etc).

    Args:
        ea: Hex address to rename.
        name: New name. Use "" to clear an existing name.

    Returns:
        {"ea", "name", "success": true}

    Raises:
        ToolError with a 403 message if the IDA server is in readonly mode.
    """
    return _ida_post("/api/rename", {"ea": _normalize_ea(ea), "name": name})


@mcp.tool()
def ida_set_comment(ea: str, comment: str, repeatable: bool = False) -> dict[str, Any]:
    """
    Set a comment at an address.

    Args:
        ea: Hex address.
        comment: Comment text. Use "" to clear.
        repeatable: If true, set as a repeatable comment.

    Returns:
        {"ea", "comment", "repeatable", "success": true}
    """
    return _ida_post("/api/comment", {
        "ea": _normalize_ea(ea),
        "comment": comment,
        "repeatable": repeatable,
    })


@mcp.tool()
def ida_set_func_comment(ea: str, comment: str, repeatable: bool = False) -> dict[str, Any]:
    """
    Set a comment on the function containing an address.

    Args:
        ea: Hex address within the target function.
        comment: Comment text. Use "" to clear.
        repeatable: If true, set as a repeatable comment.

    Returns:
        {"ea", "comment", "repeatable", "success": true}
    """
    return _ida_post("/api/func_comment", {
        "ea": _normalize_ea(ea),
        "comment": comment,
        "repeatable": repeatable,
    })


@mcp.tool()
def ida_set_type(ea: str, type_decl: str) -> dict[str, Any]:
    """
    Apply a C type declaration at an address.

    Args:
        ea: Hex address.
        type_decl: C type string, e.g. "int __fastcall(int a, int b)"
                   or "struct MyStruct *". The trailing semicolon is
                   added automatically if missing.

    Returns:
        {"ea", "type", "success": true}
    """
    if not type_decl:
        raise ToolError("type_decl is required")
    return _ida_post("/api/set_type", {
        "ea": _normalize_ea(ea),
        "type": type_decl,
    })


@mcp.tool()
def ida_create_function(start_ea: str, end_ea: Optional[str] = None) -> dict[str, Any]:
    """
    Create a function at the given address range. If end_ea is omitted,
    IDA will try to determine the function boundaries automatically.

    Args:
        start_ea: Hex address of the function start.
        end_ea: Optional hex address of the function end.

    Returns:
        {"start_ea", "end_ea", "success": true}
    """
    body: dict[str, str] = {"start_ea": _normalize_ea(start_ea)}
    if end_ea:
        body["end_ea"] = _normalize_ea(end_ea)
    return _ida_post("/api/create_function", body)


@mcp.tool()
def ida_delete_function(ea: str) -> dict[str, Any]:
    """
    Delete the function containing the given address.

    Args:
        ea: Hex address within the function to delete.

    Returns:
        {"ea", "success": true}
    """
    return _ida_post("/api/delete_function", {"ea": _normalize_ea(ea)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """
    Run the MCP server over stdio.

    Environment variables:
        IDA_BASE_URL      IDA HTTP server URL (default http://127.0.0.1:6000)
        IDA_HTTP_TIMEOUT  Request timeout in seconds (default 30.0)
    """
    logger.info("Starting IDA MCP server, backend=%s, timeout=%.1fs", IDA_BASE_URL, IDA_TIMEOUT)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
