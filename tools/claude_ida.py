"""
IDA MCP Server (Unified)
------------------------
Single MCP server that discovers and routes to ALL running IDA instances.

IDA instances register themselves via ida_server.py into ~/.ida-mcp/instances/.
This server discovers them automatically — no hardcoded ports needed.

Configure with environment variables:
    IDA_HTTP_TIMEOUT   Per-request timeout in seconds (default: 30.0)

Run:
    python claude_ida.py
"""

from __future__ import annotations

import ctypes
import glob
import json
import logging
import os
import time
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
# Configuration
# ---------------------------------------------------------------------------

IDA_TIMEOUT = float(os.getenv("IDA_HTTP_TIMEOUT", "30.0"))
REGISTRY_DIR = os.path.join(os.path.expanduser("~"), ".ida-mcp", "instances")

# ---------------------------------------------------------------------------
# Instance discovery
# ---------------------------------------------------------------------------

# Cache to avoid hitting the filesystem on every tool call
_discovery_cache: list[dict[str, Any]] = []
_discovery_cache_time: float = 0.0
_CACHE_TTL = 3.0  # seconds


def _pid_exists(pid: int) -> bool:
    """Check if a process with the given PID exists (Windows)."""
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    handle = ctypes.windll.kernel32.OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION, False, pid
    )
    if handle:
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    return False


def _discover_live_instances(force: bool = False) -> list[dict[str, Any]]:
    """
    Read all instance files from the registry directory, validate liveness,
    and return a list of live instance records.

    Stale entries (dead PIDs) are cleaned up automatically.
    Results are cached for a few seconds to avoid repeated filesystem hits.
    """
    global _discovery_cache, _discovery_cache_time

    now = time.monotonic()
    if not force and _discovery_cache and (now - _discovery_cache_time) < _CACHE_TTL:
        return _discovery_cache

    if not os.path.isdir(REGISTRY_DIR):
        _discovery_cache = []
        _discovery_cache_time = now
        return []

    instances = []
    for path in glob.glob(os.path.join(REGISTRY_DIR, "*.json")):
        try:
            with open(path, "r") as f:
                info = json.load(f)
        except (json.JSONDecodeError, OSError):
            # Corrupted or unreadable — skip
            continue

        pid = info.get("pid")
        if pid is None:
            continue

        # Check if the process is still alive
        if not _pid_exists(pid):
            # Stale entry — clean up
            try:
                os.unlink(path)
                logger.info("Cleaned up stale instance file: %s", path)
            except OSError:
                pass
            continue

        instances.append(info)

    _discovery_cache = instances
    _discovery_cache_time = now
    return instances


def _resolve_target(target: Optional[str]) -> dict[str, Any]:
    """
    Resolve a target name to a single instance record.

    - If target is None and exactly one instance is running, auto-select it.
    - If target is None and multiple are running, raise with a listing.
    - Match by exact instance_id, or "name:pid" for disambiguation,
      or case-insensitive substring as a fallback.
    """
    instances = _discover_live_instances()

    if not instances:
        raise ToolError(
            "No IDA instances are running. Load ida_server.py in IDA first."
        )

    if target is None:
        if len(instances) == 1:
            return instances[0]
        names = [
            f'  - "{i["instance_id"]}" (pid {i["pid"]}, port {i["port"]})'
            for i in instances
        ]
        raise ToolError(
            "Multiple IDA instances running. Specify target=<name>:\n"
            + "\n".join(names)
        )

    # Exact match on instance_id
    matches = [i for i in instances if i["instance_id"] == target]
    if len(matches) == 1:
        return matches[0]

    # PID-qualified match: "commctrl.dll:12340"
    if ":" in target:
        name_part, pid_part = target.rsplit(":", 1)
        try:
            pid = int(pid_part)
            matches = [
                i for i in instances
                if i["instance_id"] == name_part and i["pid"] == pid
            ]
            if len(matches) == 1:
                return matches[0]
        except ValueError:
            pass

    # Case-insensitive substring fallback
    lower_target = target.lower()
    matches = [i for i in instances if lower_target in i["instance_id"].lower()]
    if len(matches) == 1:
        return matches[0]

    if len(matches) > 1:
        names = [
            f'  - "{i["instance_id"]}" (pid {i["pid"]}, port {i["port"]})'
            for i in matches
        ]
        raise ToolError(
            f'Ambiguous target "{target}" matches {len(matches)} instances:\n'
            + "\n".join(names)
            + '\nUse full name or "name:pid" to disambiguate.'
        )

    raise ToolError(f'No IDA instance found matching "{target}".')


# ---------------------------------------------------------------------------
# HTTP helpers (target-aware)
# ---------------------------------------------------------------------------


def _base_url(target: Optional[str]) -> str:
    """Resolve target to a base URL like http://127.0.0.1:51234."""
    inst = _resolve_target(target)
    return f"http://{inst['host']}:{inst['port']}"


def _url(target: Optional[str], path: str) -> str:
    base = _base_url(target)
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


def _ida_get(
    target: Optional[str], path: str, params: dict[str, Any] | None = None
) -> dict[str, Any]:
    """GET JSON from a specific IDA HTTP server."""
    url = _url(target, path)
    logger.debug("GET %s %s", url, params)
    try:
        resp = requests.get(url, params=params or {}, timeout=IDA_TIMEOUT)
    except requests.RequestException as exc:
        logger.error("HTTP error: %s", exc)
        raise ToolError(f"HTTP error talking to IDA at {url}: {exc}") from exc
    return _handle_response(resp, url)


def _ida_post(
    target: Optional[str], path: str, body: dict[str, Any]
) -> dict[str, Any]:
    """POST JSON to a specific IDA HTTP server."""
    url = _url(target, path)
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
# Discovery tool
# ---------------------------------------------------------------------------


@mcp.tool()
def ida_list_instances() -> dict[str, Any]:
    """
    List all running IDA instances available for analysis.
    Call this first to see what targets are available.

    Returns:
        {"count": N, "instances": [{"instance_id", "file_path", "port", "pid", "started_at"}, ...]}
    """
    instances = _discover_live_instances(force=True)
    # Strip host field from output (always 127.0.0.1), keep it clean
    cleaned = []
    for inst in instances:
        cleaned.append({
            "instance_id": inst.get("instance_id"),
            "file_path": inst.get("file_path"),
            "port": inst.get("port"),
            "pid": inst.get("pid"),
            "started_at": inst.get("started_at"),
            "ida_version": inst.get("ida_version"),
        })
    return {"count": len(cleaned), "instances": cleaned}


# ---------------------------------------------------------------------------
# Read tools
# ---------------------------------------------------------------------------


@mcp.tool()
def ida_ping(target: Optional[str] = None) -> dict[str, Any]:
    """
    Health check. Returns IDA version, Hex-Rays availability, and readonly status.

    Args:
        target: IDA instance to query (e.g. "commctrl.dll"). Optional if only one instance is running.
    """
    return _ida_get(target, "/api/ping")


@mcp.tool()
def ida_info(target: Optional[str] = None) -> dict[str, Any]:
    """
    Get metadata about the loaded IDB: file path, imagebase, architecture,
    pointer size, segment bounds, Hex-Rays availability, readonly mode.

    Args:
        target: IDA instance to query. Optional if only one instance is running.
    """
    return _ida_get(target, "/api/info")


@mcp.tool()
def ida_get_bytes(ea: str, size: int = 256, target: Optional[str] = None) -> dict[str, Any]:
    """
    Read raw bytes at an address.

    Args:
        ea: Hex address string (e.g. "0x401000").
        size: Number of bytes to read (default 256).
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"ea", "size", "bytes_hex"} where bytes_hex is a lowercase hex string.
    """
    if size <= 0:
        raise ToolError("size must be positive")
    return _ida_get(target, "/api/bytes", {"ea": _normalize_ea(ea), "size": str(size)})


@mcp.tool()
def ida_get_disasm(ea: str, count: int = 50, target: Optional[str] = None) -> dict[str, Any]:
    """
    Get disassembly lines starting at an address.

    Args:
        ea: Hex address string.
        count: Max number of instructions (default 50).
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"start_ea", "count", "disasm": [{"ea", "text"}, ...]}
    """
    if count <= 0:
        raise ToolError("count must be positive")
    return _ida_get(target, "/api/disasm", {"ea": _normalize_ea(ea), "count": str(count)})


@mcp.tool()
def ida_decompile(ea: str, target: Optional[str] = None) -> dict[str, Any]:
    """
    Decompile the function containing the given address using Hex-Rays.

    Args:
        ea: Hex address string.
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"ea", "function": {"name", "start_ea", "end_ea"}, "pseudocode"}
    """
    return _ida_get(target, "/api/decompile", {"ea": _normalize_ea(ea)})


@mcp.tool()
def ida_get_function_context(ea: str, target: Optional[str] = None) -> dict[str, Any]:
    """
    Get rich context for the function containing an address: disassembly,
    pseudocode, callers, callees, xrefs, and comments.

    Args:
        ea: Hex address string.
        target: IDA instance to query. Optional if only one instance is running.

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
    return _ida_get(target, "/api/function", {"ea": _normalize_ea(ea)})


@mcp.tool()
def ida_list_functions(
    limit: int = 0,
    name_filter: Optional[str] = None,
    mode: Literal["fast", "full"] = "fast",
    target: Optional[str] = None,
) -> dict[str, Any]:
    """
    List functions known to IDA.

    Args:
        limit: Max functions to return. 0 = no limit.
        name_filter: Case-insensitive substring filter on function names.
        mode: "fast" for basic info, "full" to also count xrefs_to and include type.
        target: IDA instance to query. Optional if only one instance is running.

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
    return _ida_get(target, "/api/functions", params)


@mcp.tool()
def ida_get_xrefs(
    ea: str,
    direction: Literal["from", "to", "both"] = "both",
    target: Optional[str] = None,
) -> dict[str, Any]:
    """
    Get cross-references for an address.

    Args:
        ea: Hex address string.
        direction: "from" (outgoing), "to" (incoming), or "both".
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"ea", "xrefs_from": [...], "xrefs_to": [...]}
        Each xref has {from, to, type, type_name}.
    """
    if direction not in ("from", "to", "both"):
        raise ToolError("direction must be 'from', 'to', or 'both'")
    return _ida_get(target, "/api/xrefs", {"ea": _normalize_ea(ea), "direction": direction})


@mcp.tool()
def ida_get_names(
    limit: int = 0,
    name_filter: Optional[str] = None,
    target: Optional[str] = None,
) -> dict[str, Any]:
    """
    List named addresses in the IDB.

    Args:
        limit: Max entries. 0 = no limit.
        name_filter: Case-insensitive substring filter.
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"count", "names": [{"ea", "name"}, ...]}
    """
    if limit < 0:
        raise ToolError("limit must be >= 0")
    params: dict[str, str] = {"limit": str(limit)}
    if name_filter:
        params["filter"] = name_filter
    return _ida_get(target, "/api/names", params)


@mcp.tool()
def ida_get_strings(
    limit: int = 0,
    min_length: int = 4,
    target: Optional[str] = None,
) -> dict[str, Any]:
    """
    List string literals found in the binary.

    Args:
        limit: Max strings to return. 0 = no limit.
        min_length: Minimum string length to include (default 4).
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"count", "strings": [{"ea", "length", "type", "value"}, ...]}
    """
    if limit < 0:
        raise ToolError("limit must be >= 0")
    return _ida_get(target, "/api/strings", {"limit": str(limit), "min_length": str(min_length)})


@mcp.tool()
def ida_get_segments(target: Optional[str] = None) -> dict[str, Any]:
    """
    List all segments (sections) in the binary.

    Args:
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"count", "segments": [{"start_ea", "end_ea", "name", "class", "size", "perm", "bitness"}, ...]}
    """
    return _ida_get(target, "/api/segments")


@mcp.tool()
def ida_get_imports(target: Optional[str] = None) -> dict[str, Any]:
    """
    List all imported modules and their functions.

    Args:
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"count", "modules": {"dll_name": [{"ea", "name", "ordinal"}, ...], ...}}
    """
    return _ida_get(target, "/api/imports")


@mcp.tool()
def ida_get_exports(target: Optional[str] = None) -> dict[str, Any]:
    """
    List all exported entry points.

    Args:
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"count", "exports": [{"index", "ordinal", "ea", "name"}, ...]}
    """
    return _ida_get(target, "/api/exports")


@mcp.tool()
def ida_list_structs(name_filter: Optional[str] = None, target: Optional[str] = None) -> dict[str, Any]:
    """
    List structure types defined in the IDB.

    Args:
        name_filter: Case-insensitive substring filter.
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"count", "structs": [{"index", "id", "name", "size", "is_union"}, ...]}
    """
    params: dict[str, str] = {}
    if name_filter:
        params["filter"] = name_filter
    return _ida_get(target, "/api/structs", params)


@mcp.tool()
def ida_get_struct(name: str, target: Optional[str] = None) -> dict[str, Any]:
    """
    Get full details of a struct by name, including all members.

    Args:
        name: Exact struct name.
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"name", "id", "size", "is_union",
         "members": [{"offset", "name", "size", "type", "comment"}, ...]}
    """
    if not name:
        raise ToolError("name is required")
    return _ida_get(target, "/api/struct", {"name": name})


@mcp.tool()
def ida_list_enums(name_filter: Optional[str] = None, target: Optional[str] = None) -> dict[str, Any]:
    """
    List enum types defined in the IDB.

    Args:
        name_filter: Case-insensitive substring filter.
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"count", "enums": [{"id", "name", "is_bitfield", "member_count"}, ...]}
    """
    params: dict[str, str] = {}
    if name_filter:
        params["filter"] = name_filter
    return _ida_get(target, "/api/enums", params)


@mcp.tool()
def ida_get_enum(name: str, target: Optional[str] = None) -> dict[str, Any]:
    """
    Get full details of an enum by name, including all members.

    Args:
        name: Exact enum name.
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"name", "id", "is_bitfield",
         "members": [{"name", "value", "value_hex"}, ...]}
    """
    if not name:
        raise ToolError("name is required")
    return _ida_get(target, "/api/enum", {"name": name})


@mcp.tool()
def ida_get_vtable(ea: str, count: int = 64, target: Optional[str] = None) -> dict[str, Any]:
    """
    Read a vtable as an array of pointers at a given address.
    Each pointer is resolved to a function name where possible.
    Stops early if a pointer target looks invalid (null, out of bounds).

    Args:
        ea: Hex address of the vtable start.
        count: Max number of slots to read (default 64).
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"ea", "pointer_size", "count",
         "entries": [{"index", "slot_ea", "target", "name", "is_function"}, ...]}
    """
    if count <= 0:
        raise ToolError("count must be positive")
    return _ida_get(target, "/api/vtable", {"ea": _normalize_ea(ea), "count": str(count)})


@mcp.tool()
def ida_get_address_info(ea: str, target: Optional[str] = None) -> dict[str, Any]:
    """
    Get detailed information about a single address: name, type, segment,
    flags (code/data/head/tail), containing function, comments, raw bytes.

    Args:
        ea: Hex address string.
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"ea", "name", "type", "segment", "is_code", "is_data", "is_head",
         "is_tail", "in_function", "function_name", "function_start",
         "comment", "repeatable_comment", "item_size", "bytes_hex"}
    """
    return _ida_get(target, "/api/address", {"ea": _normalize_ea(ea)})


@mcp.tool()
def ida_search_bytes(
    pattern: str,
    start: Optional[str] = None,
    direction: Literal["down", "up"] = "down",
    max_results: int = 100,
    target: Optional[str] = None,
) -> dict[str, Any]:
    """
    Search for a byte pattern in the binary.

    Args:
        pattern: Hex byte pattern with optional '??' wildcards,
                 e.g. "48 8B ?? 10" or "E8 ?? ?? ?? FF".
        start: Hex address to start searching from. Defaults to min_ea (down) or max_ea (up).
        direction: "down" (forward) or "up" (backward). Default "down".
        max_results: Max matches to return (default 100).
        target: IDA instance to query. Optional if only one instance is running.

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
    return _ida_get(target, "/api/search", params)


# ---------------------------------------------------------------------------
# Write tools (will return 403 if the IDA server is in readonly mode)
# ---------------------------------------------------------------------------


@mcp.tool()
def ida_rename(ea: str, name: str, target: Optional[str] = None) -> dict[str, Any]:
    """
    Rename an address (function, global, label, etc).

    Args:
        ea: Hex address to rename.
        name: New name. Use "" to clear an existing name.
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"ea", "name", "success": true}

    Raises:
        ToolError with a 403 message if the IDA server is in readonly mode.
    """
    return _ida_post(target, "/api/rename", {"ea": _normalize_ea(ea), "name": name})


@mcp.tool()
def ida_set_comment(ea: str, comment: str, repeatable: bool = False, target: Optional[str] = None) -> dict[str, Any]:
    """
    Set a comment at an address.

    Args:
        ea: Hex address.
        comment: Comment text. Use "" to clear.
        repeatable: If true, set as a repeatable comment.
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"ea", "comment", "repeatable", "success": true}
    """
    return _ida_post(target, "/api/comment", {
        "ea": _normalize_ea(ea),
        "comment": comment,
        "repeatable": repeatable,
    })


@mcp.tool()
def ida_set_func_comment(ea: str, comment: str, repeatable: bool = False, target: Optional[str] = None) -> dict[str, Any]:
    """
    Set a comment on the function containing an address.

    Args:
        ea: Hex address within the target function.
        comment: Comment text. Use "" to clear.
        repeatable: If true, set as a repeatable comment.
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"ea", "comment", "repeatable", "success": true}
    """
    return _ida_post(target, "/api/func_comment", {
        "ea": _normalize_ea(ea),
        "comment": comment,
        "repeatable": repeatable,
    })


@mcp.tool()
def ida_set_type(ea: str, type_decl: str, target: Optional[str] = None) -> dict[str, Any]:
    """
    Apply a C type declaration at an address.

    Args:
        ea: Hex address.
        type_decl: C type string, e.g. "int __fastcall(int a, int b)"
                   or "struct MyStruct *". The trailing semicolon is
                   added automatically if missing.
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"ea", "type", "success": true}
    """
    if not type_decl:
        raise ToolError("type_decl is required")
    return _ida_post(target, "/api/set_type", {
        "ea": _normalize_ea(ea),
        "type": type_decl,
    })


@mcp.tool()
def ida_create_function(start_ea: str, end_ea: Optional[str] = None, target: Optional[str] = None) -> dict[str, Any]:
    """
    Create a function at the given address range. If end_ea is omitted,
    IDA will try to determine the function boundaries automatically.

    Args:
        start_ea: Hex address of the function start.
        end_ea: Optional hex address of the function end.
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"start_ea", "end_ea", "success": true}
    """
    body: dict[str, str] = {"start_ea": _normalize_ea(start_ea)}
    if end_ea:
        body["end_ea"] = _normalize_ea(end_ea)
    return _ida_post(target, "/api/create_function", body)


@mcp.tool()
def ida_delete_function(ea: str, target: Optional[str] = None) -> dict[str, Any]:
    """
    Delete the function containing the given address.

    Args:
        ea: Hex address within the function to delete.
        target: IDA instance to query. Optional if only one instance is running.

    Returns:
        {"ea", "success": true}
    """
    return _ida_post(target, "/api/delete_function", {"ea": _normalize_ea(ea)})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """
    Run the MCP server over stdio.

    Environment variables:
        IDA_HTTP_TIMEOUT  Request timeout in seconds (default 30.0)
    """
    logger.info(
        "Starting unified IDA MCP server, registry=%s, timeout=%.1fs",
        REGISTRY_DIR,
        IDA_TIMEOUT,
    )
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
