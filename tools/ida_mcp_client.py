"""Instance discovery, target resolution and HTTP transport for the IDA MCP server."""

from __future__ import annotations

import ctypes
import glob
import json
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from fnmatch import fnmatch
from typing import Any, Callable

import requests
from mcp.server.fastmcp.exceptions import ToolError

from ida_mcp_app import IDA_TIMEOUT, REGISTRY_DIR, logger

_discovery_cache: list[dict[str, Any]] = []
_discovery_cache_time: float = 0.0
_CACHE_TTL = 3.0


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


def discover_live_instances(force: bool = False) -> list[dict[str, Any]]:
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
            continue

        pid = info.get("pid")
        if pid is None:
            continue

        if not _pid_exists(pid):
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


def instance_label(inst: dict[str, Any]) -> str:
    """Format an instance record for display in error messages."""
    return f"  - {inst['instance_id']} (port={inst.get('port')}, pid={inst.get('pid')})"


def resolve_target(target: str) -> dict[str, Any]:
    """
    Resolve a target to a single instance record.

    target is REQUIRED and is one of:
    - A port number (integer or "port=N")
    - The full file path (instance_id) as shown by ida_list_instances
    - Any substring or glob of that path that matches exactly one instance,
      e.g. "ddi.dll", "casio*nk.exe"

    A pattern matching more than one instance is an error listing every
    candidate; it is never resolved by guessing.
    """
    instances = discover_live_instances()

    if not instances:
        raise ToolError(
            "No IDA instances are running. Load ida_server.py in IDA first."
        )

    if not target or not target.strip():
        raise ToolError(
            "target is REQUIRED. You must provide one of:\n"
            "  1. The port number (e.g. 58013)\n"
            "  2. The full file path (instance_id) from ida_list_instances\n"
            "  3. A substring or glob of that path matching exactly one instance\n"
            "Available instances:\n"
            + "\n".join(instance_label(i) for i in instances)
        )

    target = target.strip()

    port_str = target[5:] if target.startswith("port=") else target
    try:
        port_num = int(port_str)
        for inst in instances:
            if inst.get("port") == port_num:
                return inst
    except ValueError:
        pass

    lowered = target.lower().replace("/", "\\")

    for inst in instances:
        if inst["instance_id"].lower() == lowered:
            return inst

    if any(ch in lowered for ch in "*?["):
        matches = [i for i in instances
                   if fnmatch(i["instance_id"].lower(), lowered)
                   or fnmatch(i["instance_id"].lower(), "*" + lowered.strip("*") + "*")]
    else:
        matches = [i for i in instances if lowered in i["instance_id"].lower()]

    if len(matches) == 1:
        return matches[0]

    if len(matches) > 1:
        raise ToolError(
            f'target "{target}" is ambiguous - it matches {len(matches)} instances.\n'
            "Narrow it until it identifies one, or use the port number.\n"
            "Matching instances:\n"
            + "\n".join(instance_label(i) for i in matches)
        )

    raise ToolError(
        f'No IDA instance found for target "{target}".\n'
        "Use a port number, the full instance_id path, or a substring/glob of it\n"
        "that matches exactly one instance.\n"
        "Available instances:\n"
        + "\n".join(instance_label(i) for i in instances)
    )


def _base_url(target: str) -> str:
    """Resolve target to a base URL like http://127.0.0.1:51234."""
    inst = resolve_target(target)
    return f"http://{inst['host']}:{inst['port']}"


def _url(target: str, path: str) -> str:
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


def _get_json(url: str, params: dict[str, Any] | None,
              check: Callable[[dict[str, Any]], None] | None) -> dict[str, Any]:
    resp = requests.get(url, params=params or {}, timeout=IDA_TIMEOUT)
    payload = _handle_response(resp, url)
    if check is not None:
        check(payload)
    return payload


def ida_get(target: str, path: str, params: dict[str, Any] | None = None,
            check: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
    """GET JSON from a specific IDA HTTP server."""
    url = _url(target, path)
    logger.debug("GET %s %s", url, params)
    try:
        return _get_json(url, params, check)
    except requests.RequestException as exc:
        logger.error("HTTP error: %s", exc)
        raise ToolError(f"HTTP error talking to IDA at {url}: {exc}") from exc


def ida_post(target: str, path: str, body: dict[str, Any]) -> dict[str, Any]:
    """POST JSON to a specific IDA HTTP server."""
    url = _url(target, path)
    logger.debug("POST %s %s", url, body)
    try:
        resp = requests.post(url, json=body, timeout=IDA_TIMEOUT)
    except requests.RequestException as exc:
        logger.error("HTTP error: %s", exc)
        raise ToolError(f"HTTP error talking to IDA at {url}: {exc}") from exc
    return _handle_response(resp, url)


BROADCAST_PREFIX = "all:"
_BROADCAST_WORKERS = 12


def is_broadcast_target(target: str) -> bool:
    """True when *target* asks for a fan-out rather than a single instance."""
    if not target:
        return False
    stripped = target.strip()
    return stripped == "*" or stripped.lower().startswith(BROADCAST_PREFIX)


def resolve_broadcast_targets(target: str) -> list[dict[str, Any]]:
    """Resolve a broadcast target to the list of instances it selects."""
    instances = discover_live_instances()
    if not instances:
        raise ToolError(
            "No IDA instances are running. Load ida_server.py in IDA first."
        )

    stripped = target.strip()
    pattern = "" if stripped == "*" else stripped[len(BROADCAST_PREFIX):].strip()
    if not pattern or pattern == "*":
        return instances

    lowered = pattern.lower().replace("/", "\\")
    if any(ch in lowered for ch in "*?["):
        selected = [i for i in instances
                    if fnmatch(i["instance_id"].lower(), lowered)
                    or fnmatch(i["instance_id"].lower(), "*" + lowered.strip("*") + "*")]
    else:
        selected = [i for i in instances if lowered in i["instance_id"].lower()]

    if not selected:
        raise ToolError(
            f'Broadcast pattern "{pattern}" matched no running instance.\n'
            "Available instances:\n"
            + "\n".join(instance_label(i) for i in instances)
        )
    return selected


def _instance_labels(instances: list[dict[str, Any]]) -> dict[int, str]:
    """Short, unique display key per instance, keyed by port."""
    names: dict[int, str] = {}
    seen: dict[str, int] = {}
    for inst in instances:
        base = os.path.basename(inst["instance_id"]) or inst["instance_id"]
        seen[base] = seen.get(base, 0) + 1
    for inst in instances:
        base = os.path.basename(inst["instance_id"]) or inst["instance_id"]
        names[inst["port"]] = base if seen[base] == 1 else f"{base}@{inst['port']}"
    return names


def _is_empty_result(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    if payload.get("total_matched") == 0:
        return True
    return payload.get("count") == 0


def broadcast_get(target: str, path: str,
                  params: dict[str, Any] | None = None,
                  check: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
    """Run one GET against every instance the broadcast target selects.

    Instances are queried in parallel, so wall-clock stays close to a single
    call. Instances with no matches are omitted so the response carries the
    answer rather than a wall of empty records; one instance failing is
    reported without failing the rest.
    """
    instances = resolve_broadcast_targets(target)
    labels = _instance_labels(instances)

    results: dict[str, Any] = {}
    errors: dict[str, str] = {}
    empty: list[str] = []

    def _one(inst: dict[str, Any]):
        url = f"http://{inst['host']}:{inst['port']}{path}"
        return _get_json(url, params, check)

    with ThreadPoolExecutor(max_workers=min(_BROADCAST_WORKERS, len(instances))) as pool:
        futures = {pool.submit(_one, inst): inst for inst in instances}
        for future in as_completed(futures):
            inst = futures[future]
            label = labels[inst["port"]]
            try:
                payload = future.result()
            except Exception as exc:
                errors[label] = str(exc)
                continue
            if _is_empty_result(payload):
                empty.append(label)
            else:
                payload["instance_id"] = inst["instance_id"]
                results[label] = payload

    out: dict[str, Any] = {
        "broadcast": True,
        "searched": len(instances),
        "with_matches": len(results),
        "results": results,
    }
    if empty:
        out["no_matches"] = sorted(empty)
    if errors:
        out["errors"] = errors
    return out


def get_or_broadcast(target: str, path: str,
                     params: dict[str, Any] | None = None,
                     narrowed: bool = True,
                     narrowing_hint: str = "",
                     check: Callable[[dict[str, Any]], None] | None = None) -> dict[str, Any]:
    """Dispatch to one instance, or fan out when *target* is a broadcast."""
    if not is_broadcast_target(target):
        return ida_get(target, path, params, check)
    if not narrowed:
        raise ToolError(
            "Broadcasting this tool across instances without narrowing would "
            "return every entry from every module at once. " + narrowing_hint)
    return broadcast_get(target, path, params, check)


_EA_RE = re.compile(r"(?:0x)?([0-9a-f]+)")


def normalize_ea(ea: str) -> str:
    """
    Normalize a hex address string.
    Accepts "0x401000", "401000", "0X401000".
    Returns lowercase hex with 0x prefix.
    """
    parts = _EA_RE.fullmatch(ea.strip().lower())
    if not parts:
        raise ToolError(f"ea must be a hex address, got {ea!r}")
    return f"0x{int(parts.group(1), 16):x}"
