"""
IDA HTTP API Server (Unified)
-----------------------------
Exposes IDA Pro's analysis database over HTTP for use by remote clients
(MCP servers, automation scripts, AI agents, etc).

Targets IDA 9.0+ with IDAPython. Uses ida_typeinf for struct/enum
access (ida_struct and ida_enum were removed in IDA 9.0).

Auto-assigns a free port and registers the instance for discovery by
the unified MCP client (claude_ida.py).

Endpoints live in the idasrv_* sibling modules:
    idasrv_config  configuration, logging, Hex-Rays availability
    idasrv_util    shared IDA access helpers
    idasrv_code    ping/info/bytes/disasm/decompile/function/xrefs/vtable/address
    idasrv_data    names/strings/segments/imports/exports/structs/enums
    idasrv_search  byte search
    idasrv_write   rename/comment/type/function edits
    idasrv_http    request handling and route dispatch

Start (in IDA):
    import ida_server
    ida_server.start_server()          # auto-picks port
    ida_server.start_server(port=5055) # or specify one

Stop:
    ida_server.stop_server()
"""

import atexit
import json
import os
import re
import sys
import tempfile
import threading
from datetime import datetime, timezone
from http.server import ThreadingHTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import idaapi
import ida_loader

import idasrv_config
from idasrv_config import REGISTRY_DIR, log, set_readonly
from idasrv_http import IDARequestHandler

_INSTANCE_FILE = None


def _sanitize_filename(name: str) -> str:
    """Make a string safe for use in a filename on Windows."""
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', name)
    sanitized = re.sub(r'_+', '_', sanitized)
    sanitized = sanitized.strip('. ')
    return sanitized[:200] if sanitized else 'unknown'


def get_instance_id():
    """Derive instance ID from the loaded binary's full path."""
    try:
        idb = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        base, ext = os.path.splitext(idb or "")
        if ext.lower() in (".i64", ".idb"):
            return base
        path = idaapi.get_input_file_path()
        if path:
            return path
    except Exception:
        pass
    return "unknown"


def _register_instance(port):
    """Write instance info to the registry directory for MCP client discovery."""
    global _INSTANCE_FILE
    os.makedirs(REGISTRY_DIR, exist_ok=True)

    instance_id = get_instance_id()
    pid = os.getpid()
    info = {
        "instance_id": instance_id,
        "port": port,
        "pid": pid,
        "host": "127.0.0.1",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "ida_version": idaapi.get_kernel_version(),
    }

    filename = f"{_sanitize_filename(instance_id)}_{pid}.json"
    target_path = os.path.join(REGISTRY_DIR, filename)

    # Atomic write: write to temp file then rename
    fd, tmp_path = tempfile.mkstemp(dir=REGISTRY_DIR, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(info, f, indent=2)
        os.replace(tmp_path, target_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    _INSTANCE_FILE = target_path
    log.info("Registered instance: %s (port %d) -> %s", instance_id, port, target_path)


def _unregister_instance():
    """Remove our instance file from the registry."""
    global _INSTANCE_FILE
    if _INSTANCE_FILE and os.path.exists(_INSTANCE_FILE):
        try:
            os.unlink(_INSTANCE_FILE)
            log.info("Unregistered instance: %s", _INSTANCE_FILE)
        except OSError as exc:
            log.warning("Failed to unregister instance: %s", exc)
        _INSTANCE_FILE = None


_SERVER = None
_THREAD = None


def start_server(host="127.0.0.1", port=0):
    """
    Start the HTTP API server in a background daemon thread.

    Args:
        host: Interface to bind to (default 127.0.0.1, local only).
        port: Port to listen on. 0 = auto-assign a free port (default).
    """
    global _SERVER, _THREAD

    if _SERVER is not None:
        log.warning("Server is already running, stopping old instance first")
        stop_server()

    _SERVER = ThreadingHTTPServer((host, port), IDARequestHandler)
    actual_port = _SERVER.server_address[1]
    _THREAD = threading.Thread(target=_SERVER.serve_forever, daemon=True)
    _THREAD.start()

    _register_instance(actual_port)

    log.info("IDA API server listening on %s:%d (readonly=%s)",
             host, actual_port, idasrv_config.READONLY)
    idaapi.msg(f"[ida_api] Server listening on {host}:{actual_port} "
               f"(readonly={idasrv_config.READONLY})\n")


def stop_server():
    """Shutdown the HTTP API server and unregister from discovery."""
    global _SERVER, _THREAD
    if _SERVER is not None:
        log.info("Shutting down IDA API server...")
        _unregister_instance()
        _SERVER.shutdown()
        _SERVER.server_close()
        _SERVER = None
        _THREAD = None
        idaapi.msg("[ida_api] Server stopped.\n")
    else:
        log.info("No server running")


atexit.register(_unregister_instance)


if __name__ == "__main__":
    start_server()
