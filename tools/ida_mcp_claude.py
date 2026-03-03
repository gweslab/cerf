"""
IDA HTTP API Server
-------------------
Exposes IDA Pro's analysis database over HTTP for use by remote clients
(MCP servers, automation scripts, AI agents, etc).

Targets IDA 9.0+ with IDAPython. Uses ida_typeinf for struct/enum
access (ida_struct and ida_enum were removed in IDA 9.0).

Start:
    from ida_api_server import start_server, stop_server
    start_server(host="0.0.0.0", port=6000)

Stop:
    stop_server()
"""

import json
import logging
import binascii
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

import idaapi
import idc
import ida_bytes
import ida_funcs
import ida_ida
import ida_kernwin
import ida_nalt
import ida_name
import ida_search
import ida_typeinf
import ida_xref
import idautils

import ida_hexrays

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

READONLY = True  # flip to False to enable write endpoints

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

log = logging.getLogger("ida_api_server")
log.setLevel(logging.INFO)
if not log.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("[ida_api] %(levelname)s %(message)s"))
    log.addHandler(_handler)

# ---------------------------------------------------------------------------
# Hex-Rays availability
# ---------------------------------------------------------------------------

HAS_HEXRAYS = False
if ida_hexrays.init_hexrays_plugin():
    HAS_HEXRAYS = True
    log.info("Hex-Rays decompiler available")
else:
    log.warning("Hex-Rays decompiler NOT available - /decompile will be limited")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_64bit():
    """Return True if the IDB is 64-bit."""
    return ida_ida.inf_is_64bit()


def _pointer_size():
    """Return pointer size in bytes for this IDB."""
    return 8 if _is_64bit() else 4


def _read_pointer(ea):
    """Read a pointer-sized value at *ea*."""
    if _is_64bit():
        return ida_bytes.get_qword(ea)
    return ida_bytes.get_dword(ea)


def hex_ea(ea):
    """Format an address as '0x...' hex string."""
    return f"0x{ea:X}"


def parse_hex(s):
    """Parse a hex string (with or without 0x prefix) into an int."""
    s = s.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    return int(s, 16)


def run_in_main(fn, mode=ida_kernwin.MFF_READ):
    """
    Run *fn* in IDA's main thread (required for most IDA API calls when
    invoked from a background HTTP thread).  Returns the result or
    re-raises exceptions from the main thread.
    """
    result = {"val": None, "err": None}

    def _thunk():
        try:
            result["val"] = fn()
        except Exception as exc:
            result["err"] = exc
        return 1

    ida_kernwin.execute_sync(_thunk, mode)
    if result["err"] is not None:
        raise result["err"]
    return result["val"]


# ---------------------------------------------------------------------------
# Read helpers  (all called inside main thread via run_in_main)
# ---------------------------------------------------------------------------


def _get_bytes_hex(ea, size):
    raw = ida_bytes.get_bytes(ea, size)
    if raw is None:
        return ""
    return binascii.hexlify(raw).decode()


def _disasm_at(ea, count):
    """Return *count* disassembly lines starting at *ea*."""
    head = idc.get_item_head(ea)
    if head != idaapi.BADADDR:
        ea = head

    seg = idaapi.getseg(ea)
    limit = seg.end_ea if seg else ida_ida.inf_get_max_ea()

    lines = []
    cur = ea
    for _ in range(count):
        if cur == idaapi.BADADDR or cur >= limit:
            break
        text = idc.GetDisasm(cur)
        if text:
            lines.append({"ea": hex_ea(cur), "text": text})
        cur = idc.next_head(cur, limit)
    return lines


def _decompile(ea):
    """Decompile the function containing *ea*.  Returns (pseudocode, func_name, start, end) or raises."""
    if not HAS_HEXRAYS:
        raise RuntimeError("Hex-Rays decompiler is not available")
    func = ida_funcs.get_func(ea)
    if func is None:
        raise ValueError(f"No function at {hex_ea(ea)}")
    cfunc = ida_hexrays.decompile(func)
    if cfunc is None:
        raise RuntimeError(f"Decompilation failed for function at {hex_ea(func.start_ea)}")
    return {
        "ea": hex_ea(ea),
        "function": {
            "name": ida_funcs.get_func_name(func.start_ea),
            "start_ea": hex_ea(func.start_ea),
            "end_ea": hex_ea(func.end_ea),
        },
        "pseudocode": str(cfunc),
    }


def _xrefs_from(ea):
    out = []
    for xr in idautils.XrefsFrom(ea, ida_xref.XREF_ALL):
        out.append({
            "from": hex_ea(xr.frm),
            "to": hex_ea(xr.to),
            "type": xr.type,
            "type_name": idautils.XrefTypeName(xr.type),
        })
    return out


def _xrefs_to(ea):
    out = []
    for xr in idautils.XrefsTo(ea, ida_xref.XREF_ALL):
        out.append({
            "from": hex_ea(xr.frm),
            "to": hex_ea(xr.to),
            "type": xr.type,
            "type_name": idautils.XrefTypeName(xr.type),
        })
    return out


def _callers_of(func):
    callers = set()
    for item_ea in idautils.FuncItems(func.start_ea):
        for xr in idautils.XrefsTo(item_ea, 0):
            caller_func = ida_funcs.get_func(xr.frm)
            if caller_func and caller_func.start_ea != func.start_ea:
                callers.add(caller_func.start_ea)
    return sorted(callers)


def _callees_of(func):
    callees = set()
    for item_ea in idautils.FuncItems(func.start_ea):
        for xr in idautils.XrefsFrom(item_ea, 0):
            callee_func = ida_funcs.get_func(xr.to)
            if callee_func and callee_func.start_ea != func.start_ea:
                callees.add(callee_func.start_ea)
    return sorted(callees)


def _get_type_str(ea):
    """Get the type string applied at *ea*, or None."""
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, ea):
        return str(tif)
    return None


def _get_name(ea):
    """Get the user/auto name at *ea*, or empty string."""
    n = ida_name.get_name(ea)
    return n if n else ""


# ---------------------------------------------------------------------------
# Endpoint implementations  (each returns a JSON-serialisable dict)
# All are called inside run_in_main so they have safe access to IDA APIs.
# ---------------------------------------------------------------------------


def ep_ping():
    return {"status": "ok", "ida_version": idaapi.get_kernel_version(), "hexrays": HAS_HEXRAYS}


def ep_info():
    ptr_size = _pointer_size()
    return {
        "file_path": idaapi.get_input_file_path(),
        "file_md5": ida_nalt.retrieve_input_file_md5().hex() if ida_nalt.retrieve_input_file_md5() else None,
        "imagebase": hex_ea(ida_nalt.get_imagebase()),
        "min_ea": hex_ea(ida_ida.inf_get_min_ea()),
        "max_ea": hex_ea(ida_ida.inf_get_max_ea()),
        "processor": ida_ida.inf_get_procname(),
        "bits": ptr_size * 8,
        "is_be": ida_ida.inf_is_be(),
        "is_dll": ida_ida.inf_is_dll(),
        "pointer_size": ptr_size,
        "hexrays": HAS_HEXRAYS,
        "readonly": READONLY,
    }


def ep_bytes(ea, size):
    return {
        "ea": hex_ea(ea),
        "size": size,
        "bytes_hex": _get_bytes_hex(ea, size),
    }


def ep_disasm(ea, count):
    lines = _disasm_at(ea, count)
    return {
        "start_ea": hex_ea(ea),
        "count": len(lines),
        "disasm": lines,
    }


def ep_decompile(ea):
    return _decompile(ea)


def ep_function(ea):
    """Rich context for the function (or raw area) containing *ea*."""
    head = idc.get_item_head(ea)
    if head != idaapi.BADADDR:
        ea = head

    func = ida_funcs.get_func(ea)
    in_function = func is not None

    if func:
        start, end = func.start_ea, func.end_ea
        fname = ida_funcs.get_func_name(func.start_ea)
    else:
        start = ea
        end = ea + 0x100
        fname = None

    disasm = _disasm_at(start, 2000 if in_function else 128)

    pseudo = None
    if in_function and HAS_HEXRAYS:
        try:
            cfunc = ida_hexrays.decompile(func)
            if cfunc:
                pseudo = str(cfunc)
        except Exception:
            pass

    callers = [hex_ea(c) for c in _callers_of(func)] if func else []
    callees = [hex_ea(c) for c in _callees_of(func)] if func else []

    func_cmt = idc.get_func_cmt(start, False) if func else None
    func_cmt_rep = idc.get_func_cmt(start, True) if func else None

    instr_comments = []
    for item_ea in idautils.Heads(start, end):
        cmt = idc.get_cmt(item_ea, False)
        cmt_rep = idc.get_cmt(item_ea, True)
        if cmt or cmt_rep:
            instr_comments.append({
                "ea": hex_ea(item_ea),
                "comment": cmt or "",
                "repeatable_comment": cmt_rep or "",
            })

    return {
        "ea": hex_ea(ea),
        "in_function": in_function,
        "function": {
            "name": fname,
            "start_ea": hex_ea(start),
            "end_ea": hex_ea(end),
        } if in_function else None,
        "bytes_at_ea": _get_bytes_hex(ea, 64),
        "disasm": disasm,
        "pseudocode": pseudo,
        "xrefs_from": _xrefs_from(ea),
        "xrefs_to": _xrefs_to(ea),
        "callers": callers,
        "callees": callees,
        "function_comment": func_cmt,
        "function_repeatable_comment": func_cmt_rep,
        "instr_comments": instr_comments,
    }


def ep_functions(limit, name_filter, mode):
    funcs = []
    for fea in idautils.Functions():
        fn = ida_funcs.get_func(fea)
        if fn is None:
            continue
        name = ida_funcs.get_func_name(fn.start_ea)
        if name_filter and name_filter.lower() not in name.lower():
            continue
        entry = {
            "start_ea": hex_ea(fn.start_ea),
            "end_ea": hex_ea(fn.end_ea),
            "name": name,
            "size": fn.end_ea - fn.start_ea,
        }
        if mode == "full":
            entry["xrefs_to_count"] = len(list(idautils.XrefsTo(fn.start_ea, 0)))
            type_str = _get_type_str(fn.start_ea)
            if type_str:
                entry["type"] = type_str
        funcs.append(entry)
        if limit and len(funcs) >= limit:
            break
    return {"count": len(funcs), "functions": funcs}


def ep_xrefs(ea, direction):
    result = {"ea": hex_ea(ea)}
    if direction in ("from", "both"):
        result["xrefs_from"] = _xrefs_from(ea)
    if direction in ("to", "both"):
        result["xrefs_to"] = _xrefs_to(ea)
    return result


def ep_names(limit, name_filter):
    names = []
    for ea, name in idautils.Names():
        if name_filter and name_filter.lower() not in name.lower():
            continue
        names.append({"ea": hex_ea(ea), "name": name})
        if limit and len(names) >= limit:
            break
    return {"count": len(names), "names": names}


def ep_strings(limit, min_length):
    strings = idautils.Strings()
    strings.setup(
        strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16],
        minlen=min_length,
        only_7bit=False,
        display_only_existing_strings=True,
    )
    out = []
    for s in strings:
        raw = ida_bytes.get_strlit_contents(s.ea, s.length, s.strtype)
        text = raw.decode("utf-8", errors="replace") if raw else ""
        out.append({
            "ea": hex_ea(s.ea),
            "length": s.length,
            "type": s.strtype,
            "value": text,
        })
        if limit and len(out) >= limit:
            break
    return {"count": len(out), "strings": out}


def ep_segments():
    segs = []
    for seg_ea in idautils.Segments():
        seg = idaapi.getseg(seg_ea)
        if seg is None:
            continue
        segs.append({
            "start_ea": hex_ea(seg.start_ea),
            "end_ea": hex_ea(seg.end_ea),
            "name": idc.get_segm_name(seg.start_ea),
            "class": idaapi.get_segm_class(seg) or "",
            "size": seg.end_ea - seg.start_ea,
            "perm": seg.perm,
            "bitness": seg.bitness,  # 0=16, 1=32, 2=64
        })
    return {"count": len(segs), "segments": segs}


def ep_imports():
    modules = {}
    nimps = idaapi.get_import_module_qty()
    for i in range(nimps):
        mod_name = idaapi.get_import_module_name(i)
        if not mod_name:
            continue
        entries = []

        def _cb(ea, name, ordinal):
            entries.append({
                "ea": hex_ea(ea),
                "name": name or "",
                "ordinal": ordinal,
            })
            return True  # continue enumeration

        idaapi.enum_import_names(i, _cb)
        modules[mod_name] = entries
    return {"count": nimps, "modules": modules}


def ep_exports():
    exports = []
    for idx, ordinal, ea, name in idautils.Entries():
        exports.append({
            "index": idx,
            "ordinal": ordinal,
            "ea": hex_ea(ea),
            "name": name or "",
        })
    return {"count": len(exports), "exports": exports}


def ep_structs(name_filter):
    """List structure/union definitions in the IDB (IDA 9.0+, uses ida_typeinf)."""
    results = []
    for ordinal, sid, sname in idautils.Structs():
        if name_filter and name_filter.lower() not in sname.lower():
            continue
        tif = ida_typeinf.tinfo_t()
        tif.get_type_by_tid(sid)
        results.append({
            "ordinal": ordinal,
            "id": sid,
            "name": sname,
            "size": tif.get_size() if tif.present() else 0,
            "is_union": tif.is_union(),
        })
    return {"count": len(results), "structs": results}


def ep_struct(name):
    """Get full details of a struct by name (IDA 9.0+, uses ida_typeinf)."""
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, name, ida_typeinf.BTF_STRUCT, True, False):
        # Also try BTF_UNION in case it's a union
        if not tif.get_named_type(til, name, ida_typeinf.BTF_UNION, True, False):
            raise ValueError(f"Struct/union '{name}' not found")

    udt = ida_typeinf.udt_type_data_t()
    if not tif.get_udt_details(udt):
        raise ValueError(f"Could not read UDT details for '{name}'")

    members = []
    for udm in udt:
        if udm.is_gap():
            continue
        type_str = str(udm.type) if udm.type.present() else None
        cmt = udm.cmt or ""
        members.append({
            "offset": udm.offset // 8,
            "name": udm.name or "",
            "size": udm.size // 8,
            "type": type_str,
            "comment": cmt,
        })
    return {
        "name": name,
        "id": tif.get_tid(),
        "size": tif.get_size(),
        "is_union": tif.is_union(),
        "members": members,
    }


def ep_enums(name_filter):
    """List enum definitions (IDA 9.0+, uses ida_typeinf)."""
    results = []
    limit = ida_typeinf.get_ordinal_limit()
    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        tif.get_numbered_type(None, ordinal)
        if not tif.is_enum():
            continue
        ename = tif.get_type_name()
        if not ename:
            continue
        if name_filter and name_filter.lower() not in ename.lower():
            continue
        edt = ida_typeinf.enum_type_data_t()
        member_count = 0
        is_bf = False
        if tif.get_enum_details(edt):
            member_count = edt.size()
            is_bf = edt.is_bf()
        results.append({
            "id": tif.get_tid(),
            "name": ename,
            "is_bitfield": is_bf,
            "member_count": member_count,
        })
    return {"count": len(results), "enums": results}


def ep_enum(name):
    """Get full details of an enum by name (IDA 9.0+, uses ida_typeinf)."""
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, name, ida_typeinf.BTF_ENUM, True, False):
        raise ValueError(f"Enum '{name}' not found")

    edt = ida_typeinf.enum_type_data_t()
    if not tif.get_enum_details(edt):
        raise ValueError(f"Could not read enum details for '{name}'")

    members = []
    for edm in edt:
        val = edm.value
        members.append({
            "name": edm.name or f"unk_{val:X}",
            "value": val,
            "value_hex": hex_ea(val),
        })
    return {
        "name": name,
        "id": tif.get_tid(),
        "is_bitfield": edt.is_bf(),
        "members": members,
    }


def ep_vtable(ea, count):
    """
    Read a vtable as an array of pointers at *ea*.
    Resolves each pointer to a function name if possible.
    Stops early if a pointer target is obviously invalid (0, or outside
    any segment).
    """
    ptr_size = _pointer_size()
    min_ea = ida_ida.inf_get_min_ea()
    max_ea = ida_ida.inf_get_max_ea()
    entries = []
    for i in range(count):
        slot_ea = ea + i * ptr_size
        target = _read_pointer(slot_ea)
        if target == 0 or target < min_ea or target > max_ea:
            break
        fname = _get_name(target)
        func = ida_funcs.get_func(target)
        entries.append({
            "index": i,
            "slot_ea": hex_ea(slot_ea),
            "target": hex_ea(target),
            "name": fname,
            "is_function": func is not None,
        })
    return {
        "ea": hex_ea(ea),
        "pointer_size": ptr_size,
        "count": len(entries),
        "entries": entries,
    }


def ep_address(ea):
    """Detailed information about a single address."""
    seg = idaapi.getseg(ea)
    func = ida_funcs.get_func(ea)
    flags = ida_bytes.get_flags(ea)
    return {
        "ea": hex_ea(ea),
        "name": _get_name(ea),
        "type": _get_type_str(ea),
        "segment": idc.get_segm_name(ea) if seg else None,
        "is_code": ida_bytes.is_code(flags),
        "is_data": ida_bytes.is_data(flags),
        "is_head": ida_bytes.is_head(flags),
        "is_tail": ida_bytes.is_tail(flags),
        "in_function": func is not None,
        "function_name": ida_funcs.get_func_name(func.start_ea) if func else None,
        "function_start": hex_ea(func.start_ea) if func else None,
        "comment": idc.get_cmt(ea, False) or "",
        "repeatable_comment": idc.get_cmt(ea, True) or "",
        "item_size": idc.get_item_size(ea),
        "bytes_hex": _get_bytes_hex(ea, idc.get_item_size(ea)),
    }


def ep_search(pattern, start_ea, direction, max_results):
    """
    Search for a byte pattern.
    *pattern* is a hex string with optional wildcards, e.g. "48 8B ?? 10".
    """
    flag = ida_search.SEARCH_DOWN if direction == "down" else ida_search.SEARCH_UP
    flag |= ida_search.SEARCH_CASE

    if start_ea is None:
        start_ea = ida_ida.inf_get_min_ea() if direction == "down" else ida_ida.inf_get_max_ea()

    results = []
    cur = start_ea
    for _ in range(max_results):
        found = idaapi.find_binary(cur, idaapi.BADADDR if direction == "down" else 0, pattern, 16, flag)
        if found == idaapi.BADADDR:
            break
        results.append({
            "ea": hex_ea(found),
            "name": _get_name(found),
        })
        cur = found + 1 if direction == "down" else found - 1
    return {
        "pattern": pattern,
        "count": len(results),
        "results": results,
    }


# ---------------------------------------------------------------------------
# Write endpoints  (gated behind READONLY)
# ---------------------------------------------------------------------------


def _require_write():
    if READONLY:
        raise PermissionError("Server is in read-only mode. Set READONLY = False to enable write operations.")


def ep_rename(ea, new_name):
    _require_write()
    ok = ida_name.set_name(ea, new_name, ida_name.SN_CHECK)
    if not ok:
        raise RuntimeError(f"Failed to rename {hex_ea(ea)} to '{new_name}'")
    return {"ea": hex_ea(ea), "name": new_name, "success": True}


def ep_set_comment(ea, comment, repeatable):
    _require_write()
    ok = idc.set_cmt(ea, comment, repeatable)
    if not ok:
        raise RuntimeError(f"Failed to set comment at {hex_ea(ea)}")
    return {"ea": hex_ea(ea), "comment": comment, "repeatable": repeatable, "success": True}


def ep_set_func_comment(ea, comment, repeatable):
    _require_write()
    func = ida_funcs.get_func(ea)
    if func is None:
        raise ValueError(f"No function at {hex_ea(ea)}")
    ok = idc.set_func_cmt(func.start_ea, comment, repeatable)
    if not ok:
        raise RuntimeError(f"Failed to set function comment at {hex_ea(ea)}")
    return {"ea": hex_ea(func.start_ea), "comment": comment, "repeatable": repeatable, "success": True}


def ep_set_type(ea, type_str):
    """Apply a C type declaration at *ea* (e.g. 'int __fastcall func(int a, int b)')."""
    _require_write()
    # idc.SetType handles parsing and application in one step, and works
    # consistently across IDA versions.
    decl = type_str.rstrip(";") + ";"
    ok = idc.SetType(ea, decl)
    if not ok:
        raise RuntimeError(f"Failed to apply type '{type_str}' at {hex_ea(ea)}")
    applied = _get_type_str(ea)
    return {"ea": hex_ea(ea), "type": applied or type_str, "success": True}


def ep_create_function(start_ea, end_ea):
    _require_write()
    if end_ea:
        ok = ida_funcs.add_func(start_ea, end_ea)
    else:
        ok = ida_funcs.add_func(start_ea)
    if not ok:
        raise RuntimeError(f"Failed to create function at {hex_ea(start_ea)}")
    func = ida_funcs.get_func(start_ea)
    return {
        "start_ea": hex_ea(func.start_ea) if func else hex_ea(start_ea),
        "end_ea": hex_ea(func.end_ea) if func else None,
        "success": True,
    }


def ep_delete_function(ea):
    _require_write()
    func = ida_funcs.get_func(ea)
    if func is None:
        raise ValueError(f"No function at {hex_ea(ea)}")
    ok = ida_funcs.del_func(func.start_ea)
    if not ok:
        raise RuntimeError(f"Failed to delete function at {hex_ea(func.start_ea)}")
    return {"ea": hex_ea(func.start_ea), "success": True}


# ---------------------------------------------------------------------------
# Request routing
# ---------------------------------------------------------------------------


def _qs_str(qs, key, default=None):
    """Get a single string value from parsed query string."""
    vals = qs.get(key)
    if not vals:
        return default
    return vals[0]


def _qs_int(qs, key, default=None):
    val = _qs_str(qs, key)
    if val is None:
        return default
    return int(val)


def _qs_ea(qs, key="ea"):
    val = _qs_str(qs, key)
    if val is None:
        raise ValueError(f"Missing required parameter: {key}")
    return parse_hex(val)


def _qs_bool(qs, key, default=False):
    val = _qs_str(qs, key)
    if val is None:
        return default
    return val.lower() in ("1", "true", "yes")


class IDARequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler that dispatches to endpoint functions."""

    # Silence per-request logging from BaseHTTPRequestHandler
    def log_message(self, fmt, *args):
        log.debug(fmt, *args)

    def _send_json(self, data, status=200):
        body = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error(self, status, message):
        self._send_json({"error": message}, status=status)

    def _read_body_json(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw)

    # -- GET routes --------------------------------------------------------

    def _dispatch_get(self, path, qs):
        if path == "/api/ping":
            return run_in_main(ep_ping)

        if path == "/api/info":
            return run_in_main(ep_info)

        if path == "/api/bytes":
            ea = _qs_ea(qs)
            size = _qs_int(qs, "size", 256)
            return run_in_main(lambda: ep_bytes(ea, size))

        if path == "/api/disasm":
            ea = _qs_ea(qs)
            count = _qs_int(qs, "count", 50)
            return run_in_main(lambda: ep_disasm(ea, count))

        if path == "/api/decompile":
            ea = _qs_ea(qs)
            return run_in_main(lambda: ep_decompile(ea))

        if path == "/api/function":
            ea = _qs_ea(qs)
            return run_in_main(lambda: ep_function(ea))

        if path == "/api/functions":
            limit = _qs_int(qs, "limit", 0)
            name_filter = _qs_str(qs, "filter")
            mode = _qs_str(qs, "mode", "fast")
            return run_in_main(lambda: ep_functions(limit, name_filter, mode))

        if path == "/api/xrefs":
            ea = _qs_ea(qs)
            direction = _qs_str(qs, "direction", "both")
            return run_in_main(lambda: ep_xrefs(ea, direction))

        if path == "/api/names":
            limit = _qs_int(qs, "limit", 0)
            name_filter = _qs_str(qs, "filter")
            return run_in_main(lambda: ep_names(limit, name_filter))

        if path == "/api/strings":
            limit = _qs_int(qs, "limit", 0)
            min_length = _qs_int(qs, "min_length", 4)
            return run_in_main(lambda: ep_strings(limit, min_length))

        if path == "/api/segments":
            return run_in_main(ep_segments)

        if path == "/api/imports":
            return run_in_main(ep_imports)

        if path == "/api/exports":
            return run_in_main(ep_exports)

        if path == "/api/structs":
            name_filter = _qs_str(qs, "filter")
            return run_in_main(lambda: ep_structs(name_filter))

        if path == "/api/struct":
            name = _qs_str(qs, "name")
            if not name:
                raise ValueError("Missing required parameter: name")
            return run_in_main(lambda: ep_struct(name))

        if path == "/api/enums":
            name_filter = _qs_str(qs, "filter")
            return run_in_main(lambda: ep_enums(name_filter))

        if path == "/api/enum":
            name = _qs_str(qs, "name")
            if not name:
                raise ValueError("Missing required parameter: name")
            return run_in_main(lambda: ep_enum(name))

        if path == "/api/vtable":
            ea = _qs_ea(qs)
            count = _qs_int(qs, "count", 64)
            return run_in_main(lambda: ep_vtable(ea, count))

        if path == "/api/address":
            ea = _qs_ea(qs)
            return run_in_main(lambda: ep_address(ea))

        if path == "/api/search":
            pattern = _qs_str(qs, "pattern")
            if not pattern:
                raise ValueError("Missing required parameter: pattern")
            start = _qs_str(qs, "start")
            start_ea = parse_hex(start) if start else None
            direction = _qs_str(qs, "direction", "down")
            max_results = _qs_int(qs, "max_results", 100)
            return run_in_main(lambda: ep_search(pattern, start_ea, direction, max_results))

        return None  # 404

    # -- POST routes -------------------------------------------------------

    def _dispatch_post(self, path, body):
        if path == "/api/rename":
            ea = parse_hex(body["ea"])
            new_name = body["name"]
            return run_in_main(lambda: ep_rename(ea, new_name), ida_kernwin.MFF_WRITE)

        if path == "/api/comment":
            ea = parse_hex(body["ea"])
            comment = body["comment"]
            repeatable = body.get("repeatable", False)
            return run_in_main(lambda: ep_set_comment(ea, comment, repeatable), ida_kernwin.MFF_WRITE)

        if path == "/api/func_comment":
            ea = parse_hex(body["ea"])
            comment = body["comment"]
            repeatable = body.get("repeatable", False)
            return run_in_main(lambda: ep_set_func_comment(ea, comment, repeatable), ida_kernwin.MFF_WRITE)

        if path == "/api/set_type":
            ea = parse_hex(body["ea"])
            type_str = body["type"]
            return run_in_main(lambda: ep_set_type(ea, type_str), ida_kernwin.MFF_WRITE)

        if path == "/api/create_function":
            start = parse_hex(body["start_ea"])
            end = parse_hex(body["end_ea"]) if "end_ea" in body else None
            return run_in_main(lambda: ep_create_function(start, end), ida_kernwin.MFF_WRITE)

        if path == "/api/delete_function":
            ea = parse_hex(body["ea"])
            return run_in_main(lambda: ep_delete_function(ea), ida_kernwin.MFF_WRITE)

        return None  # 404

    # -- HTTP method handlers ----------------------------------------------

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            result = self._dispatch_get(parsed.path, qs)
            if result is None:
                self._send_error(404, f"Unknown endpoint: {parsed.path}")
            else:
                self._send_json(result)
        except ValueError as exc:
            self._send_error(400, str(exc))
        except PermissionError as exc:
            self._send_error(403, str(exc))
        except Exception as exc:
            log.exception("Error handling GET %s", self.path)
            self._send_error(500, str(exc))

    def do_POST(self):
        try:
            parsed = urlparse(self.path)
            body = self._read_body_json()
            result = self._dispatch_post(parsed.path, body)
            if result is None:
                self._send_error(404, f"Unknown endpoint: {parsed.path}")
            else:
                self._send_json(result)
        except ValueError as exc:
            self._send_error(400, str(exc))
        except PermissionError as exc:
            self._send_error(403, str(exc))
        except KeyError as exc:
            self._send_error(400, f"Missing required field: {exc}")
        except Exception as exc:
            log.exception("Error handling POST %s", self.path)
            self._send_error(500, str(exc))


# ---------------------------------------------------------------------------
# Server lifecycle
# ---------------------------------------------------------------------------

_SERVER = None
_THREAD = None


def start_server(host="0.0.0.0", port=6000):
    """Start the HTTP API server in a background daemon thread."""
    global _SERVER, _THREAD

    if _SERVER is not None:
        log.warning("Server is already running, stopping old instance first")
        stop_server()

    _SERVER = ThreadingHTTPServer((host, port), IDARequestHandler)
    _THREAD = threading.Thread(target=_SERVER.serve_forever, daemon=True)
    _THREAD.start()
    log.info("IDA API server listening on %s:%d (readonly=%s)", host, port, READONLY)
    idaapi.msg(f"[ida_api] Server listening on {host}:{port} (readonly={READONLY})\n")


def stop_server():
    """Shutdown the HTTP API server."""
    global _SERVER, _THREAD
    if _SERVER is not None:
        log.info("Shutting down IDA API server...")
        _SERVER.shutdown()
        _SERVER.server_close()
        _SERVER = None
        _THREAD = None
        idaapi.msg("[ida_api] Server stopped.\n")
    else:
        log.info("No server running")


def set_readonly(enabled):
    """Toggle read-only mode at runtime."""
    global READONLY
    READONLY = enabled
    log.info("Read-only mode: %s", READONLY)
    idaapi.msg(f"[ida_api] Read-only mode: {READONLY}\n")


# ---------------------------------------------------------------------------
# Auto-start when loaded as a script
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    start_server(host="0.0.0.0", port=6000)