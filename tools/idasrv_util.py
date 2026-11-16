"""Shared IDA access helpers for the HTTP API endpoints.

Everything here assumes it runs inside IDA's main thread; HTTP handlers reach
it through run_in_main().
"""

import binascii
import re

import idaapi
import idc
import ida_bytes
import ida_funcs
import ida_ida
import ida_kernwin
import ida_nalt
import ida_name
import ida_typeinf
import ida_xref
import idautils


def is_64bit():
    """Return True if the IDB is 64-bit."""
    return ida_ida.inf_is_64bit()


def pointer_size():
    """Return pointer size in bytes for this IDB."""
    return 8 if is_64bit() else 4


def read_pointer(ea):
    """Read a pointer-sized value at *ea*."""
    if is_64bit():
        return ida_bytes.get_qword(ea)
    return ida_bytes.get_dword(ea)


def hex_ea(ea):
    """Format an address as '0x...' hex string."""
    return f"0x{ea:X}"


_HEX_RE = re.compile(r'(?:0[xX])?([0-9A-Fa-f]+)')


def parse_hex(s):
    """Parse a hex string (with or without 0x prefix) into an int."""
    parts = _HEX_RE.fullmatch(s.strip())
    if not parts:
        raise ValueError(f"Not a hex number: {s!r}")
    return int(parts.group(1), 16)


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


def paginate(items, offset, limit):
    """Slice *items* to a page, returning (page, total_matched).

    offset skips entries after filtering; limit 0 means no cap.
    """
    total = len(items)
    if offset:
        items = items[offset:]
    if limit:
        items = items[:limit]
    return items, total


def get_bytes_hex(ea, size):
    raw = ida_bytes.get_bytes(ea, size)
    if raw is None:
        return ""
    return binascii.hexlify(raw).decode()


def get_name(ea):
    """Get the user/auto name at *ea*, or empty string."""
    n = ida_name.get_name(ea)
    return n if n else ""


def get_type_str(ea):
    """Get the type string applied at *ea*, or None."""
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, ea):
        return str(tif)
    return None


def disasm_at(ea, count, end_ea=None):
    """Return up to *count* disassembly lines starting at *ea*.

    Listing stops at *end_ea* when given, otherwise at the end of the
    containing segment.
    """
    head = idc.get_item_head(ea)
    if head != idaapi.BADADDR:
        ea = head

    seg = idaapi.getseg(ea)
    limit = seg.end_ea if seg else ida_ida.inf_get_max_ea()
    if end_ea is not None:
        limit = min(limit, end_ea)

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


def _xref_record(xr):
    record = {
        "from": hex_ea(xr.frm),
        "to": hex_ea(xr.to),
        "type": xr.type,
        "type_name": idautils.XrefTypeName(xr.type),
    }

    owner = ida_funcs.get_func(xr.frm)
    if owner:
        record["from_func_ea"] = hex_ea(owner.start_ea)
        record["from_func_name"] = ida_funcs.get_func_name(owner.start_ea)

    target_name = get_name(xr.to)
    if target_name:
        record["to_name"] = target_name

    if ida_bytes.is_code(ida_bytes.get_flags(xr.frm)):
        text = idc.GetDisasm(xr.frm)
        if text:
            record["disasm"] = text

    return record


def xrefs_from(ea):
    return [_xref_record(xr) for xr in idautils.XrefsFrom(ea, ida_xref.XREF_ALL)]


def xrefs_to(ea):
    return [_xref_record(xr) for xr in idautils.XrefsTo(ea, ida_xref.XREF_ALL)]


def _func_records(start_eas):
    return [
        {"ea": hex_ea(ea), "name": ida_funcs.get_func_name(ea)}
        for ea in sorted(start_eas)
    ]


def callers_of(func):
    callers = set()
    for item_ea in idautils.FuncItems(func.start_ea):
        for xr in idautils.XrefsTo(item_ea, 0):
            caller_func = ida_funcs.get_func(xr.frm)
            if caller_func and caller_func.start_ea != func.start_ea:
                callers.add(caller_func.start_ea)
    return _func_records(callers)


def callees_of(func):
    callees = set()
    for item_ea in idautils.FuncItems(func.start_ea):
        for xr in idautils.XrefsFrom(item_ea, 0):
            callee_func = ida_funcs.get_func(xr.to)
            if callee_func and callee_func.start_ea != func.start_ea:
                callees.add(callee_func.start_ea)
    return _func_records(callees)
