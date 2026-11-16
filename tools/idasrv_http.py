"""HTTP request handling and route dispatch for the IDA API server."""

import json
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

import ida_kernwin

from idasrv_config import log
from idasrv_util import parse_hex, run_in_main

import idasrv_code as code
import idasrv_data as data
import idasrv_search as search
import idasrv_write as write


class _Query:
    def __init__(self, values):
        self._values = values
        self._read = set()

    def get(self, key):
        self._read.add(key)
        return self._values.get(key)

    def unread(self):
        return sorted(set(self._values) - self._read)


def _qs_str(qs, key, default=None):
    """Get a single string value from parsed query string."""
    vals = qs.get(key)
    if not vals:
        return default
    return vals[0]


def _qs_int(qs, key, default, minimum):
    val = _qs_str(qs, key)
    if val is None:
        return default
    value = int(val)
    if value < minimum:
        raise ValueError(f"Parameter {key} must be at least {minimum}. Got: {value}")
    return value


def _qs_choice(qs, key, default, choices):
    val = _qs_str(qs, key, default)
    if val not in choices:
        raise ValueError(f"Parameter {key} must be one of {', '.join(choices)}. Got: {val!r}")
    return val


def _qs_ea(qs, key="ea"):
    val = _qs_str(qs, key)
    if val is None:
        raise ValueError(f"Missing required parameter: {key}")
    return parse_hex(val)


def _qs_optional_ea(qs, key):
    val = _qs_str(qs, key)
    return parse_hex(val) if val else None


def _qs_max_results(qs):
    return _qs_int(qs, "max_results", 100, 1)


def _qs_bool(qs, key, default=False):
    val = _qs_str(qs, key)
    if val is None:
        return default
    if val.lower() in ("1", "true", "yes"):
        return True
    if val.lower() in ("0", "false", "no"):
        return False
    raise ValueError(f"Parameter {key} must be 1 or 0. Got: {val!r}")


def _required(qs, key):
    val = _qs_str(qs, key)
    if not val:
        raise ValueError(f"Missing required parameter: {key}")
    return val


def dispatch_get(path, qs):
    """Route a GET request. Returns a JSON-serialisable dict, or None for 404."""
    if path == "/api/ping":
        return run_in_main(code.ep_ping)

    if path == "/api/info":
        return run_in_main(code.ep_info)

    if path == "/api/bytes":
        ea = _qs_ea(qs)
        size = _qs_int(qs, "size", 256, 1)
        return run_in_main(lambda: code.ep_bytes(ea, size))

    if path == "/api/values":
        ea = _qs_ea(qs)
        value_type = _qs_str(qs, "type", "dword")
        count = _qs_int(qs, "count", 1, 1)
        return run_in_main(lambda: code.ep_read_values(ea, value_type, count))

    if path == "/api/disasm":
        ea = _qs_ea(qs)
        count = _qs_int(qs, "count", 50, 1)
        return run_in_main(lambda: code.ep_disasm(ea, count))

    if path == "/api/decompile":
        ea = _qs_ea(qs)
        return run_in_main(lambda: code.ep_decompile(ea))

    if path == "/api/function":
        ea = _qs_ea(qs)
        raw_sections = _qs_str(qs, "sections")
        sections = [s.strip() for s in raw_sections.split(",") if s.strip()] if raw_sections else None
        max_disasm = _qs_int(qs, "max_disasm", code.DEFAULT_MAX_DISASM, 0)
        return run_in_main(lambda: code.ep_function(ea, sections, max_disasm))

    if path == "/api/functions":
        limit = _qs_int(qs, "limit", 0, 0)
        offset = _qs_int(qs, "offset", 0, 0)
        name_filter = _qs_str(qs, "filter")
        mode = _qs_choice(qs, "mode", "fast", ("fast", "full"))
        return run_in_main(lambda: code.ep_functions(limit, offset, name_filter, mode))

    if path == "/api/xrefs":
        ea = _qs_ea(qs)
        direction = _qs_choice(qs, "direction", "both", ("from", "to", "both"))
        return run_in_main(lambda: code.ep_xrefs(ea, direction))

    if path == "/api/names":
        limit = _qs_int(qs, "limit", 0, 0)
        offset = _qs_int(qs, "offset", 0, 0)
        name_filter = _qs_str(qs, "filter")
        return run_in_main(lambda: data.ep_names(limit, offset, name_filter))

    if path == "/api/strings":
        limit = _qs_int(qs, "limit", 0, 0)
        offset = _qs_int(qs, "offset", 0, 0)
        min_length = _qs_int(qs, "min_length", 4, 0)
        content_filter = _qs_str(qs, "filter")
        return run_in_main(lambda: data.ep_strings(limit, offset, min_length, content_filter))

    if path == "/api/segments":
        return run_in_main(data.ep_segments)

    if path == "/api/imports":
        return run_in_main(data.ep_imports)

    if path == "/api/exports":
        return run_in_main(data.ep_exports)

    if path == "/api/structs":
        name_filter = _qs_str(qs, "filter")
        return run_in_main(lambda: data.ep_structs(name_filter))

    if path == "/api/struct":
        name = _required(qs, "name")
        return run_in_main(lambda: data.ep_struct(name))

    if path == "/api/enums":
        name_filter = _qs_str(qs, "filter")
        return run_in_main(lambda: data.ep_enums(name_filter))

    if path == "/api/enum":
        name = _required(qs, "name")
        return run_in_main(lambda: data.ep_enum(name))

    if path == "/api/vtable":
        ea = _qs_ea(qs)
        count = _qs_int(qs, "count", 64, 1)
        return run_in_main(lambda: code.ep_vtable(ea, count))

    if path == "/api/address":
        ea = _qs_ea(qs)
        return run_in_main(lambda: code.ep_address(ea))

    if path == "/api/search":
        pattern = _required(qs, "pattern")
        start_ea = _qs_optional_ea(qs, "start")
        direction = _qs_choice(qs, "direction", "down", ("down", "up"))
        max_results = _qs_max_results(qs)
        return run_in_main(lambda: search.ep_search(pattern, start_ea, direction, max_results))

    if path == "/api/search_text":
        text = _required(qs, "text")
        encoding = _qs_str(qs, "encoding", "both")
        start_ea = _qs_optional_ea(qs, "start")
        direction = _qs_choice(qs, "direction", "down", ("down", "up"))
        max_results = _qs_max_results(qs)
        return run_in_main(lambda: search.ep_search_text(
            text, encoding, start_ea, direction, max_results))

    if path == "/api/search_immediate":
        raw_value = _required(qs, "value")
        value = parse_hex(raw_value)
        include_halves = _qs_bool(qs, "include_halves", False)
        start_ea = _qs_optional_ea(qs, "start")
        end_ea = _qs_optional_ea(qs, "end")
        max_results = _qs_max_results(qs)
        return run_in_main(lambda: search.ep_search_immediate(
            value, include_halves, start_ea, end_ea, max_results))

    if path == "/api/search_insn":
        patterns = _required(qs, "patterns")
        word_size = int(_required(qs, "word_size"))
        include_noncode = _qs_bool(qs, "include_noncode", False)
        start_ea = _qs_optional_ea(qs, "start")
        end_ea = _qs_optional_ea(qs, "end")
        max_results = _qs_max_results(qs)
        return run_in_main(lambda: search.ep_search_insn(
            patterns, word_size, include_noncode, start_ea, end_ea, max_results))

    return None


def dispatch_post(path, body):
    """Route a POST request. Returns a JSON-serialisable dict, or None for 404."""
    if path == "/api/rename":
        ea = parse_hex(body["ea"])
        new_name = body["name"]
        return run_in_main(lambda: write.ep_rename(ea, new_name), ida_kernwin.MFF_WRITE)

    if path == "/api/comment":
        ea = parse_hex(body["ea"])
        comment = body["comment"]
        repeatable = body.get("repeatable", False)
        return run_in_main(lambda: write.ep_set_comment(ea, comment, repeatable), ida_kernwin.MFF_WRITE)

    if path == "/api/func_comment":
        ea = parse_hex(body["ea"])
        comment = body["comment"]
        repeatable = body.get("repeatable", False)
        return run_in_main(lambda: write.ep_set_func_comment(ea, comment, repeatable), ida_kernwin.MFF_WRITE)

    if path == "/api/set_type":
        ea = parse_hex(body["ea"])
        type_str = body["type"]
        return run_in_main(lambda: write.ep_set_type(ea, type_str), ida_kernwin.MFF_WRITE)

    if path == "/api/create_function":
        start = parse_hex(body["start_ea"])
        end = parse_hex(body["end_ea"]) if "end_ea" in body else None
        return run_in_main(lambda: write.ep_create_function(start, end), ida_kernwin.MFF_WRITE)

    if path == "/api/delete_function":
        ea = parse_hex(body["ea"])
        return run_in_main(lambda: write.ep_delete_function(ea), ida_kernwin.MFF_WRITE)

    return None


class IDARequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler that dispatches to endpoint functions."""

    def log_message(self, fmt, *args):
        log.debug(fmt, *args)

    def _send_json(self, data_obj, status=200):
        body = json.dumps(data_obj, indent=2, ensure_ascii=False).encode("utf-8")
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

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            qs = _Query(parse_qs(parsed.query))
            result = dispatch_get(parsed.path, qs)
            if result is None:
                self._send_error(404, f"Unknown endpoint: {parsed.path}")
            elif qs.unread():
                self._send_error(
                    400, f"Unknown parameter for {parsed.path}: {', '.join(qs.unread())}")
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
            result = dispatch_post(parsed.path, body)
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
