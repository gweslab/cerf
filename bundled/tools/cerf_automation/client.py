from __future__ import annotations

import collections
import json
import re
import subprocess
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Deque, Dict, Iterable, List, Optional, Sequence, Tuple

from . import discovery
from .frame import Frame
from .transport import Transport, endpoint_address, endpoint_name, open_transport

PROTOCOL = 1
SHIFT = "VK_SHIFT"


class CerfError(Exception):
    def __init__(self, code: int, message: str) -> None:
        super().__init__("{} ({})".format(message, code))
        self.code = code
        self.message = message


class _Namespace:
    def __init__(self, cerf: "Cerf", prefix: str) -> None:
        self._cerf = cerf
        self._prefix = prefix

    def __getattr__(self, name: str) -> Callable[..., Any]:
        method = self._prefix + "." + name
        if method not in self._cerf.methods:
            raise AttributeError("the instance has no method " + method)
        return lambda **params: self._cerf.call(method, **params)


class Cerf:
    def __init__(self, transport: Transport, process: Optional[subprocess.Popen] = None,
                 log_file: Optional[str] = None) -> None:
        self._transport = transport
        self._buffer = b""
        self._next_id = 1
        self._events: Deque[Tuple[str, Any]] = collections.deque()
        self._subscribed: set = set()
        self.process = process
        self.log_file = log_file
        self.keep_running = process is None
        description = self.call("describe")
        if description.get("protocol") != PROTOCOL:
            raise CerfError(0, "protocol {} expected, the instance has protocol {}".format(
                PROTOCOL, description.get("protocol")))
        self.methods: Dict[str, Dict] = {m["name"]: m for m in description["methods"]}
        self.topics: Dict[str, Dict] = {t["name"]: t for t in description["topics"]}

    @classmethod
    def connect(cls, endpoint: Optional[str] = None, device: Optional[str] = None, cerf: Optional[str] = None,
                wait: float = 0.0, log_file: Optional[str] = None) -> "Cerf":
        if (endpoint is None) == (device is None):
            raise ValueError("give either endpoint= or device=")
        deadline = time.monotonic() + wait
        if device is not None:
            address = discovery.device_address(device, cerf)
            while address is None and time.monotonic() < deadline:
                time.sleep(0.2)
                address = discovery.device_address(device, cerf)
            if address is None:
                raise ConnectionError("no running instance of {} has an automation endpoint".format(device))
        else:
            address = endpoint_address(endpoint)
        return cls(open_transport(address, max(0.0, deadline - time.monotonic())), log_file=log_file)

    @classmethod
    def spawn(cls, device: str, cerf: Optional[str] = None, args: Sequence[str] = (), name: Optional[str] = None,
              log_file: Optional[str] = None, wait: float = 60.0, keep_running: bool = False) -> "Cerf":
        install, exe = discovery.install_and_executable(cerf)
        name = name or endpoint_name("cerf-{}-{}".format(device, uuid.uuid4().hex[:8]))
        command = [str(exe), "--device=" + device, "--automation=" + name]
        if log_file is not None:
            command.append("--log-file=" + str(Path(log_file).resolve()))
        command += list(args)
        options: Dict[str, Any] = {"cwd": str(install), "stdin": subprocess.DEVNULL,
                                   "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
        if sys.platform == "win32":
            options["creationflags"] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            options["start_new_session"] = True
        process = subprocess.Popen(command, **options)
        deadline = time.monotonic() + wait
        address = endpoint_address(name)
        while True:
            if process.poll() is not None:
                raise ConnectionError("the instance exited with code {} before its endpoint opened".format(
                    process.returncode))
            try:
                transport = open_transport(address, 0.0)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)
        cerf_instance = cls(transport, process, log_file)
        cerf_instance.keep_running = keep_running
        return cerf_instance

    @staticmethod
    def running(cerf: Optional[str] = None) -> List[Dict]:
        return discovery.running(cerf)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_") or "methods" not in self.__dict__:
            raise AttributeError(name)
        if name in self.methods:
            return lambda **params: self.call(name, **params)
        if any(method.startswith(name + ".") for method in self.methods):
            return _Namespace(self, name)
        raise AttributeError("the instance has no method or method group " + name)

    def __enter__(self) -> "Cerf":
        return self

    def __exit__(self, *exc: Any) -> None:
        if self.keep_running or self.process is None:
            self.close()
            return
        try:
            self.call("shutdown.run", action="exit")
        except (CerfError, ConnectionError):
            pass
        self.close()
        self.process.wait(timeout=60)

    def close(self) -> None:
        self._transport.close()

    def call(self, method: str, _timeout: Optional[float] = None, **params: Any) -> Any:
        request_id = self._next_id
        self._next_id += 1
        message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
        self._transport.send((json.dumps(message) + "\n").encode("utf-8"))
        deadline = None if _timeout is None else time.monotonic() + _timeout
        while True:
            reply = self._read(None if deadline is None else max(0.0, deadline - time.monotonic()))
            if reply is None:
                raise TimeoutError("{} got no reply in {} s".format(method, _timeout))
            if reply.get("id") != request_id:
                continue
            if "error" in reply:
                raise CerfError(reply["error"]["code"], reply["error"]["message"])
            return reply["result"]

    def _read(self, timeout: Optional[float]) -> Optional[Dict]:
        deadline = None if timeout is None else time.monotonic() + timeout
        while b"\n" not in self._buffer:
            left = None if deadline is None else max(0.0, deadline - time.monotonic())
            data = self._transport.receive(left)
            if data is None:
                return None
            if data == b"":
                raise ConnectionError("the instance closed the connection")
            self._buffer += data
        line, self._buffer = self._buffer.split(b"\n", 1)
        message = json.loads(line.decode("utf-8"))
        if message.get("method") == "event":
            self._events.append((message["params"]["topic"], message["params"]["data"]))
            return {}
        return message

    def subscribe(self, *topics: str) -> Dict[str, Any]:
        snapshot = self.call("events.subscribe", topics=list(topics))
        self._subscribed.update(topics)
        return snapshot

    def unsubscribe(self, *topics: str) -> None:
        self.call("events.unsubscribe", topics=list(topics))
        self._subscribed.difference_update(topics)

    def next_event(self, timeout: Optional[float] = None) -> Optional[Tuple[str, Any]]:
        deadline = None if timeout is None else time.monotonic() + timeout
        while not self._events:
            left = None if deadline is None else max(0.0, deadline - time.monotonic())
            if self._read(left) is None:
                return None
        return self._events.popleft()

    def wait_event(self, topic: str, predicate: Optional[Callable[[Any], bool]] = None,
                   timeout: Optional[float] = None) -> Any:
        if topic not in self._subscribed:
            raise CerfError(0, "the topic {} is not subscribed".format(topic))
        deadline = None if timeout is None else time.monotonic() + timeout
        kept: List[Tuple[str, Any]] = []
        try:
            while True:
                left = None if deadline is None else max(0.0, deadline - time.monotonic())
                event = self.next_event(left)
                if event is None:
                    raise TimeoutError("no {} event in {} s".format(topic, timeout))
                if event[0] == topic and (predicate is None or predicate(event[1])):
                    return event[1]
                kept.append(event)
        finally:
            self._events.extendleft(reversed(kept))

    def wait_for(self, condition: Callable[[], Any], timeout: float, interval: float = 0.1) -> Any:
        deadline = time.monotonic() + timeout
        while True:
            value = condition()
            if value:
                return value
            if time.monotonic() >= deadline:
                raise TimeoutError("the condition did not hold in {} s".format(timeout))
            time.sleep(interval)

    def wait_log(self, pattern: str, timeout: float, from_start: bool = False) -> "re.Match":
        if self.log_file is None:
            raise CerfError(0, "no log file; pass log_file= to connect or spawn")
        regex = re.compile(pattern)
        path = Path(self.log_file)
        offset = 0 if from_start or not path.exists() else path.stat().st_size
        pending = ""
        deadline = time.monotonic() + timeout
        while True:
            if path.exists():
                with path.open("rb") as f:
                    f.seek(offset)
                    chunk = f.read()
                offset += len(chunk)
                pending += chunk.decode("utf-8", errors="replace")
                lines = pending.split("\n")
                pending = lines.pop()
                for line in lines:
                    match = regex.search(line)
                    if match:
                        return match
            if time.monotonic() >= deadline:
                raise TimeoutError("no log line matched {!r} in {} s".format(pattern, timeout))
            time.sleep(0.1)

    def frame(self, x: Optional[int] = None, y: Optional[int] = None, width: Optional[int] = None,
              height: Optional[int] = None) -> Frame:
        params = {k: v for k, v in (("x", x), ("y", y), ("width", width), ("height", height)) if v is not None}
        return Frame.from_reply(self.call("screen.pixels", **params), x or 0, y or 0)

    def tap(self, x: int, y: int, button: str = "left", hold: float = 0.1) -> None:
        self.call("pointer.press", x=x, y=y, button=button)
        time.sleep(hold)
        self.call("pointer.release", x=x, y=y, button=button)

    def drag(self, points: Iterable[Tuple[int, int]], button: str = "left", step: float = 0.02) -> None:
        path = list(points)
        if len(path) < 2:
            raise ValueError("a drag needs at least two points")
        self.call("pointer.press", x=path[0][0], y=path[0][1], button=button)
        for x, y in path[1:]:
            time.sleep(step)
            self.call("pointer.move", x=x, y=y)
        self.call("pointer.release", x=path[-1][0], y=path[-1][1], button=button)

    def press_key(self, key: Any, hold: float = 0.1, stock: bool = False) -> None:
        self.call("keyboard.press", key=key, stock=stock)
        time.sleep(hold)
        self.call("keyboard.release", key=key)

    def press_button(self, path: List[str], hold: float = 0.1) -> None:
        self.call("button.press", path=path)
        time.sleep(hold)
        self.call("button.release", path=path)

    def type_text(self, text: str, hold: float = 0.1, gap: float = 0.1) -> None:
        for key in self.call("keyboard.keys_for_text", text=text):
            if key["shift"]:
                self.call("keyboard.press", key=SHIFT)
            self.press_key(key["vk"], hold)
            if key["shift"]:
                self.call("keyboard.release", key=SHIFT)
            time.sleep(gap)
