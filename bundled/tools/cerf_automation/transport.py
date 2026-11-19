from __future__ import annotations

import os
import re
import socket
import sys
import time
from typing import Optional

READ_SIZE = 1 << 16
ERROR_PIPE_NOT_CONNECTED = 233


class Transport:
    def send(self, data: bytes) -> None:
        raise NotImplementedError

    def receive(self, timeout: Optional[float]) -> Optional[bytes]:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


class PipeTransport(Transport):
    def __init__(self, address: str) -> None:
        import _winapi

        self._winapi = _winapi
        self._read   = None
        self._handle = None
        self._handle = _winapi.CreateFile(
            address, _winapi.GENERIC_READ | _winapi.GENERIC_WRITE, 0, _winapi.NULL, _winapi.OPEN_EXISTING,
            _winapi.FILE_FLAG_OVERLAPPED, _winapi.NULL)

    def _closed(self, error: OSError) -> bool:
        return error.winerror in (self._winapi.ERROR_BROKEN_PIPE, self._winapi.ERROR_NO_DATA, ERROR_PIPE_NOT_CONNECTED)

    def send(self, data: bytes) -> None:
        w = self._winapi
        try:
            ov, err = w.WriteFile(self._handle, data, overlapped=True)
            if err == w.ERROR_IO_PENDING:
                w.WaitForMultipleObjects([ov.event], False, w.INFINITE)
            written, err = ov.GetOverlappedResult(True)
        except OSError as error:
            if self._closed(error):
                raise ConnectionError("the instance closed the connection") from error
            raise
        if err != 0 or written != len(data):
            raise ConnectionError("the instance closed the connection")

    def receive(self, timeout: Optional[float]) -> Optional[bytes]:
        w = self._winapi
        try:
            if self._read is None:
                self._read, _ = w.ReadFile(self._handle, READ_SIZE, overlapped=True)
            wait = w.INFINITE if timeout is None else max(0, int(timeout * 1000))
            if w.WaitForMultipleObjects([self._read.event], False, wait) == w.WAIT_TIMEOUT:
                return None
            read, self._read = self._read, None
            count, err = read.GetOverlappedResult(True)
        except OSError as error:
            if self._closed(error):
                self._read = None
                return b""
            raise
        if err == 0 and count == 0:
            return b""
        if err not in (0, w.ERROR_MORE_DATA):
            raise ConnectionError("reading the automation endpoint failed with error {}".format(err))
        return bytes(read.getbuffer())

    def __del__(self) -> None:
        self.close()

    def close(self) -> None:
        if self._read is not None:
            self._read.cancel()
            try:
                self._read.GetOverlappedResult(True)
            except OSError:
                pass
            self._read = None
        if self._handle is not None:
            self._winapi.CloseHandle(self._handle)
            self._handle = None


class SocketTransport(Transport):
    def __init__(self, address: str) -> None:
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            self._socket.connect(address)
        except OSError:
            self._socket.close()
            raise

    def send(self, data: bytes) -> None:
        self._socket.settimeout(None)
        try:
            self._socket.sendall(data)
        except OSError as error:
            raise ConnectionError("the instance closed the connection") from error

    def receive(self, timeout: Optional[float]) -> Optional[bytes]:
        self._socket.settimeout(timeout)
        try:
            return self._socket.recv(READ_SIZE)
        except (socket.timeout, BlockingIOError):
            return None
        except ConnectionResetError:
            return b""

    def close(self) -> None:
        self._socket.close()


def endpoint_name(text: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "-", text)[:64]


def endpoint_address(endpoint: str) -> str:
    if sys.platform == "win32":
        if endpoint.startswith("\\\\"):
            return endpoint
        return "\\\\.\\pipe\\" + endpoint
    if endpoint.startswith("/"):
        return endpoint
    temp = os.environ.get("TMPDIR", "").rstrip("/") or "/tmp"
    return temp + "/" + endpoint


def open_transport(address: str, wait: float) -> Transport:
    deadline = time.monotonic() + wait
    while True:
        try:
            if sys.platform == "win32":
                return PipeTransport(address)
            return SocketTransport(address)
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.1)
