from __future__ import annotations

import base64
import struct
import zlib
from typing import Tuple


class Frame:

    def __init__(self, width: int, height: int, data: bytes, x: int = 0, y: int = 0) -> None:
        if len(data) != width * height * 4:
            raise ValueError("the pixel data does not match {}x{}".format(width, height))
        self.width = width
        self.height = height
        self.data = data
        self.x = x
        self.y = y

    @classmethod
    def from_reply(cls, reply: dict, x: int = 0, y: int = 0) -> "Frame":
        return cls(reply["width"], reply["height"], base64.b64decode(reply["pixels"]), x, y)

    def pixel(self, x: int, y: int) -> Tuple[int, int, int]:
        if not (0 <= x < self.width and 0 <= y < self.height):
            raise IndexError("({}, {}) is outside the {}x{} frame".format(x, y, self.width, self.height))
        offset = (y * self.width + x) * 4
        b, g, r = self.data[offset], self.data[offset + 1], self.data[offset + 2]
        return r, g, b

    def region(self, x: int, y: int, width: int, height: int) -> "Frame":
        if x < 0 or y < 0 or width <= 0 or height <= 0 or x + width > self.width or y + height > self.height:
            raise IndexError("the region is outside the {}x{} frame".format(self.width, self.height))
        rows = [self.data[((y + row) * self.width + x) * 4:((y + row) * self.width + x + width) * 4]
                for row in range(height)]
        return Frame(width, height, b"".join(rows), self.x + x, self.y + y)

    def changed_pixels(self, other: "Frame") -> int:
        if (self.width, self.height) != (other.width, other.height):
            raise ValueError("the frames have different sizes")
        count = 0
        for offset in range(0, len(self.data), 4):
            if self.data[offset:offset + 3] != other.data[offset:offset + 3]:
                count += 1
        return count

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Frame):
            return NotImplemented
        return self.width == other.width and self.height == other.height and self.changed_pixels(other) == 0

    def _rgb_rows(self) -> bytes:
        out = bytearray()
        for row in range(self.height):
            out.append(0)
            line = self.data[row * self.width * 4:(row + 1) * self.width * 4]
            for offset in range(0, len(line), 4):
                out += bytes((line[offset + 2], line[offset + 1], line[offset]))
        return bytes(out)

    def save_png(self, path: str) -> None:
        def chunk(kind: bytes, body: bytes) -> bytes:
            return struct.pack(">I", len(body)) + kind + body + struct.pack(">I", zlib.crc32(kind + body))

        header = struct.pack(">IIBBBBB", self.width, self.height, 8, 2, 0, 0, 0)
        png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(self._rgb_rows()))
               + chunk(b"IEND", b""))
        with open(path, "wb") as f:
            f.write(png)
