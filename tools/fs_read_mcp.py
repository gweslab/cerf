"""
Filesystem Read MCP Server
--------------------------
Reads text files without the Read tool's 25000-token refusal.

The Read tool counts tokens of the requested slice and refuses the whole call
when the slice is dense, which turns a large document into a guess-the-offset
retry loop. This server returns a deterministic character-bounded chunk plus
the exact offset of the next chunk, so a read never fails and never needs a
retry.

Two host-side caps still apply to any MCP result and shape the defaults here:

    MAX_MCP_OUTPUT_TOKENS   token cap, default 25000, settable in
                            ~/.claude/settings.json under "env"
    persistence threshold   50000 characters, not settable; a larger result is
                            written to a temp file and replaced by a preview

FS_READ_MAX_CHARS keeps the default chunk under the second cap.

Configure with environment variables:
    FS_READ_MAX_CHARS       default characters per chunk (default: 45000)
    FS_READ_MAX_FILE_BYTES  refuse files larger than this (default: 67108864)

Run:
    python fs_read_mcp.py
"""

from __future__ import annotations

import logging
import os

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ToolError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("fs-read-mcp")

mcp = FastMCP("fs-tools")

DEFAULT_MAX_CHARS = int(os.getenv("FS_READ_MAX_CHARS", "45000"))
MAX_FILE_BYTES = int(os.getenv("FS_READ_MAX_FILE_BYTES", str(64 * 1024 * 1024)))


def _resolve(path: str) -> str:
    if not path:
        raise ToolError("path is required")
    full = os.path.abspath(os.path.expanduser(path))
    if not os.path.exists(full):
        raise ToolError("no such path: %s" % full)
    if os.path.isdir(full):
        raise ToolError("path is a directory: %s" % full)
    if not os.path.isfile(full):
        raise ToolError("path is not a regular file: %s" % full)
    size = os.path.getsize(full)
    if size > MAX_FILE_BYTES:
        raise ToolError(
            "file is %d bytes, over the FS_READ_MAX_FILE_BYTES limit of %d"
            % (size, MAX_FILE_BYTES)
        )
    return full


def _read_lines(full: str) -> list[str]:
    with open(full, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        text = fh.read()
    return text.splitlines(keepends=True)


def _char_offsets(lines: list[str]) -> list[int]:
    offsets = [0]
    total = 0
    for line in lines:
        total += len(line)
        offsets.append(total)
    return offsets


@mcp.tool(structured_output=False)
def fs_read(
    path: str,
    offset: int = 1,
    limit: int = 0,
    max_chars: int = 0,
    line_numbers: bool = False,
) -> str:
    """
    Read a text file from a starting line, bounded by a character budget.

    Use this instead of the Read tool for large or dense files. The call never
    fails on size: it returns as many whole lines as fit in the budget and
    reports the offset to pass on the next call. Repeat until the header says
    "more: no".

    The result is raw file content, so it does not satisfy the Edit tool's
    "must Read the file first" precondition. Use the Read tool before editing.

    Args:
        path: File to read. Absolute, or relative to the server's directory.
        offset: 1-based line to start at. Default 1.
        limit: Maximum lines to return, before the character budget is
               applied. 0 means "to the end of the file". Default 0.
        max_chars: Character budget for this chunk. 0 uses the FS_READ_MAX_CHARS
                   default (45000, which stays under the host's 50000-character
                   MCP persistence threshold). A negative value removes the
                   budget, which lets the host truncate or persist the result.
        line_numbers: Prefix each line with its 1-based number. Default False.

    Returns:
        A header block (path, line range, character range, whether more
        content follows, the next offset) followed by the file content.
    """
    full = _resolve(path)
    lines = _read_lines(full)
    total_lines = len(lines)
    offsets = _char_offsets(lines)
    total_chars = offsets[-1]

    if offset < 1:
        raise ToolError("offset is 1-based, got %d" % offset)
    if limit < 0:
        raise ToolError("limit must be zero or positive, got %d" % limit)

    start = offset - 1
    if start >= total_lines:
        return (
            "=== fs_read: %s ===\n"
            "lines: none (offset %d is past the last line, file has %d)\n"
            "chars: %d total | more: no\n"
            % (full, offset, total_lines, total_chars)
        )

    stop = total_lines if limit == 0 else min(total_lines, start + limit)
    budget = DEFAULT_MAX_CHARS if max_chars == 0 else max_chars

    end = start
    used = 0
    while end < stop:
        length = len(lines[end])
        if budget >= 0 and end > start and used + length > budget:
            break
        used += length
        end += 1

    body = "".join(lines[start:end])
    if line_numbers:
        body = "".join(
            "%d\t%s" % (start + i + 1, lines[start + i]) for i in range(end - start)
        )

    more = end < total_lines
    header = (
        "=== fs_read: %s ===\n"
        "lines %d-%d of %d | chars %d-%d of %d | more: %s\n"
        % (
            full,
            start + 1,
            end,
            total_lines,
            offsets[start],
            offsets[end],
            total_chars,
            "yes" if more else "no",
        )
    )
    if more:
        header += "next: fs_read(path=%r, offset=%d)\n" % (full, end + 1)
    header += "\n"
    return header + body


@mcp.tool(structured_output=False)
def fs_stat(path: str) -> str:
    """
    Report the size of a text file and how many fs_read calls it takes.

    Call this before reading an unfamiliar large file, to plan the reads.

    Args:
        path: File to measure. Absolute, or relative to the server's directory.

    Returns:
        Byte size, line count, character count, the longest line, and the
        number of fs_read chunks at the current default budget.
    """
    full = _resolve(path)
    lines = _read_lines(full)
    total_chars = sum(len(line) for line in lines)
    longest = max((len(line) for line in lines), default=0)

    chunks = 0
    used = 0
    for line in lines:
        if used and used + len(line) > DEFAULT_MAX_CHARS:
            chunks += 1
            used = 0
        used += len(line)
    if used or not lines:
        chunks += 1

    return (
        "=== fs_stat: %s ===\n"
        "bytes: %d\n"
        "lines: %d\n"
        "chars: %d\n"
        "longest line: %d chars\n"
        "fs_read chunks at %d chars: %d\n"
        % (
            full,
            os.path.getsize(full),
            len(lines),
            total_chars,
            longest,
            DEFAULT_MAX_CHARS,
            chunks,
        )
    )


def main() -> None:
    """
    Run the MCP server over stdio.

    Environment variables:
        FS_READ_MAX_CHARS       Default characters per chunk (default 45000)
        FS_READ_MAX_FILE_BYTES  Largest readable file (default 64 MiB)
    """
    logger.info(
        "Starting filesystem read MCP server, max_chars=%d, max_file_bytes=%d",
        DEFAULT_MAX_CHARS,
        MAX_FILE_BYTES,
    )
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
