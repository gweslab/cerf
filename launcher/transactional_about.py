from __future__ import annotations
from i18n import t

from typing import Optional

from about_window import AboutWindow


def _device_line(query: dict) -> str:
    board = query.get("board_name")
    soc = query.get("soc_name")
    if not isinstance(board, str) or not board:
        return ""
    line = t("about.emulated_device", device=board)
    if isinstance(soc, str) and soc:
        line += "  ·  " + soc
    return line


def run_about(ctx, query: dict) -> Optional[dict]:
    AboutWindow(ctx.root, _device_line(query),
                owner_hwnd=ctx.owner_hwnd).wait()
    return None
