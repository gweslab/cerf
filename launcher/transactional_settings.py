from __future__ import annotations

from typing import Optional

from settings_dialog import SettingsDialog


def run_settings(ctx, _query: dict) -> Optional[dict]:
    SettingsDialog(ctx.root, owner_hwnd=ctx.owner_hwnd).wait()
    return None
