from __future__ import annotations

from tkinter import ttk
from typing import Callable, List, Sequence, Tuple

ACCENT_STYLE = "Accent.TButton"
BUTTON_GAP = 6

Action = Tuple[str, Callable[[], None]]


def pack_actions(frame: ttk.Frame, actions: Sequence[Action],
                 primary_style: str = ACCENT_STYLE) -> List[ttk.Button]:
    buttons: List[ttk.Button] = []
    for index, (label, command) in enumerate(actions):
        button = ttk.Button(frame, text=label, command=command,
                            style=primary_style if index == 0 else "TButton")
        button.pack(side="left", padx=(BUTTON_GAP if index else 0, 0))
        buttons.append(button)
    return buttons
