from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Callable, List, Optional, Sequence

CUSTOM_LABEL = "Custom..."
LIST_ROWS = 12

LabelOf = Callable[[object], str]
AskCustom = Callable[[object], Optional[object]]


class ChoiceCombo:
    def __init__(self, parent: tk.Misc,
                 on_change: Optional[Callable[[], None]] = None,
                 ask_custom: Optional[AskCustom] = None) -> None:
        self._on_change = on_change
        self._ask_custom = ask_custom
        self._values: List[object] = []
        self._label_of: LabelOf = str
        self._value: object = None
        self.var = tk.StringVar()
        self.widget = ttk.Combobox(parent, state="readonly", width=1,
                                   height=LIST_ROWS, textvariable=self.var)
        self.widget.bind("<<ComboboxSelected>>", self._on_selected)

    def configure(self, values: Sequence[object], label_of: LabelOf) -> None:
        self._values = list(values)
        self._label_of = label_of
        labels = [label_of(v) for v in self._values]
        if self._ask_custom is not None:
            labels.append(CUSTOM_LABEL)
        self.widget.config(values=labels)
        self._show()

    def get(self) -> object:
        return self._value

    def set(self, value: object) -> None:
        self._value = value
        self._show()

    def set_enabled(self, enabled: bool) -> None:
        self.widget.config(state="readonly" if enabled else "disabled")

    def _show(self) -> None:
        self.var.set(self._label_of(self._value))

    def _on_selected(self, _event: object) -> None:
        index = self.widget.current()
        self.widget.selection_clear()
        if 0 <= index < len(self._values):
            value = self._values[index]
        elif self._ask_custom is not None and index == len(self._values):
            value = self._ask_custom(self._value)
            if value is None:
                self._show()
                return
        else:
            return
        changed = value != self._value
        self._value = value
        self._show()
        if changed and self._on_change is not None:
            self._on_change()
