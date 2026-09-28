from __future__ import annotations

import tkinter as tk

import ui_theme as theme

_ENTRY_CLASSES = ("TEntry", "TCombobox", "Entry")
_TEXT_CLASS = "Text"


class TextContextMenu:
    def __init__(self, root: tk.Tk) -> None:
        self._menu = tk.Menu(root, tearoff=0, bd=0)
        for cls in _ENTRY_CLASSES + (_TEXT_CLASS,):
            root.bind_class(cls, "<Button-3>", self._on_right_click)

    def _on_right_click(self, event: tk.Event) -> None:
        widget = event.widget
        is_text = widget.winfo_class() == _TEXT_CLASS
        if hasattr(widget, "instate"):
            disabled = widget.instate(["disabled"])
            readonly = widget.instate(["readonly"])
        else:
            state = str(widget.cget("state"))
            disabled = state == "disabled"
            readonly = state == "readonly"
        if disabled and not is_text:
            return
        editable = not disabled and not readonly
        if is_text:
            has_selection = bool(widget.tag_ranges("sel"))
        else:
            has_selection = widget.selection_present()
        try:
            has_clip = bool(widget.clipboard_get())
        except tk.TclError:
            has_clip = False

        widget.focus_set()
        menu = self._menu
        menu.config(background=theme.BG_FIELD, foreground=theme.FG,
                    activebackground=theme.BG_HOVER, activeforeground=theme.FG,
                    disabledforeground=theme.FG_DIM)
        menu.delete(0, "end")
        self._add(menu, widget, "Cut", "<<Cut>>", editable and has_selection)
        self._add(menu, widget, "Copy", "<<Copy>>", has_selection)
        self._add(menu, widget, "Paste", "<<Paste>>", editable and has_clip)
        self._add(menu, widget, "Delete", "<<Clear>>", editable and has_selection)
        menu.add_separator()
        self._add(menu, widget, "Select all", "<<SelectAll>>", True)
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    @staticmethod
    def _add(menu: tk.Menu, widget: tk.Misc, label: str, virtual: str,
             enabled: bool) -> None:
        menu.add_command(label=label,
                         command=lambda: widget.event_generate(virtual),
                         state="normal" if enabled else "disabled")
