from __future__ import annotations
from i18n import t

import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, List, Optional, Tuple

from board_database import BOARD_FAMILIES, BOARD_FAMILIES_BY_ID, BOARDS, sort_text
from board_info import (SUPPORT_LABELS, SUPPORT_NO_SUPPORT,
                        SUPPORT_UNKNOWN_PARTIAL, board_soc_label,
                        board_sort_key, support_label)
from branded_dialog import scaled
from dialog_buttons import pack_actions
from filter_tree import (GROUP_TAG, grouped_tree, pack_search, pack_toggle,
                         search_query)
from screen_geometry import fit_geometry
import ui_theme as theme

_FAMILY_IID_PREFIX = "board-family::"
_CELL_PAD_DIP = 24


def _support_width(widget: tk.Misc) -> int:
    font = ttk.Style(widget).lookup("Treeview", "font") or "TkDefaultFont"
    text = max((int(widget.tk.call("font", "measure", font, label))
                for label in (support_label(level) for level in SUPPORT_LABELS)))
    return text + scaled(widget, _CELL_PAD_DIP)


class BoardPicker:
    def __init__(self, parent: tk.Misc, current_board_id: str,
                 on_pick: Callable[[str], None]) -> None:
        self._on_pick = on_pick
        self._current = current_board_id

        dlg = tk.Toplevel(parent)
        self._dlg = dlg
        dlg.title(t("launcher.board_picker.pick_a_board"))
        if parent.winfo_viewable():
            dlg.transient(parent)
        body = ttk.Frame(dlg, padding=8)
        body.pack(fill="both", expand=True)
        body.rowconfigure(1, weight=1)
        body.columnconfigure(0, weight=1)

        filt = ttk.Frame(body)
        filt.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 6))
        self.var_hide_unconfirmed = tk.BooleanVar(value=False)
        self.var_hide_unsupported = tk.BooleanVar(value=True)
        pack_toggle(filt, t("board.hide_unknown_support"), self.var_hide_unconfirmed,
                    self._refill)
        pack_toggle(filt, t("launcher.board_picker.hide_unsupported"), self.var_hide_unsupported,
                    self._refill)
        self.var_search = tk.StringVar(value="")
        pack_search(filt, self.var_search, self._refill)

        support_w = _support_width(dlg)
        self.tree, _ = grouped_tree(
            body, ("#0", t("common.board"), 300, 200, "w", True),
            [("soc", "SoC", 200, 120, "w", True),
             ("support", t("board.emulation_coverage"), support_w, support_w, "w", False)],
            selectmode="browse", row=1)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._sync_ok())
        self.tree.bind("<Double-1>", self._on_double_click)

        footer = ttk.Frame(body)
        footer.grid(row=2, column=0, columnspan=2, sticky="e", pady=(8, 0))
        self.btn_ok = pack_actions(footer, [(t("common.ok"), self._confirm),
                                            (t("common.cancel"), dlg.destroy)])[0]

        self._refill()
        dlg.update_idletasks()
        theme.apply_titlebar(dlg)
        fit_geometry(dlg, 820, 560, parent=parent)
        dlg.grab_set()

    def _visible(self, board: dict) -> bool:
        level = board.get("support_level")
        if self.var_hide_unconfirmed.get() and level == SUPPORT_UNKNOWN_PARTIAL:
            return False
        if self.var_hide_unsupported.get() and level == SUPPORT_NO_SUPPORT:
            return False
        query = search_query(self.var_search)
        return not query or query in self._haystack(board)

    def _haystack(self, board: dict) -> str:
        family = BOARD_FAMILIES_BY_ID.get(board.get("board_family_id", ""), {})
        return " ".join([board.get("name", ""), board["id"],
                         family.get("name", ""), board_soc_label(board["id"]),
                         support_label(board.get("support_level", ""))]
                        ).lower()

    def _grouped(self) -> List[Tuple[dict, List[dict]]]:
        members: Dict[str, List[dict]] = {}
        for board in BOARDS:
            if self._visible(board):
                members.setdefault(board.get("board_family_id", ""), []).append(board)
        families = sorted((f for f in BOARD_FAMILIES if f["id"] in members),
                          key=lambda f: sort_text(f.get("name")))
        return [(f, sorted(members[f["id"]],
                           key=lambda b: board_sort_key(b.get("name"))))
                for f in families]

    def _refill(self) -> None:
        tree = self.tree
        tree.delete(*tree.get_children())
        for family, boards in self._grouped():
            gid = _FAMILY_IID_PREFIX + family["id"]
            tree.insert("", "end", iid=gid, text=family.get("name", family["id"]),
                        open=True, tags=(GROUP_TAG,))
            for board in boards:
                tree.insert(gid, "end", iid=board["id"],
                            text=board.get("name", board["id"]),
                            values=(board_soc_label(board["id"]),
                                    support_label(board.get("support_level", ""))))
        if tree.exists(self._current):
            tree.selection_set(self._current)
            tree.see(self._current)
        self._sync_ok()

    def _selected_board(self) -> Optional[str]:
        selection = self.tree.selection()
        if not selection or selection[0].startswith(_FAMILY_IID_PREFIX):
            return None
        return selection[0]

    def _sync_ok(self) -> None:
        self.btn_ok.config(state="normal" if self._selected_board() else "disabled")

    def _on_double_click(self, event: tk.Event) -> None:
        if self.tree.identify_row(event.y) and self._selected_board():
            self._confirm()

    def _confirm(self) -> None:
        board_id = self._selected_board()
        if board_id is None:
            return
        self._dlg.destroy()
        self._on_pick(board_id)
