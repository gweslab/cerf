from __future__ import annotations
from i18n import t

import tkinter as tk
from tkinter import ttk
from typing import Callable, Sequence, Tuple

import ui_theme as theme

GROUP_TAG = "group"
SEARCH_WIDTH = 24

Column = Tuple[str, str, int, int, str, bool]


def pack_toggle(parent: tk.Misc, text: str, variable: tk.BooleanVar,
                on_change: Callable[[], None]) -> ttk.Checkbutton:
    toggle = ttk.Checkbutton(parent, text=text, variable=variable,
                             command=on_change)
    toggle.pack(side="left", padx=(0, 12))
    return toggle


def pack_search(parent: tk.Misc, variable: tk.StringVar,
                on_change: Callable[[], None]) -> ttk.Entry:
    entry = ttk.Entry(parent, textvariable=variable, width=SEARCH_WIDTH)
    entry.pack(side="right")
    ttk.Label(parent, text=t("common.search")).pack(side="right", padx=(0, 4))
    variable.trace_add("write", lambda *_: on_change())
    return entry


def search_query(variable: tk.StringVar) -> str:
    return variable.get().strip().lower()


def grouped_tree(parent: tk.Misc, tree_column: Column,
                 columns: Sequence[Column], selectmode: str,
                 row: int) -> Tuple[ttk.Treeview, ttk.Scrollbar]:
    tree = ttk.Treeview(parent, columns=[c[0] for c in columns],
                        show="tree headings", selectmode=selectmode)
    for column_id, heading, width, minwidth, anchor, stretch in (
            [("#0",) + tuple(tree_column[1:])] + list(columns)):
        tree.heading(column_id, text=heading)
        tree.column(column_id, width=width, minwidth=minwidth, anchor=anchor,
                    stretch=stretch)
    tree.grid(row=row, column=0, sticky="nsew")
    scrollbar = ttk.Scrollbar(parent, orient="vertical", command=tree.yview)
    scrollbar.grid(row=row, column=1, sticky="ns")
    tree.configure(yscrollcommand=scrollbar.set)
    tree.tag_configure(GROUP_TAG, background=theme.GROUP_BG, foreground=theme.FG)
    return tree, scrollbar
