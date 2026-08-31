from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional

from color_schemes import color_scheme_supported_for_os
from customizations_block import CUSTOMIZATION_FIELDS, CustomizationsBlock
from persisted_options import persist_subset
import ui_theme as theme

RESET_NOTE = ("Windows CE 3 and older need at least a soft reset to use the "
              "new resolution. A DPI, font-size or colour-depth change "
              "requires a reset.")

_RESET_CHOICES = (("none", "Do not reset"),
                  ("soft", "Soft reset"),
                  ("hard", "Hard reset"))


class _CustomizationsDialog:
    def __init__(self, ctx, query: dict):
        self._ctx = ctx
        self._accepted = False
        self._reboot = None
        self._reset_needing = None

        force = query.get("force_reboot") is True
        default = query.get("default_reset")
        if force or default == "soft":
            initial = "soft"
        elif default == "hard":
            initial = "hard"
        else:
            initial = "none"

        dlg = tk.Toplevel(ctx.root)
        dlg.withdraw()
        dlg.title("Customizations - CE Runtime Foundation")
        dlg.configure(bg=theme.BG)
        dlg.resizable(False, False)
        self._dlg = dlg

        body = ttk.Frame(dlg, padding=14)
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)

        holder = ttk.Frame(body)
        holder.grid(row=0, column=0, sticky="ew")
        holder.columnconfigure(0, weight=1)
        self.block = CustomizationsBlock(holder, dlg, self._on_change, row=0)
        self.block.restore(ctx.effective)
        self.block.refresh_state(
            True, True, color_scheme_supported_for_os(ctx.meta.os_name), False)

        reset = ttk.LabelFrame(body, text="Reset device", padding=8)
        reset.grid(row=1, column=0, sticky="ew", pady=(12, 0))
        reset.columnconfigure(0, weight=1)
        ttk.Label(reset, text=RESET_NOTE, wraplength=380,
                  justify="left").grid(row=0, column=0, sticky="w",
                                       pady=(0, 6))
        self.var_reset = tk.StringVar(value=initial)
        self._radios = []
        for i, (value, label) in enumerate(_RESET_CHOICES):
            rb = ttk.Radiobutton(reset, text=label, value=value,
                                 variable=self.var_reset)
            rb.grid(row=1 + i, column=0, sticky="w")
            self._radios.append(rb)
        if force:
            for rb in self._radios:
                rb.config(state="disabled")

        buttons = ttk.Frame(body)
        buttons.grid(row=2, column=0, sticky="e", pady=(14, 0))
        ok = ttk.Button(buttons, text="OK", command=self._on_ok)
        ok.pack(side="left", padx=(6, 0))
        ttk.Button(buttons, text="Cancel",
                   command=self._on_cancel).pack(side="left", padx=(6, 0))
        ok.focus_set()

        dlg.bind("<Escape>", lambda _e: self._on_cancel())
        dlg.protocol("WM_DELETE_WINDOW", self._on_cancel)

        self._reset_needing = self._reset_needing_values()

    def run(self) -> Optional[dict]:
        self._ctx.present(self._dlg)
        if not self._accepted:
            return None
        return {"reboot": self._reboot}

    def _reset_needing_values(self) -> tuple:
        return (self.block.bpp_value(), self.block.dpi_enabled(),
                self.block.dpi.optional_value(),
                self.block.font_size_enabled(),
                self.block.font_size.optional_value(),
                self.block.color_scheme_key())

    def _on_change(self) -> None:
        if self._reset_needing is None:
            return
        current = self._reset_needing_values()
        if current == self._reset_needing:
            return
        self._reset_needing = current
        if self.var_reset.get() == "none":
            self.var_reset.set("soft")

    def _on_ok(self) -> None:
        if not self.block.validate():
            return
        fields: dict = {}
        self.block.collect(fields)
        persist_subset(self._ctx.device_dir, self._ctx.baseline,
                       CUSTOMIZATION_FIELDS, fields)
        choice = self.var_reset.get()
        self._reboot = None if choice == "none" else choice
        self._accepted = True
        self._dlg.destroy()

    def _on_cancel(self) -> None:
        self._accepted = False
        self._dlg.destroy()


def run_customizations(ctx, query: dict) -> Optional[dict]:
    return _CustomizationsDialog(ctx, query).run()
