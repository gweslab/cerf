"""Modal dialogs and tooltips: the generic dark-themed dialog plus every
canned launcher dialog (ROM license, guest-additions help)."""
from __future__ import annotations
from i18n import t

import os
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import ttk
from typing import Callable, Dict, Optional, Tuple

from copyright_removal_dialog import (BUTTON_LABEL as COPYRIGHT_BUTTON_LABEL,
                                      ContactsFn, show_copyright_removal)
from device_source_text import source_credit
from device_state import DeviceSource
from dialog_buttons import pack_actions
import ui_theme as theme


DISCORD_URL = "https://discord.gg/QREE9Y2v2d"
WEBSITE_URL = "https://cerf.cx"
GUEST_ADDITIONS_URL = "https://cerf.cx/articles/guest-additions/"
BUNDLE_REPOSITORIES_URL = "https://cerf.cx/articles/bundle-repositories/"
HIBERNATION_WARNING_URL = "https://cerf.cx/hibernation-warning"

# Funding target, mirroring .github/FUNDING.yml (patreon: dz3n) - that file is
# not shipped with the packaged launcher, so the handle is spelled out here.
PATREON_URL = "https://www.patreon.com/dz3n"


def open_device_directory(parent: tk.Misc, path: Path) -> None:
    try:
        os.startfile(str(path))
    except OSError as exc:
        show_error(parent, t("launcher.launcher_app.open_device_directory"), str(exc))


def _run_extra(dlg: tk.Toplevel, handler: Callable[[tk.Misc], None]) -> None:
    handler(dlg)
    if dlg.winfo_exists():
        dlg.grab_set()


def show_dialog(parent: tk.Misc, title: str, message: str,
                buttons: Optional[tuple[str, ...]] = None,
                default: Optional[str] = None,
                extra: Optional[Tuple[str, Callable[[tk.Misc], None]]] = None
                ) -> str:
    if buttons is None:
        buttons = (t("common.ok"),)
    dlg = tk.Toplevel(parent)
    dlg.title(title)
    dlg.configure(bg=theme.BG)
    if parent.winfo_viewable():
        dlg.transient(parent)
    dlg.resizable(False, False)
    result = {"value": default if default is not None else buttons[-1]}

    body = ttk.Frame(dlg, padding=16)
    body.pack(fill="both", expand=True)
    ttk.Label(body, text=message, wraplength=420, justify="left").pack(
        anchor="w", pady=(0, 14))

    row = ttk.Frame(body)
    row.pack(fill="x")
    if extra is not None:
        extra_label, extra_handler = extra
        ttk.Button(row, text=extra_label,
                   command=lambda: _run_extra(dlg, extra_handler)).pack(
            side="left")

    btns = ttk.Frame(row)
    btns.pack(side="right")

    def click(label: str) -> None:
        result["value"] = label
        dlg.destroy()

    primary = pack_actions(btns, [(label, lambda l=label: click(l))
                                  for label in buttons])[0]
    primary.focus_set()
    dlg.bind("<Return>", lambda _e: click(buttons[0]))
    dlg.bind("<Escape>", lambda _e: dlg.destroy())

    dlg.update_idletasks()
    theme.apply_titlebar(dlg)
    w, h = dlg.winfo_reqwidth(), dlg.winfo_reqheight()
    x = parent.winfo_rootx() + (parent.winfo_width()  - w) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
    dlg.geometry(f"+{max(0, x)}+{max(0, y)}")

    dlg.lift()
    dlg.focus_force()
    dlg.grab_set()
    parent.wait_window(dlg)
    return result["value"]


def ask_text(parent: tk.Misc, title: str, prompt: str,
             initial: str = "") -> Optional[str]:
    dlg = tk.Toplevel(parent)
    dlg.title(title)
    dlg.configure(bg=theme.BG)
    if parent.winfo_viewable():
        dlg.transient(parent)
    dlg.resizable(False, False)
    result: Dict[str, Optional[str]] = {"value": None}

    body = ttk.Frame(dlg, padding=16)
    body.pack(fill="both", expand=True)
    ttk.Label(body, text=prompt, wraplength=460, justify="left").pack(
        anchor="w", pady=(0, 8))
    var = tk.StringVar(value=initial)
    entry = ttk.Entry(body, textvariable=var, width=64)
    entry.pack(fill="x")
    entry.focus_set()

    def accept() -> None:
        result["value"] = var.get().strip()
        dlg.destroy()

    btns = ttk.Frame(body)
    btns.pack(anchor="e", pady=(14, 0))
    pack_actions(btns, [(t("common.ok"), accept), (t("common.cancel"), dlg.destroy)])
    dlg.bind("<Return>", lambda _e: accept())
    dlg.bind("<Escape>", lambda _e: dlg.destroy())

    dlg.update_idletasks()
    theme.apply_titlebar(dlg)
    w, h = dlg.winfo_reqwidth(), dlg.winfo_reqheight()
    x = parent.winfo_rootx() + (parent.winfo_width() - w) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
    dlg.geometry(f"+{max(0, x)}+{max(0, y)}")

    dlg.lift()
    dlg.focus_force()
    dlg.grab_set()
    parent.wait_window(dlg)
    return result["value"]


def show_info(parent: tk.Misc, title: str, message: str) -> None:
    show_dialog(parent, title, message)


def show_error(parent: tk.Misc, title: str, message: str) -> None:
    show_dialog(parent, title, message)


def ask_yesno(parent: tk.Misc, title: str, message: str,
              extra: Optional[Tuple[str, Callable[[tk.Misc], None]]] = None
              ) -> bool:
    return show_dialog(parent, title, message, (t("common.yes"), t("common.no")), default=t("common.no"),
                       extra=extra) == t("common.yes")


def confirm_rom_license(parent: tk.Misc, display_name: str,
                        abuse_contacts_fn: ContactsFn) -> bool:
    return ask_yesno(
        parent,
        t("launcher.ui_dialogs.download_confirmation"),
        t('launcher.ui_dialogs.rom_bundles_and_add_on_packages_distributed', display_name=display_name, display_name2=display_name),
        extra=(t(COPYRIGHT_BUTTON_LABEL),
               lambda dlg: show_copyright_removal(dlg, abuse_contacts_fn())),
    )


def show_bpp_help(parent: tk.Misc) -> None:
    show_info(
        parent,
        t("common.color_depth"),
        t("properties.color_depth_help")
    )


def show_guest_additions_help(parent: tk.Misc) -> None:
    """Open the Guest Additions article in the browser."""
    webbrowser.open(GUEST_ADDITIONS_URL)


def link_label(parent: tk.Misc, text: str, url: str) -> ttk.Label:
    lbl = ttk.Label(parent, text=text, foreground=theme.LINK_FG, cursor="hand2")
    lbl.bind("<Button-1>", lambda _e: webbrowser.open(url))
    return lbl


def show_source_thanks(parent: tk.Misc, source: DeviceSource) -> None:
    show_sources_thanks(parent, [source] if source is not None else [])


def show_sources_thanks(parent: tk.Misc, sources) -> None:
    distinct: list = []
    seen: set = set()
    for s in sources:
        if s is not None and s.has_website_and_donate and s.name not in seen:
            seen.add(s.name)
            distinct.append(s)
    if not distinct:
        return

    dlg = tk.Toplevel(parent)
    dlg.title(t("launcher.ui_dialogs.rom_preservation"))
    dlg.configure(bg=theme.BG)
    if parent.winfo_viewable():
        dlg.transient(parent)
    dlg.resizable(False, False)

    body = ttk.Frame(dlg, padding=16)
    body.pack(fill="both", expand=True)
    for i, source in enumerate(distinct):
        if i:
            ttk.Label(body, text="").pack(anchor="w")
        ttk.Label(body, wraplength=420, justify="left",
                  text=source_credit(source)).pack(anchor="w")
        ask = ttk.Frame(body)
        ask.pack(anchor="w", pady=(6, 0))
        ttk.Label(ask, text=t("launcher.ui_dialogs.would_you_like_to")).pack(side="left")
        link_label(ask, "pay them a visit", source.website).pack(side="left")
        ttk.Label(ask, text=t("launcher.ui_dialogs.or")).pack(side="left")
        link_label(ask, "support them", source.donate).pack(side="left")
        ttk.Label(ask, text="?").pack(side="left")
        if source.origin:
            link_label(body, "Source data link", source.origin).pack(anchor="w")

    btns = ttk.Frame(body)
    btns.pack(anchor="e", pady=(14, 0))
    pack_actions(btns, [(t("common.ok"), dlg.destroy)])[0].focus_set()
    dlg.bind("<Return>", lambda _e: dlg.destroy())
    dlg.bind("<Escape>", lambda _e: dlg.destroy())

    dlg.update_idletasks()
    theme.apply_titlebar(dlg)
    w, h = dlg.winfo_reqwidth(), dlg.winfo_reqheight()
    x = parent.winfo_rootx() + (parent.winfo_width()  - w) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
    dlg.geometry(f"+{max(0, x)}+{max(0, y)}")


def bind_tooltip(widget: tk.Widget, text: str) -> None:
    state: Dict[str, Optional[tk.Toplevel]] = {"tip": None}

    def show(_e: object) -> None:
        if state["tip"] is not None:
            return
        tip = tk.Toplevel(widget)
        tip.wm_overrideredirect(True)
        tip.configure(bg=theme.BORDER)
        ttk.Label(tip, text=text, background=theme.BG_FIELD, foreground=theme.FG,
                  padding=(6, 2)).pack(padx=1, pady=1)
        x = widget.winfo_rootx()
        y = widget.winfo_rooty() + widget.winfo_height() + 2
        tip.wm_geometry(f"+{x}+{y}")
        state["tip"] = tip

    def hide(_e: object) -> None:
        if state["tip"] is not None:
            state["tip"].destroy()
            state["tip"] = None

    widget.bind("<Enter>", show)
    widget.bind("<Leave>", hide)
