"""Modal dialogs and tooltips: the generic dark-themed dialog plus every
canned launcher dialog (ROM license, guest-additions help)."""
from __future__ import annotations

import tkinter as tk
import webbrowser
from tkinter import ttk
from typing import Callable, Dict, Optional, Tuple

from copyright_removal_dialog import (BUTTON_LABEL as COPYRIGHT_BUTTON_LABEL,
                                      ContactsFn, show_copyright_removal)
from device_state import DeviceSource
import ui_theme as theme


DISCORD_URL = "https://discord.gg/QREE9Y2v2d"
WEBSITE_URL = "https://cerf.cx"
GUEST_ADDITIONS_URL = "https://cerf.cx/articles/guest-additions/"

# Funding target, mirroring .github/FUNDING.yml (patreon: dz3n) - that file is
# not shipped with the packaged launcher, so the handle is spelled out here.
PATREON_URL = "https://www.patreon.com/dz3n"


def _run_extra(dlg: tk.Toplevel, handler: Callable[[tk.Misc], None]) -> None:
    handler(dlg)
    if dlg.winfo_exists():
        dlg.grab_set()


def show_dialog(parent: tk.Misc, title: str, message: str,
                buttons: tuple[str, ...] = ("OK",),
                default: Optional[str] = None,
                extra: Optional[Tuple[str, Callable[[tk.Misc], None]]] = None
                ) -> str:
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
    for i, label in enumerate(buttons):
        def click(l=label):
            result["value"] = l
            dlg.destroy()
        b = ttk.Button(btns, text=label, command=click)
        b.pack(side="left", padx=(6, 0))
        if i == 0:
            b.focus_set()
        dlg.bind("<Return>", lambda _e, l=label: click(l)) if i == 0 else None
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
    ttk.Button(btns, text="OK", command=accept).pack(side="left", padx=(6, 0))
    ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side="left",
                                                              padx=(6, 0))
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
    return show_dialog(parent, title, message, ("Yes", "No"), default="No",
                       extra=extra) == "Yes"


def confirm_rom_license(parent: tk.Misc, display_name: str,
                        abuse_contacts_fn: ContactsFn) -> bool:
    return ask_yesno(
        parent,
        "Download confirmation",
        "ROM bundles and add-on packages distributed by this launcher are "
        "abandonware/released publicly by their respective OEMs. They remain "
        "the property of those OEMs and are governed by whatever terms "
        "the OEM applied when releasing them.\n\n"
        f"By pressing Yes you take full personal responsibility for "
        f"downloading {display_name} and accept whatever license, "
        f"terms, or restrictions the OEM applied. The CERF project "
        f"gives no warranty, grants no license, and accepts no "
        f"liability for the contents.\n\n"
        f"Download {display_name}?",
        extra=(COPYRIGHT_BUTTON_LABEL,
               lambda dlg: show_copyright_removal(dlg, abuse_contacts_fn())),
    )


def show_dpi_help(parent: tk.Misc) -> None:
    show_info(
        parent,
        "Display DPI override",
        "Overrides the logical DPI (pixels-per-inch) the CERF guest display "
        "driver reports to the OS. It changes what the OS believes the screen "
        "density is - it most likely causes rendering artifacts and broken "
        "graphics.\n\n"
        "Known behaviour:\n"
        "• Restores VGA (2×) mode on Device Emulator ROMs.\n"
        "• Scales readable / printable text (documents, web pages) on older "
        "CE versions.\n"
        "• Works best on Alt-Controls (touch-style) ROMs."
    )


def show_bpp_help(parent: tk.Misc) -> None:
    show_info(
        parent,
        "Color depth override",
        "Some boards and guest additions allow to change BPP. Windows CE "
        "guest apps are often very picky.\n\n"
        "• Auto - Make CERF automatically pick depth per known values.\n"
        "• 8 bpp - Should be used for Windows CE 2.0.\n"
        "• 16 bpp - Known to work best for Windows CE 2.11-3 era.\n"
        "• 24 bpp - Known to work best for all CE eras.\n"
        "• 32 bpp - Supported by newer CE 2.11+ but often breaks rendering "
        "in guest apps."
    )


def show_color_scheme_help(parent: tk.Misc) -> None:
    show_info(
        parent,
        "Color scheme override",
        "Forces a fixed system color scheme onto the guest. Handy to colorize "
        "grayscale devices (which render everything in black and white) with a "
        "proper colored theme, or to restyle any CE desktop.\n\n"
        "It is applied by force and may refuse to work on some ROMs, because "
        "the approach is hacky rather than a supported OS feature."
    )


def show_guest_additions_help(parent: tk.Misc) -> None:
    """Open the Guest Additions article in the browser."""
    webbrowser.open(GUEST_ADDITIONS_URL)


def link_label(parent: tk.Misc, text: str, url: str) -> ttk.Label:
    lbl = ttk.Label(parent, text=text, foreground=theme.LINK_FG, cursor="hand2")
    lbl.bind("<Button-1>", lambda _e: webbrowser.open(url))
    return lbl


def _maybe_link(parent: tk.Misc, text: str, url: str) -> ttk.Label:
    """A clickable link when url is set, otherwise the same text as plain
    (non-clickable) label."""
    return link_label(parent, text, url) if url else ttk.Label(parent, text=text)


def show_source_thanks(parent: tk.Misc, source: DeviceSource) -> None:
    show_sources_thanks(parent, [source] if source is not None else [])


def show_sources_thanks(parent: tk.Misc, sources) -> None:
    distinct: list = []
    seen: set = set()
    for s in sources:
        if s is not None and s.has_links and s.name not in seen:
            seen.add(s.name)
            distinct.append(s)
    if not distinct:
        return

    dlg = tk.Toplevel(parent)
    dlg.title("ROM preservation")
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
                  text=f"This ROM bundle was preserved and provided by "
                       f"{source.name}.").pack(anchor="w")
        ask = ttk.Frame(body)
        ask.pack(anchor="w", pady=(6, 0))
        ttk.Label(ask, text="Would you like to ").pack(side="left")
        _maybe_link(ask, "pay them a visit", source.website).pack(side="left")
        ttk.Label(ask, text=" or ").pack(side="left")
        _maybe_link(ask, "support them", source.donate).pack(side="left")
        ttk.Label(ask, text="?").pack(side="left")
        if source.origin:
            link_label(body, "Source data link", source.origin).pack(anchor="w")

    btns = ttk.Frame(body)
    btns.pack(anchor="e", pady=(14, 0))
    ok = ttk.Button(btns, text="OK", command=dlg.destroy)
    ok.pack(side="left")
    ok.focus_set()
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
