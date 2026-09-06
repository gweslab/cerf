"""GUI gate for large (>=300 MB) ROM-bundle / package downloads.

A flaky connection can fail a multi-hundred-MB or multi-GB download streamed
through the launcher. After the abandonware-license step, the GUI offers the
user a choice: keep downloading in-launcher, or download the ZIP themselves in
a browser / download manager. For the manual path the launcher pre-stages the
device directory, cerf.json, and local-manifest entry so the user only has to
unpack the ZIP. This is GUI-only - the CLI always streams in-process."""
from __future__ import annotations

import tkinter as tk
import webbrowser
from tkinter import ttk
from typing import List, Optional, Tuple

from bundles import BundleError, is_large_download
from device_state import DeviceBundle, PackageStatus, format_size
from ui_dialogs import (confirm_rom_license, show_dialog, show_error, show_info,
                        show_source_thanks)
import ui_theme as theme

_LAUNCHER = "launcher"
_MANUAL = "manual"
_CANCEL = "cancel"


def _ask_large(parent: tk.Misc, *, headline: str, link_url: str,
               instructions: str) -> str:
    """Modal launcher-vs-manual-vs-cancel dialog with a clickable download
    link and unpack instructions. Returns _LAUNCHER / _MANUAL / _CANCEL."""
    dlg = tk.Toplevel(parent)
    dlg.title("Large download")
    dlg.configure(bg=theme.BG)
    if parent.winfo_viewable():
        dlg.transient(parent)
    dlg.resizable(False, False)
    result = {"value": _CANCEL}

    body = ttk.Frame(dlg, padding=16)
    body.pack(fill="both", expand=True)
    ttk.Label(body, text=headline, wraplength=460, justify="left").pack(
        anchor="w", pady=(0, 10))

    link = ttk.Label(body, text=link_url, foreground=theme.LINK_FG, cursor="hand2",
                     wraplength=460, justify="left")
    link.bind("<Button-1>", lambda _e: webbrowser.open(link_url))
    link.pack(anchor="w", pady=(0, 10))

    ttk.Label(body, text=instructions, wraplength=460, justify="left").pack(
        anchor="w", pady=(0, 14))

    def choose(value: str) -> None:
        result["value"] = value
        dlg.destroy()

    btns = ttk.Frame(body)
    btns.pack(anchor="e")
    ttk.Button(btns, text="Continue download via launcher",
               command=lambda: choose(_LAUNCHER),
               style="Accent.TButton").pack(side="left", padx=(6, 0))
    ttk.Button(btns, text="Open download link in browser",
               command=lambda: choose(_MANUAL)).pack(side="left", padx=(6, 0))
    ttk.Button(btns, text="Cancel",
               command=lambda: choose(_CANCEL)).pack(side="left", padx=(6, 0))
    dlg.bind("<Escape>", lambda _e: choose(_CANCEL))

    dlg.update_idletasks()
    theme.apply_titlebar(dlg)
    w, h = dlg.winfo_reqwidth(), dlg.winfo_reqheight()
    x = parent.winfo_rootx() + (parent.winfo_width() - w) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
    dlg.geometry(f"+{max(0, x)}+{max(0, y)}")
    dlg.grab_set()
    parent.wait_window(dlg)
    return result["value"]


def gate_large_bundle(app, device: DeviceBundle) -> bool:
    remote = device.remote
    if not is_large_download(remote.archive_size):
        return True
    name = device.name
    verb = "update" if device.is_installed else "download"
    headline = (
        f"{device.meta.device_name or name} is a large {verb} "
        f"({format_size(remote.archive_size)}). On an unreliable connection "
        f"the in-launcher download can fail partway. You can let the launcher "
        f"download it (with progress), or download the ZIP yourself in a "
        f"browser or download manager:")
    instructions = (
        f"Choosing the browser download pre-creates devices/{name}/ with its "
        f"cerf.json and manifest entry now. When the download finishes, unpack "
        f"the ZIP so its files land directly in devices/{name}/, then refresh "
        f"the launcher.")
    choice = _ask_large(app, headline=headline,
                        link_url=remote.archive_url, instructions=instructions)
    if choice == _MANUAL:
        _manual_bundle(app, device)
    return choice == _LAUNCHER


def gate_bundle_download(app, device: DeviceBundle) -> bool:
    if not confirm_rom_license(app, device.meta.device_name or device.name,
                               app.manager.repo_abuse_contacts):
        return False
    show_source_thanks(app, device.meta.source)
    return gate_large_bundle(app, device)


def _manual_bundle(app, device: DeviceBundle) -> None:
    try:
        dir_name = app.manager.prepare_manual_install(device)
    except BundleError as exc:
        show_error(app, "Could not prepare manual download", str(exc))
        return
    webbrowser.open(device.remote.archive_url)
    app._reload_device_list()
    show_info(
        app, "Manual download started",
        f"Your browser is downloading the ZIP. The launcher created "
        f"devices/{dir_name}/ with its cerf.json.\n\n"
        f"When the download finishes, unpack the ZIP so its files land "
        f"directly in devices/{dir_name}/, then refresh the launcher.")


def gate_package_download(app, device: DeviceBundle, ps: PackageStatus) -> bool:
    """License + source credit + (for large packages) the launcher-vs-manual
    gate. Returns True to proceed with the in-launcher download; False when the
    user cancelled or chose the manual path (fully handled here)."""
    label = f"{ps.remote.name} ({device.meta.device_name or device.name})"
    if not confirm_rom_license(app, label, app.manager.repo_abuse_contacts):
        return False
    show_source_thanks(app, device.meta.source)
    if not is_large_download(ps.remote.archive_size):
        return True
    name = device.name
    verb = "update" if ps.installed else "download"
    headline = (
        f"{ps.remote.name} for {device.meta.device_name or name} is a large "
        f"{verb} ({format_size(ps.remote.archive_size)}). On an unreliable "
        f"connection the in-launcher download can fail partway. You can let "
        f"the launcher download it (with progress), or download the ZIP "
        f"yourself in a browser or download manager:")
    instructions = _package_manual_steps(name, ps)
    choice = _ask_large(app, headline=headline,
                        link_url=ps.remote.archive_url,
                        instructions=instructions)
    if choice == _LAUNCHER:
        return True
    if choice == _MANUAL:
        _manual_package(app, device, ps)
    return False


def _package_manual_steps(name: str, ps: PackageStatus) -> str:
    if ps.remote.is_directory:
        return (
            f"When the download finishes, unpack the ZIP so its contents fill "
            f"devices/{name}/{ps.remote.key}/, then refresh the launcher.")
    return (
        f"When the download finishes, unpack the ZIP and place "
        f"{ps.remote.key} into devices/{name}/, then refresh the launcher.")


def _manual_package(app, device: DeviceBundle, ps: PackageStatus) -> None:
    try:
        app.manager.prepare_manual_install_package(
            device.name, ps.remote.category, ps.remote.key)
    except BundleError as exc:
        show_error(app, "Could not prepare manual download", str(exc))
        return
    webbrowser.open(ps.remote.archive_url)
    app._reload_device_list()
    show_info(app, "Manual download started",
              f"Your browser is downloading the ZIP.\n\n"
              f"{_package_manual_steps(device.name, ps)}")


def filter_update_all_targets(
        app,
        rom_targets: List[DeviceBundle],
        pkg_targets: List[Tuple[DeviceBundle, PackageStatus]],
) -> Optional[Tuple[List[DeviceBundle],
                    List[Tuple[DeviceBundle, PackageStatus]]]]:
    """For 'Update all': when some targets are large, ask whether to update
    everything via the launcher or skip the large ones (so the user updates
    each individually, where the per-bundle manual option is offered). Returns
    the (possibly filtered) targets to proceed with, or None to cancel."""
    large_roms = [d for d in rom_targets if is_large_download(d.remote.archive_size)]
    large_pkgs = [(d, ps) for d, ps in pkg_targets
                  if is_large_download(ps.remote.archive_size)]
    if not large_roms and not large_pkgs:
        return rom_targets, pkg_targets

    lines = [f"  • {d.meta.device_name or d.name} "
             f"({format_size(d.remote.archive_size)})" for d in large_roms]
    lines += [f"  • {d.name}: {ps.remote.name} "
              f"({format_size(ps.remote.archive_size)})" for d, ps in large_pkgs]
    message = (
        "These updates are large (over 300 MB) and may be unreliable to "
        "download in bulk:\n\n" + "\n".join(lines) + "\n\n"
        "Update everything via the launcher, or skip the large ones and "
        "update each individually from the table (where you can choose a "
        "manual browser download)?")
    choice = show_dialog(app, "Update all", message,
                         buttons=("Update all via launcher",
                                  "Skip large ones", "Cancel"),
                         default="Cancel")
    if choice == "Update all via launcher":
        return rom_targets, pkg_targets
    if choice != "Skip large ones":
        return None
    rom_targets = [d for d in rom_targets
                   if not is_large_download(d.remote.archive_size)]
    pkg_targets = [(d, ps) for d, ps in pkg_targets
                   if not is_large_download(ps.remote.archive_size)]
    return rom_targets, pkg_targets
