"""GUI gate for large (>=300 MB) ROM-bundle / package downloads.

A flaky connection can fail a multi-hundred-MB or multi-GB download streamed
through the launcher. After the abandonware-license step, the GUI offers the
user a choice: keep downloading in-launcher, or download the ZIP themselves in
a browser / download manager. For the manual path the launcher pre-stages the
device directory, cerf.json, and local-manifest entry so the user only has to
unpack the ZIP. This is GUI-only - the CLI always streams in-process."""
from __future__ import annotations
from i18n import t

import tkinter as tk
import webbrowser
from tkinter import ttk
from typing import List, Optional, Tuple

from bundles import BundleError, is_large_download
from device_state import DeviceBundle, PackageStatus, format_size
from dialog_buttons import pack_actions
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
    dlg.title(t("launcher.ui_large_download.large_download"))
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
    pack_actions(btns, [
        (t("launcher.ui_large_download.continue_in_launcher"), lambda: choose(_LAUNCHER)),
        (t("launcher.ui_large_download.open_in_browser"), lambda: choose(_MANUAL)),
        (t("common.cancel"), lambda: choose(_CANCEL))])
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
    verb = t("launcher.ui_large_download.operation_update" if device.is_installed
             else "launcher.ui_large_download.operation_download")
    headline = (
        t('launcher.ui_large_download.value_is_a_large_verb_value2_on', value=device.meta.device_name or name, verb=verb, value2=format_size(remote.archive_size)))
    instructions = (
        t('launcher.ui_large_download.choosing_the_browser_download_pre_creates_devices', name=name, name2=name))
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
        show_error(app, t("launcher.ui_large_download.could_not_prepare_manual_download"), str(exc))
        return
    webbrowser.open(device.remote.archive_url)
    app._reload_device_list()
    show_info(
        app, t("launcher.ui_large_download.manual_download_started"),
        t('launcher.ui_large_download.your_browser_is_downloading_the_zip_the', dir_name=dir_name, dir_name2=dir_name))


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
    verb = t("launcher.ui_large_download.operation_update" if ps.installed
             else "launcher.ui_large_download.operation_download")
    headline = (
        t('launcher.ui_large_download.name_for_value_is_a_large_verb', name=ps.remote.name, value=device.meta.device_name or name, verb=verb, value2=format_size(ps.remote.archive_size)))
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
            t('launcher.ui_large_download.when_the_download_finishes_unpack_the_zip_2', name=name, key=ps.remote.key))
    return (
        t('launcher.ui_large_download.when_the_download_finishes_unpack_the_zip', key=ps.remote.key, name=name))


def _manual_package(app, device: DeviceBundle, ps: PackageStatus) -> None:
    try:
        app.manager.prepare_manual_install_package(
            device.name, ps.remote.category, ps.remote.key)
    except BundleError as exc:
        show_error(app, t("launcher.ui_large_download.could_not_prepare_manual_download"), str(exc))
        return
    webbrowser.open(ps.remote.archive_url)
    app._reload_device_list()
    show_info(app, t("launcher.ui_large_download.manual_download_started"),
              t('launcher.ui_large_download.your_browser_is_downloading_the_zip_value', value=_package_manual_steps(device.name, ps)))


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
    message = t("launcher.ui_large_download.bulk_update", items="\n".join(lines))
    update_label = t("launcher.ui_large_download.update_all_in_launcher")
    skip_label = t("launcher.ui_large_download.skip_large")
    choice = show_dialog(app, t("launcher.launcher_operations.update_all"), message,
                         buttons=(update_label, skip_label, t("common.cancel")),
                         default=t("common.cancel"))
    if choice == update_label:
        return rom_targets, pkg_targets
    if choice != skip_label:
        return None
    rom_targets = [d for d in rom_targets
                   if not is_large_download(d.remote.archive_size)]
    pkg_targets = [(d, ps) for d, ps in pkg_targets
                   if not is_large_download(ps.remote.archive_size)]
    return rom_targets, pkg_targets
