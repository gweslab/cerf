from __future__ import annotations

import ctypes
import queue
import sys
import threading
import tkinter as tk
from concurrent.futures import Future
from ctypes import wintypes
from pathlib import Path
from tkinter import ttk
from typing import Callable, List, Optional, Tuple

from app_paths import resolve_icon, resolve_icons_dir, resolve_version
from device_card_list import DeviceCardList
from device_state import (DeviceBundle, SAVED_STATE_SCREENSHOT_FILENAME,
                          STATE_IMAGE_FILENAME, running_status, saved_state_info)
from device_model import TreeSelection
from download_window import DownloadWindow
from feedback_window import FeedbackWindow
from toolbar import Toolbar
from details_panel import DetailsPanel
from config_preview import ConfigPreviewPanel
from launcher_spawn import SpawnMixin
from launcher_operations import OperationsMixin
from launcher_properties import PropertiesMixin
from launcher_refresh import RefreshMixin
from saved_state_warning import SavedStateEditWarning
from new_device_wizard import NewDeviceWizard
from settings_dialog import SettingsDialog
from user_device_create import UserDeviceSpec
from operations import BundleManager
from screen_geometry import fit_geometry
from preview_tile import PreviewTile
from status_bar import StatusBar
from cerf_user_json import write_user_meta_name
from ui_dialogs import (ask_text, ask_yesno, confirm_rom_license,
                        open_device_directory, show_error, show_info,
                        show_sources_thanks)
from ui_large_download import gate_large_bundle
from ui_scroll import ScrollColumn
from update_check import UpdateCheck
import ui_theme as theme


_WM_SETTINGCHANGE = 0x001A
_GWLP_WNDPROC = -4


class LauncherApp(OperationsMixin, RefreshMixin, SpawnMixin, PropertiesMixin,
                  tk.Tk):
    def __init__(self, manager: BundleManager, cerf_exe: Optional[Path],
                 upgraded: bool = False):
        super().__init__()
        self.manager = manager
        self.cerf_exe = cerf_exe
        self.update_check = UpdateCheck(self)
        version = resolve_version()
        self.title(f"CE Runtime Foundation Launcher {version}" if version else "CE Runtime Foundation Launcher")

        try:
            dpi = float(self.winfo_fpixels("1i"))
            self.tk.call("tk", "scaling", dpi / 72.0)
        except tk.TclError:
            dpi = 96.0

        scale = max(1.0, dpi / 96.0)
        self.minsize(int(500 * scale), int(300 * scale))

        icon = resolve_icon()
        if icon is not None:
            try:
                self.iconbitmap(default=str(icon))
            except tk.TclError:
                pass

        theme.apply_theme(self)

        self.progress_queue: "queue.Queue[tuple[str, int, Optional[int]]]" = queue.Queue()
        self.cancel_event = threading.Event()
        self.busy = False
        self.catalog_loading = False
        self._was_running = False
        self._verbose_devices = set()
        self._saved_state_warning = SavedStateEditWarning(self)

        self._build_ui()
        theme.apply_titlebar(self)
        fit_geometry(self, int(1100 * scale), int(640 * scale))
        self._install_theme_listener()
        self._pump_progress()
        self.manager.load_local()
        self._reload_device_list()
        self.after(50, lambda: self._refresh_manifest())
        self.after(50, self.update_check.start)
        self.after(50, self._poll_runtime)
        if upgraded:
            self.after(200, lambda: show_info(
                self, "Upgrade complete",
                f"CE Runtime Foundation has been upgraded to {version}."
                if version
                else "CE Runtime Foundation has been upgraded."))

        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        self.status_bar = StatusBar(
            self, on_search=lambda: self.tree_panel.toggle_search())
        for seq in ("<Control-f>", "<Control-F>"):
            self.bind(seq, lambda _e: self.tree_panel.toggle_search())

        self.toolbar = Toolbar(self, resolve_icons_dir(),
                               self.manager.devices_dir,
                               on_new=self._open_new_wizard,
                               on_properties=lambda: self._open_properties(),
                               on_remove_selected=self._delete_selected,
                               on_discard_selected=self._discard_state,
                               on_launch=self._launch,
                               on_settings=self._open_settings,
                               on_about=self._open_about,
                               on_feedback=self._open_feedback)
        self.toolbar.frame.pack(fill="x", side="top")
        self.split = self.toolbar.start

        outer = ttk.Frame(self)
        outer.pack(fill="both", expand=True)

        try:
            pscale = max(1.0, float(self.winfo_fpixels("1i")) / 96.0)
        except tk.TclError:
            pscale = 1.0

        paned = tk.PanedWindow(outer, orient="horizontal", bg=theme.BORDER, bd=0,
                               sashwidth=1, sashpad=0, sashrelief="flat",
                               showhandle=False, opaqueresize=True)
        paned.pack(fill="both", expand=True)
        self.paned = paned

        left_pane = ttk.Frame(paned, padding=(8, 8, 0, 0))
        left_pane.rowconfigure(0, weight=1)
        left_pane.columnconfigure(0, weight=1)
        self.tree_panel = DeviceCardList(
            left_pane,
            on_select=self._on_tree_select,
            on_activate=self._on_tree_activate,
            devices_dir=self.manager.devices_dir,
            icons_dir=resolve_icons_dir(),
            on_context=self._on_right_click)

        right = ttk.Frame(paned)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)

        paned.add(left_pane, minsize=int(420 * pscale), stretch="always")
        paned.add(right, minsize=int(300 * pscale), width=int(384 * pscale),
                  stretch="never")

        self.preview = PreviewTile(right, self.manager.devices_dir,
                                   int(300 * pscale), int(188 * pscale),
                                   int(24 * pscale), theme.BG, box_always=True,
                                   on_click=self._launch)
        self.preview.canvas.grid(row=0, column=0, columnspan=2, sticky="n",
                                 pady=8)

        def on_width(width: int) -> None:
            self.details.set_wraplength(max(120, width - 24))
            self.config_preview.set_wraplength(max(120, width - 24))
        self.scroll = ScrollColumn(right, width=int(340 * pscale),
                                   on_width_changed=on_width)
        self.scroll.grid(row=1, column=0, sticky="nsew")

        inner = self.scroll.inner
        self.details = DetailsPanel(inner, resolve_icons_dir(), self.manager.devices_dir,
                                    bind_wheel=self.scroll.bind_wheel,
                                    on_package_action=self._package_action)

        self.config_preview = ConfigPreviewPanel(
            inner, first_row=4, on_open=self._open_properties,
            bind_wheel=self.scroll.bind_wheel)

        self.scroll.bind_wheel(inner)

        self.empty_frame = ttk.Frame(outer)
        empty_center = ttk.Frame(self.empty_frame)
        empty_center.place(relx=0.5, rely=0.5, anchor="center")
        ttk.Label(empty_center, text="No devices yet",
                  font=("Segoe UI", 16, "bold")).pack()
        ttk.Button(empty_center, text="＋  New", style="Accent.TButton",
                   command=self._open_new_wizard).pack(pady=(14, 0))

    def _update_empty_state(self) -> None:
        if any(d.is_installed for d in self.tree_panel.devices):
            self.empty_frame.pack_forget()
            self.paned.pack(fill="both", expand=True)
        else:
            self.paned.pack_forget()
            self.empty_frame.pack(fill="both", expand=True)

    def _set_busy(self, busy: bool, label: str = "") -> None:
        self.busy = busy
        self.tree_panel.set_busy(busy)
        self.toolbar.set_busy(busy)
        self.split.set_enabled(not busy)
        if busy:
            self.status_bar.set_status(label or "Working…")
        else:
            self.status_bar.set_status("Ready.")
            self.status_bar.reset_progress()
        self._refresh_selection_state()

    def _set_catalog_loading(self, loading: bool, label: str = "") -> None:
        self.catalog_loading = loading
        if loading:
            self.status_bar.set_status(label or "Fetching bundle catalog…")
        elif not self.busy:
            self.status_bar.set_status("Ready.")
        self._refresh_selection_state()

    def _await_future(self, future: Future, done: Callable[[Optional[BaseException]], None]) -> None:
        def poll() -> None:
            if future.done():
                done(future.exception())
            else:
                self.after(50, poll)
        self.after(50, poll)

    def _progress_cb(self, label: str, done: int, total: Optional[int]) -> None:
        self.progress_queue.put((label, done, total))

    def _pump_progress(self) -> None:
        try:
            while True:
                label, done, total = self.progress_queue.get_nowait()
                self.status_bar.set_status(label)
                self.status_bar.show_progress(done, total)
        except queue.Empty:
            pass
        self.after(50, self._pump_progress)

    def _reload_device_list(self) -> None:
        self.tree_panel.reload(self.manager.list_devices())
        self._update_empty_state()
        self._on_tree_select(self.tree_panel.selection())

    def _running_status_for(self, d: Optional[DeviceBundle]):
        if d is None or not d.is_installed:
            return None
        return running_status(self.manager.devices_dir / d.name)

    def _poll_runtime(self) -> None:
        self.tree_panel.update_runtime()
        sel = self.tree_panel.selection()
        running = self._running_status_for(sel.device) is not None
        if self._was_running and not running and sel.device is not None:
            self._show_config(sel.device)
        self._was_running = running
        self.split.set_running(running)
        self.preview.refresh()
        self._refresh_selection_state()
        self.after(2500, self._poll_runtime)

    def _install_theme_listener(self) -> None:
        self._old_wndproc = None
        if sys.platform != "win32":
            return
        try:
            user32 = ctypes.windll.user32
            hwnd = theme.window_hwnd(self)
            self._theme_hwnd = hwnd
            lresult = ctypes.c_ssize_t
            self._wndproc_type = ctypes.WINFUNCTYPE(
                lresult, wintypes.HWND, wintypes.UINT,
                ctypes.c_size_t, ctypes.c_ssize_t)
            self._wndproc = self._wndproc_type(self._theme_wndproc)
            self._call_wndproc = user32.CallWindowProcW
            self._call_wndproc.restype = lresult
            self._call_wndproc.argtypes = [
                ctypes.c_void_p, wintypes.HWND, wintypes.UINT,
                ctypes.c_size_t, ctypes.c_ssize_t]
            self._old_wndproc = theme.set_window_long(
                hwnd, _GWLP_WNDPROC,
                ctypes.cast(self._wndproc, ctypes.c_void_p))
        except (OSError, AttributeError):
            self._old_wndproc = None

    def _theme_wndproc(self, hwnd, msg, wparam, lparam):
        if msg == _WM_SETTINGCHANGE:
            self.after_idle(self._maybe_retheme)
        if not self._old_wndproc:
            return ctypes.windll.user32.DefWindowProcW(hwnd, msg, wparam, lparam)
        return self._call_wndproc(self._old_wndproc, hwnd, msg, wparam, lparam)

    def _maybe_retheme(self) -> None:
        if theme.refresh_palette():
            self._retheme()

    def _retheme(self) -> None:
        theme.apply_theme(self)
        theme.apply_titlebar(self)
        self.paned.config(bg=theme.BORDER)
        self.scroll.retheme()
        self.details.retheme()
        self.config_preview.retheme()
        self.toolbar.retheme()
        self.split.retheme()
        self.status_bar.retheme()
        self.preview.retheme(theme.BG)
        self.tree_panel.retheme()

    def _open_new_wizard(self) -> None:
        if self.busy:
            return
        NewDeviceWizard(self, resolve_icons_dir(), self.manager.devices_dir,
                        on_download_roms=self._open_download_window,
                        on_create=self._create_user_device)

    def _open_settings(self) -> None:
        SettingsDialog(self, on_update_channel_changed=self.update_check.start)

    def _open_feedback(self) -> None:
        FeedbackWindow(self)

    def _create_user_device(self, spec: UserDeviceSpec) -> None:
        if self.busy:
            return
        self._set_busy(True, f"Creating {spec.name}…")
        f = self.manager.submit_create_user_device(
            spec, progress=self._progress_cb, cancel_event=self.cancel_event)

        def done(exc: Optional[BaseException]) -> None:
            self._after_op(exc, f"Created {spec.name}")
            if exc is None:
                self.tree_panel.select_device(spec.name)
        self._await_future(f, done)

    def _open_download_window(self) -> None:
        if self.busy or self.catalog_loading:
            return
        DownloadWindow(self, self.tree_panel.devices, self._download_queue,
                       self.manager.repo_abuse_contacts,
                       reload_fn=self._reload_download_sources,
                       download_places=self.manager.download_places)

    def _download_queue(self, keys: List[str]) -> None:
        if self.busy or not keys:
            return
        by_key = {d.key: d for d in self.tree_panel.devices}
        targets = [by_key[k] for k in keys
                   if k in by_key and not by_key[k].is_installed]
        if not targets:
            return
        label = ((targets[0].meta.device_name or targets[0].name)
                 if len(targets) == 1 else f"{len(targets)} ROMs")
        if not confirm_rom_license(self, label,
                                   self.manager.repo_abuse_contacts):
            return
        show_sources_thanks(self, [d.meta.source for d in targets])
        stream = [d for d in targets if gate_large_bundle(self, d)]
        if not stream:
            self._reload_device_list()
            return
        self._set_busy(True, f"Downloading {len(stream)} item(s)…")
        work: List[Tuple[str, Callable[[], Future]]] = [
            (d.name, lambda dev=d: self.manager.submit_install(
                dev, progress=self._progress_cb, cancel_event=self.cancel_event))
            for d in stream]
        self._run_sequence(work)

    def _package_action(self, d: DeviceBundle, ps, action: str) -> None:
        if self.busy:
            return
        if action == "install":
            self._download_package(d, ps)
        elif action == "delete":
            self._delete_package(d, ps)

    def _discard_state(self) -> None:
        sel = self.tree_panel.selection()
        d = sel.device
        if self.busy or d is None or not d.is_installed:
            return
        if self._running_status_for(d) is not None:
            return
        device_dir = self.manager.devices_dir / d.name
        if saved_state_info(device_dir) is None:
            return
        name = d.meta.device_name or d.name
        if not ask_yesno(self, "Delete saved state",
                         f"Delete the saved state for {name}?\n"
                         f"This cannot be undone."):
            return
        try:
            for fn in (STATE_IMAGE_FILENAME, SAVED_STATE_SCREENSHOT_FILENAME):
                p = device_dir / fn
                if p.exists():
                    p.unlink()
        except OSError as exc:
            show_error(self, "Delete failed",
                       f"Could not delete the saved state:\n{exc}")
        self._reload_device_list()

    def _rename_device(self, d: DeviceBundle) -> None:
        """Rename = the cerf-user.json meta.name override. The device
        directory name never changes (mirrors VMware/VirtualBox)."""
        current = d.meta.name or (d.meta.device_name or d.name)
        new = ask_text(self, "Rename device",
                       "Display name (leave empty to reset):",
                       initial=current)
        if new is None:
            return
        try:
            write_user_meta_name(self.manager.devices_dir / d.name, new)
        except OSError as exc:
            show_error(self, "Rename failed", str(exc))
        self._reload_device_list()

    def _open_device_folder(self, d: DeviceBundle) -> None:
        open_device_directory(self, self.manager.devices_dir / d.name)

    def _on_right_click(self, event: tk.Event) -> None:
        if self.busy:
            return
        sel = self.tree_panel.selection()
        if sel.kind != "device" or sel.device is None:
            return
        d = sel.device
        menu = tk.Menu(self, tearoff=0)
        running = self._running_status_for(d) is not None
        menu.add_command(label="Show CERF" if running else "Start", command=self._launch)
        if saved_state_info(self.manager.devices_dir / d.name) is not None:
            menu.add_command(label="Discard saved state",
                             command=self._discard_state,
                             state="disabled" if running else "normal")
        if d.has_update or d.has_cerf_json_update:
            menu.add_command(label="Update", command=self._update_selected)
        menu.add_separator()
        menu.add_command(label="Open device directory",
                         command=lambda: self._open_device_folder(d))
        menu.add_separator()
        menu.add_command(label="Remove", command=self._delete_selected,
                         state="disabled" if running else "normal")
        menu.add_command(label="Rename…",
                         command=lambda: self._rename_device(d))
        menu.add_separator()
        menu.add_command(label="Properties…",
                         command=lambda: self._open_properties())
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _on_tree_select(self, sel: TreeSelection) -> None:
        if sel.kind == "device" and sel.device is not None:
            self.details.show_device(sel.device)
            self._show_config(sel.device)
            self.split.set_device(sel.device)
            self.split.set_running(self._running_status_for(sel.device) is not None)
            self.preview.set_device(sel.device)
        self._refresh_selection_state()

    def _on_tree_activate(self, sel: TreeSelection) -> None:
        if sel.kind == "device":
            self._launch()

    def _refresh_selection_state(self) -> None:
        sel = self.tree_panel.selection()
        if self.busy:
            self.status_bar.set_bundle_updates(0, self._update_all)
            return
        d = sel.device
        running = self._running_status_for(d) is not None
        updateable = 0 if self.catalog_loading else sum(
            1 for x in self.tree_panel.devices
            if x.has_update or x.has_cerf_json_update or x.has_package_updates)
        self.status_bar.set_bundle_updates(updateable, self._update_all)
        if sel.kind == "device" and d is not None:
            can_discard = (saved_state_info(self.manager.devices_dir / d.name)
                           is not None and not running)
            self.toolbar.set_selection_enabled(d.is_installed,
                                               d.is_installed and not running,
                                               can_discard)
        else:
            self.toolbar.set_selection_enabled(False, False, False)
        self.details.set_addons_enabled(not running)
        self.split.set_enabled(d is not None and self.cerf_exe is not None)

    def _on_close(self) -> None:
        old = getattr(self, "_old_wndproc", None)
        if old and sys.platform == "win32":
            try:
                theme.set_window_long(self._theme_hwnd, _GWLP_WNDPROC, old)
                self._old_wndproc = None
            except (OSError, AttributeError):
                pass
        self.cancel_event.set()
        self.manager.shutdown()
        self.destroy()
