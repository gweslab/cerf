from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from freedesktop_services import AppearanceMonitor
import ui_theme as theme

_WM_SETTINGCHANGE = 0x001A
_GWLP_WNDPROC = -4
_APPEARANCE_POLL_MS = 250
_TK_APPEARANCE_CHANGED = "<<AppearanceChanged>>"


class ThemeFollowMixin:
    def _install_theme_listener(self) -> None:
        self._old_wndproc = None
        self._appearance = None
        self._appearance_binding = None
        if sys.platform == "darwin":
            self._appearance_binding = self.bind(
                _TK_APPEARANCE_CHANGED, lambda _event: self._maybe_retheme(), add="+")
            return
        if sys.platform != "win32":
            self._appearance = AppearanceMonitor()
            self._appearance.start()
            self.after(_APPEARANCE_POLL_MS, self._poll_appearance)
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

    def _remove_theme_listener(self) -> None:
        old = getattr(self, "_old_wndproc", None)
        if old and sys.platform == "win32":
            try:
                theme.set_window_long(self._theme_hwnd, _GWLP_WNDPROC, old)
                self._old_wndproc = None
            except (OSError, AttributeError):
                pass
        binding, self._appearance_binding = getattr(self, "_appearance_binding", None), None
        if binding is not None:
            self.unbind(_TK_APPEARANCE_CHANGED, binding)
        appearance, self._appearance = self._appearance, None
        if appearance is not None:
            appearance.stop()

    def _theme_wndproc(self, hwnd, msg, wparam, lparam):
        if msg == _WM_SETTINGCHANGE:
            self.after_idle(self._maybe_retheme)
        if not self._old_wndproc:
            return ctypes.windll.user32.DefWindowProcW(hwnd, msg, wparam, lparam)
        return self._call_wndproc(self._old_wndproc, hwnd, msg, wparam, lparam)

    def _poll_appearance(self) -> None:
        if self._appearance is None:
            return
        if self._appearance.take_change():
            self._maybe_retheme()
        self.after(_APPEARANCE_POLL_MS, self._poll_appearance)

    def _maybe_retheme(self) -> None:
        if theme.refresh_palette(self):
            self._retheme()
