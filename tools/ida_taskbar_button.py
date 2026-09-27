import ctypes
import ctypes.wintypes as wt
import os
import threading

import ida_kernwin
import ida_loader
import ida_pro

WS_EX_APPWINDOW = 0x00040000
WS_EX_NOACTIVATE = 0x08000000
WS_CAPTION = 0x00C00000
WS_SYSMENU = 0x00080000
WS_MINIMIZEBOX = 0x00020000
WS_CHILD = 0x40000000
WS_VISIBLE = 0x10000000
SS_NOPREFIX = 0x00000080
SW_SHOWMINNOACTIVE = 7
WM_SETFONT = 0x0030
DT_CALCRECT = 0x00000400
DT_NOPREFIX = 0x00000800
DEFAULT_GUI_FONT = 17
PADDING = 12
WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_SETICON = 0x0080
ICON_SMALL = 0
ICON_BIG = 1
CW_USEDEFAULT = ctypes.c_int(0x80000000).value
COLOR_BTNFACE = 15

LRESULT = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(LRESULT, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.UINT),
        ("style", wt.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wt.HINSTANCE),
        ("hIcon", wt.HICON),
        ("hCursor", wt.HICON),
        ("hbrBackground", wt.HBRUSH),
        ("lpszMenuName", wt.LPCWSTR),
        ("lpszClassName", wt.LPCWSTR),
        ("hIconSm", wt.HICON),
    ]


_user32 = ctypes.WinDLL("user32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_shell32 = ctypes.WinDLL("shell32", use_last_error=True)
_gdi32 = ctypes.WinDLL("gdi32", use_last_error=True)

_user32.GetDC.argtypes = [wt.HWND]
_user32.GetDC.restype = wt.HDC
_user32.ReleaseDC.argtypes = [wt.HWND, wt.HDC]
_user32.ReleaseDC.restype = ctypes.c_int
_user32.DrawTextW.argtypes = [wt.HDC, wt.LPCWSTR, ctypes.c_int, ctypes.POINTER(wt.RECT), wt.UINT]
_user32.DrawTextW.restype = ctypes.c_int
_user32.AdjustWindowRectEx.argtypes = [ctypes.POINTER(wt.RECT), wt.DWORD, wt.BOOL, wt.DWORD]
_user32.AdjustWindowRectEx.restype = wt.BOOL
_gdi32.GetStockObject.argtypes = [ctypes.c_int]
_gdi32.GetStockObject.restype = wt.HGDIOBJ
_gdi32.SelectObject.argtypes = [wt.HDC, wt.HGDIOBJ]
_gdi32.SelectObject.restype = wt.HGDIOBJ

_user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
_user32.RegisterClassExW.restype = wt.ATOM
_user32.CreateWindowExW.argtypes = [wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD,
                                    ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                    wt.HWND, wt.HMENU, wt.HINSTANCE, wt.LPVOID]
_user32.CreateWindowExW.restype = wt.HWND
_user32.DefWindowProcW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
_user32.DefWindowProcW.restype = LRESULT
_user32.ShowWindow.argtypes = [wt.HWND, ctypes.c_int]
_user32.ShowWindow.restype = wt.BOOL
_user32.SendMessageW.argtypes = [wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM]
_user32.SendMessageW.restype = LRESULT
_user32.GetMessageW.argtypes = [ctypes.POINTER(wt.MSG), wt.HWND, wt.UINT, wt.UINT]
_user32.GetMessageW.restype = ctypes.c_int
_user32.TranslateMessage.argtypes = [ctypes.POINTER(wt.MSG)]
_user32.TranslateMessage.restype = wt.BOOL
_user32.DispatchMessageW.argtypes = [ctypes.POINTER(wt.MSG)]
_user32.DispatchMessageW.restype = LRESULT
_user32.PostQuitMessage.argtypes = [ctypes.c_int]
_user32.PostQuitMessage.restype = None
_kernel32.GetModuleHandleW.argtypes = [wt.LPCWSTR]
_kernel32.GetModuleHandleW.restype = wt.HMODULE
_kernel32.GetModuleFileNameW.argtypes = [wt.HMODULE, wt.LPWSTR, wt.DWORD]
_kernel32.GetModuleFileNameW.restype = wt.DWORD
_shell32.ExtractIconW.argtypes = [wt.HINSTANCE, wt.LPCWSTR, wt.UINT]
_shell32.ExtractIconW.restype = wt.HICON

_CLASS_NAME = "CerfIdaTaskbarButton"
_wndproc = None


def _save_and_exit():
    ida_loader.save_database(ida_loader.get_path(ida_loader.PATH_TYPE_IDB), 0)
    ida_pro.qexit(0)
    return 1


def _on_message(hwnd, msg, wparam, lparam):
    if msg == WM_CLOSE:
        ida_kernwin.execute_sync(_save_and_exit, ida_kernwin.MFF_WRITE | ida_kernwin.MFF_NOWAIT)
        return 0
    if msg == WM_DESTROY:
        _user32.PostQuitMessage(0)
        return 0
    return _user32.DefWindowProcW(hwnd, msg, wparam, lparam)


def _ida_icon():
    buf = ctypes.create_unicode_buffer(1024)
    _kernel32.GetModuleFileNameW(None, buf, len(buf))
    return _shell32.ExtractIconW(None, os.path.join(os.path.dirname(buf.value), "ida.exe"), 0)


def _text_size(text, font):
    hdc = _user32.GetDC(None)
    old = _gdi32.SelectObject(hdc, font)
    rc = wt.RECT()
    _user32.DrawTextW(hdc, text, -1, ctypes.byref(rc), DT_CALCRECT | DT_NOPREFIX)
    _gdi32.SelectObject(hdc, old)
    _user32.ReleaseDC(None, hdc)
    return rc.right, rc.bottom


def _run(title, path):
    global _wndproc
    hinst = _kernel32.GetModuleHandleW(None)
    _wndproc = WNDPROC(_on_message)
    icon = _ida_icon()
    text = "CERF development window\r\nClose to kill this instance.\r\n" + path
    font = _gdi32.GetStockObject(DEFAULT_GUI_FONT)
    text_w, text_h = _text_size(text, font)
    style = WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX
    ex_style = WS_EX_NOACTIVATE | WS_EX_APPWINDOW
    frame = wt.RECT(0, 0, text_w + 2 * PADDING, text_h + 2 * PADDING)
    _user32.AdjustWindowRectEx(ctypes.byref(frame), style, False, ex_style)

    wc = WNDCLASSEXW()
    wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
    wc.lpfnWndProc = _wndproc
    wc.hInstance = hinst
    wc.hIcon = icon
    wc.hbrBackground = wt.HBRUSH(COLOR_BTNFACE + 1)
    wc.lpszClassName = _CLASS_NAME
    wc.hIconSm = icon
    if not _user32.RegisterClassExW(ctypes.byref(wc)):
        raise ctypes.WinError(ctypes.get_last_error())

    hwnd = _user32.CreateWindowExW(ex_style, _CLASS_NAME, title, style,
                                   CW_USEDEFAULT, CW_USEDEFAULT,
                                   frame.right - frame.left, frame.bottom - frame.top,
                                   None, None, hinst, None)
    if not hwnd:
        raise ctypes.WinError(ctypes.get_last_error())
    label = _user32.CreateWindowExW(0, "STATIC", text, WS_CHILD | WS_VISIBLE | SS_NOPREFIX,
                                    PADDING, PADDING, text_w, text_h, hwnd, None, hinst, None)
    if not label:
        raise ctypes.WinError(ctypes.get_last_error())
    _user32.SendMessageW(label, WM_SETFONT, font, False)
    _user32.SendMessageW(hwnd, WM_SETICON, ICON_BIG, icon)
    _user32.SendMessageW(hwnd, WM_SETICON, ICON_SMALL, icon)
    _user32.ShowWindow(hwnd, SW_SHOWMINNOACTIVE)

    msg = wt.MSG()
    while _user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
        _user32.TranslateMessage(ctypes.byref(msg))
        _user32.DispatchMessageW(ctypes.byref(msg))


def start(title, path):
    threading.Thread(target=_run, args=(title, path), daemon=True).start()
