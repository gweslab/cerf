#!/usr/bin/env python3
"""CERF App Interaction Tool - Screenshot, click, type, and window management
for testing WinCE apps running under CERF.

Usage:
    python3 tools/interact.py screenshot [--file PATH] [--cerf]
    python3 tools/interact.py click X Y
    python3 tools/interact.py rclick X Y
    python3 tools/interact.py dclick X Y
    python3 tools/interact.py type "text to type"
    python3 tools/interact.py key KEYNAME [KEYNAME ...]
    python3 tools/interact.py combo KEY1+KEY2  (e.g. ctrl+a, alt+f4)
    python3 tools/interact.py windows
    python3 tools/interact.py focus HWND
    python3 tools/interact.py drag X1 Y1 X2 Y2

Screenshot is saved to screenshot.png in the project root by default.
"""

import sys
import os
import ctypes
import ctypes.wintypes as wt
import time
import argparse
import subprocess

# --- DPI Awareness (must be set before any Win32 calls) ---
try:
    ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
except Exception:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        pass

u32 = ctypes.windll.user32
k32 = ctypes.windll.kernel32

# Default screenshot path (project root)
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
DEFAULT_SCREENSHOT = os.path.join(PROJECT_ROOT, "tmp", "screenshot.png")

# --- Virtual Key Codes ---
VK_CODES = {
    'backspace': 0x08, 'tab': 0x09, 'enter': 0x0D, 'return': 0x0D,
    'shift': 0x10, 'ctrl': 0x11, 'control': 0x11, 'alt': 0x12, 'menu': 0x12,
    'pause': 0x13, 'capslock': 0x14, 'escape': 0x1B, 'esc': 0x1B,
    'space': 0x20, 'pageup': 0x21, 'pagedown': 0x22,
    'end': 0x23, 'home': 0x24,
    'left': 0x25, 'up': 0x26, 'right': 0x27, 'down': 0x28,
    'printscreen': 0x2C, 'insert': 0x2D, 'delete': 0x2E, 'del': 0x2E,
    'f1': 0x70, 'f2': 0x71, 'f3': 0x72, 'f4': 0x73,
    'f5': 0x74, 'f6': 0x75, 'f7': 0x76, 'f8': 0x77,
    'f9': 0x78, 'f10': 0x79, 'f11': 0x7A, 'f12': 0x7B,
    'lwin': 0x5B, 'rwin': 0x5C, 'apps': 0x5D,
}

KEYEVENTF_KEYUP = 0x0002

# --- Window Enumeration ---
WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)

def find_cerf_pids():
    """Find all cerf.exe process IDs."""
    result = subprocess.run(
        ['tasklist', '/fi', 'imagename eq cerf.exe', '/fo', 'csv', '/nh'],
        capture_output=True, text=True
    )
    pids = []
    for line in result.stdout.strip().split('\n'):
        line = line.strip()
        if not line or 'No tasks' in line or 'INFO' in line:
            continue
        parts = line.split(',')
        if len(parts) >= 2:
            pid_str = parts[1].strip('"')
            try:
                pids.append(int(pid_str))
            except ValueError:
                pass
    return pids

def get_window_info(hwnd):
    """Get detailed info about a window."""
    title_buf = ctypes.create_unicode_buffer(256)
    u32.GetWindowTextW(hwnd, title_buf, 256)
    cls_buf = ctypes.create_unicode_buffer(256)
    u32.GetClassNameW(hwnd, cls_buf, 256)
    rect = wt.RECT()
    u32.GetWindowRect(hwnd, ctypes.byref(rect))
    crect = wt.RECT()
    u32.GetClientRect(hwnd, ctypes.byref(crect))
    style = u32.GetWindowLongW(hwnd, -16)   # GWL_STYLE
    visible = bool(style & 0x10000000)      # WS_VISIBLE
    enabled = not bool(style & 0x08000000)  # WS_DISABLED

    return {
        'hwnd': hwnd,
        'title': title_buf.value,
        'class': cls_buf.value,
        'visible': visible,
        'enabled': enabled,
        'rect': (rect.left, rect.top, rect.right, rect.bottom),
        'size': (rect.right - rect.left, rect.bottom - rect.top),
        'client': (crect.right, crect.bottom),
        'center': ((rect.left + rect.right) // 2, (rect.top + rect.bottom) // 2),
        'style': style,
    }

def get_cerf_windows():
    """Get all windows belonging to cerf.exe processes."""
    pids = find_cerf_pids()
    if not pids:
        return []
    windows = []
    for pid in pids:
        def enum_cb(hwnd, _):
            wp = wt.DWORD()
            u32.GetWindowThreadProcessId(hwnd, ctypes.byref(wp))
            if wp.value == pid:
                windows.append(get_window_info(hwnd))
            return True
        u32.EnumWindows(WNDENUMPROC(enum_cb), 0)
    return windows

def get_direct_children(parent_hwnd):
    """Get direct child windows of a window."""
    children = []
    def enum_cb(hwnd, _):
        children.append(hwnd)
        return True
    u32.EnumChildWindows(parent_hwnd, WNDENUMPROC(enum_cb), 0)
    return [h for h in children if u32.GetParent(h) == parent_hwnd]

def get_cerf_window_bbox():
    """Get bounding box encompassing all visible cerf windows."""
    windows = get_cerf_windows()
    visible = [w for w in windows if w['visible'] and w['size'][0] > 0 and w['size'][1] > 0]
    if not visible:
        return None
    left = min(w['rect'][0] for w in visible)
    top = min(w['rect'][1] for w in visible)
    right = max(w['rect'][2] for w in visible)
    bottom = max(w['rect'][3] for w in visible)
    # Add small padding
    PAD = 5
    return (max(0, left - PAD), max(0, top - PAD), right + PAD, bottom + PAD)


def bring_cerf_to_foreground():
    """Find the main cerf window and bring it to the foreground.
    Called automatically before any mouse/keyboard interaction to prevent
    accidentally clicking on other windows."""
    windows = get_cerf_windows()
    visible = [w for w in windows if w['visible'] and w['size'][0] > 0 and w['size'][1] > 0]
    if not visible:
        print("WARNING: No visible cerf.exe windows found to foreground")
        return False

    # Find the largest visible window (likely the main app window)
    main_win = max(visible, key=lambda w: w['size'][0] * w['size'][1])
    hwnd = main_win['hwnd']

    # Use multiple methods to reliably bring to foreground
    u32.ShowWindow(hwnd, 9)  # SW_RESTORE (in case minimized)
    time.sleep(0.05)

    # AttachThreadInput trick for reliable SetForegroundWindow
    foreground_hwnd = u32.GetForegroundWindow()
    if foreground_hwnd != hwnd:
        fore_tid = u32.GetWindowThreadProcessId(foreground_hwnd, None)
        our_tid = k32.GetCurrentThreadId()
        if fore_tid != our_tid:
            u32.AttachThreadInput(our_tid, fore_tid, True)
        u32.SetForegroundWindow(hwnd)
        u32.BringWindowToTop(hwnd)
        if fore_tid != our_tid:
            u32.AttachThreadInput(our_tid, fore_tid, False)

    time.sleep(0.15)  # Let the window fully activate
    print(f"Foregrounded: {main_win['class']} \"{main_win['title']}\" (0x{hwnd:X})")
    return True


# ===== COMMANDS =====

def cmd_screenshot(args):
    """Take a screenshot."""
    from PIL import ImageGrab

    filepath = args.file or DEFAULT_SCREENSHOT

    if args.cerf:
        bbox = get_cerf_window_bbox()
        if bbox is None:
            print("ERROR: No visible cerf.exe windows found")
            return 1
        img = ImageGrab.grab(bbox=bbox)
        print(f"Captured cerf window region: {bbox}")
    else:
        img = ImageGrab.grab()
        print(f"Captured full screen: {img.size[0]}x{img.size[1]}")

    img.save(filepath)
    print(f"Saved to: {filepath}")
    return 0


def cmd_click(args):
    """Left-click at screen coordinates."""
    bring_cerf_to_foreground()
    x, y = args.x, args.y
    u32.SetCursorPos(x, y)
    time.sleep(0.05)
    u32.mouse_event(0x0002, 0, 0, 0, 0)  # LEFTDOWN
    time.sleep(0.02)
    u32.mouse_event(0x0004, 0, 0, 0, 0)  # LEFTUP
    print(f"Clicked at ({x}, {y})")
    return 0


def cmd_rclick(args):
    """Right-click at screen coordinates."""
    bring_cerf_to_foreground()
    x, y = args.x, args.y
    u32.SetCursorPos(x, y)
    time.sleep(0.05)
    u32.mouse_event(0x0008, 0, 0, 0, 0)  # RIGHTDOWN
    time.sleep(0.02)
    u32.mouse_event(0x0010, 0, 0, 0, 0)  # RIGHTUP
    print(f"Right-clicked at ({x}, {y})")
    return 0


def cmd_dclick(args):
    """Double-click at screen coordinates."""
    bring_cerf_to_foreground()
    x, y = args.x, args.y
    u32.SetCursorPos(x, y)
    time.sleep(0.05)
    u32.mouse_event(0x0002, 0, 0, 0, 0)  # LEFTDOWN
    time.sleep(0.02)
    u32.mouse_event(0x0004, 0, 0, 0, 0)  # LEFTUP
    time.sleep(0.05)
    u32.mouse_event(0x0002, 0, 0, 0, 0)  # LEFTDOWN
    time.sleep(0.02)
    u32.mouse_event(0x0004, 0, 0, 0, 0)  # LEFTUP
    print(f"Double-clicked at ({x}, {y})")
    return 0


def cmd_drag(args):
    """Click and drag from one position to another."""
    bring_cerf_to_foreground()
    x1, y1, x2, y2 = args.x1, args.y1, args.x2, args.y2
    u32.SetCursorPos(x1, y1)
    time.sleep(0.05)
    u32.mouse_event(0x0002, 0, 0, 0, 0)  # LEFTDOWN
    time.sleep(0.1)
    # Move in steps for smoother drag
    steps = 10
    for i in range(1, steps + 1):
        ix = x1 + (x2 - x1) * i // steps
        iy = y1 + (y2 - y1) * i // steps
        u32.SetCursorPos(ix, iy)
        time.sleep(0.02)
    time.sleep(0.05)
    u32.mouse_event(0x0004, 0, 0, 0, 0)  # LEFTUP
    print(f"Dragged from ({x1},{y1}) to ({x2},{y2})")
    return 0


def cmd_type(args):
    """Type text by simulating key presses."""
    bring_cerf_to_foreground()
    text = args.text
    for char in text:
        vk_scan = u32.VkKeyScanW(ord(char))
        if vk_scan == -1:
            # Character can't be typed via VkKeyScan, skip
            print(f"WARNING: Cannot type character: {repr(char)}")
            continue

        vk = vk_scan & 0xFF
        shift = bool(vk_scan & 0x100)
        ctrl = bool(vk_scan & 0x200)
        alt = bool(vk_scan & 0x400)

        if shift:
            u32.keybd_event(0x10, 0, 0, 0)  # VK_SHIFT down
        if ctrl:
            u32.keybd_event(0x11, 0, 0, 0)  # VK_CONTROL down
        if alt:
            u32.keybd_event(0x12, 0, 0, 0)  # VK_MENU down

        u32.keybd_event(vk, 0, 0, 0)           # key down
        time.sleep(0.01)
        u32.keybd_event(vk, 0, KEYEVENTF_KEYUP, 0)  # key up

        if alt:
            u32.keybd_event(0x12, 0, KEYEVENTF_KEYUP, 0)
        if ctrl:
            u32.keybd_event(0x11, 0, KEYEVENTF_KEYUP, 0)
        if shift:
            u32.keybd_event(0x10, 0, KEYEVENTF_KEYUP, 0)

        time.sleep(0.02)

    print(f"Typed: {repr(text)}")
    return 0


def cmd_key(args):
    """Press one or more named keys sequentially."""
    bring_cerf_to_foreground()
    for key_name in args.keys:
        key_lower = key_name.lower()
        if key_lower in VK_CODES:
            vk = VK_CODES[key_lower]
        elif len(key_name) == 1:
            # Single character - get VK code
            vk = u32.VkKeyScanW(ord(key_name)) & 0xFF
        else:
            print(f"ERROR: Unknown key: {key_name}")
            print(f"  Available keys: {', '.join(sorted(VK_CODES.keys()))}")
            return 1

        u32.keybd_event(vk, 0, 0, 0)
        time.sleep(0.02)
        u32.keybd_event(vk, 0, KEYEVENTF_KEYUP, 0)
        time.sleep(0.05)
        print(f"Pressed: {key_name}")
    return 0


def cmd_combo(args):
    """Press a key combination like ctrl+a, alt+f4, ctrl+shift+s."""
    bring_cerf_to_foreground()
    parts = args.combo.lower().split('+')
    if len(parts) < 2:
        print("ERROR: Combo must have at least 2 keys separated by +")
        return 1

    vk_list = []
    for part in parts:
        part = part.strip()
        if part in VK_CODES:
            vk_list.append(VK_CODES[part])
        elif len(part) == 1:
            vk_list.append(u32.VkKeyScanW(ord(part)) & 0xFF)
        else:
            print(f"ERROR: Unknown key in combo: {part}")
            return 1

    # Press all keys down
    for vk in vk_list:
        u32.keybd_event(vk, 0, 0, 0)
        time.sleep(0.02)

    # Release all keys in reverse
    for vk in reversed(vk_list):
        u32.keybd_event(vk, 0, KEYEVENTF_KEYUP, 0)
        time.sleep(0.02)

    print(f"Combo: {args.combo}")
    return 0


def print_window_tree(hwnd, indent=0):
    """Recursively print a window and its children with clickable coordinates."""
    info = get_window_info(hwnd)
    prefix = '  ' * indent
    vis = 'V' if info['visible'] else 'H'
    ena = '' if info['enabled'] else ' DIS'
    title = f' "{info["title"]}"' if info['title'] else ''
    l, t, r, b = info['rect']
    w, h = info['size']
    cx, cy = info['center']

    print(f'{prefix}[{vis}{ena}] {info["class"]}{title}')
    print(f'{prefix}  rect=({l},{t})-({r},{b}) size={w}x{h} center=({cx},{cy}) hwnd=0x{hwnd:X}')

    children = get_direct_children(hwnd)
    for child in children:
        print_window_tree(child, indent + 1)


def cmd_windows(args):
    """List all cerf.exe windows with clickable coordinates."""
    pids = find_cerf_pids()
    if not pids:
        print("cerf.exe is NOT running")
        return 1

    for pid in pids:
        print(f"cerf.exe PID={pid}")
        windows = []
        def enum_cb(hwnd, _):
            wp = wt.DWORD()
            u32.GetWindowThreadProcessId(hwnd, ctypes.byref(wp))
            if wp.value == pid:
                windows.append(get_window_info(hwnd))
            return True
        u32.EnumWindows(WNDENUMPROC(enum_cb), 0)

        if not windows:
            print("  No windows found")
            continue

        visible_count = sum(1 for w in windows if w['visible'])
        print(f"  Windows: {len(windows)} total, {visible_count} visible\n")

        for w in windows:
            if w['visible']:
                print(f"  --- Visible Window ---")
                print_window_tree(w['hwnd'], indent=1)
                print()
            else:
                print(f"  [hidden] class='{w['class']}' hwnd=0x{w['hwnd']:X}")
    return 0


def cmd_focus(args):
    """Focus/activate a window by HWND."""
    hwnd = int(args.hwnd, 16) if args.hwnd.startswith('0x') else int(args.hwnd)
    # Try to bring window to foreground
    u32.ShowWindow(hwnd, 9)  # SW_RESTORE
    u32.SetForegroundWindow(hwnd)
    u32.BringWindowToTop(hwnd)
    print(f"Focused window 0x{hwnd:X}")
    return 0


# ===== MAIN =====

def main():
    parser = argparse.ArgumentParser(description='CERF App Interaction Tool')
    sub = parser.add_subparsers(dest='command')

    # screenshot
    p_ss = sub.add_parser('screenshot', aliases=['ss'], help='Take a screenshot')
    p_ss.add_argument('--file', '-f', help=f'Output file (default: screenshot.png)')
    p_ss.add_argument('--cerf', '-c', action='store_true', help='Capture only cerf window region')

    # click
    p_click = sub.add_parser('click', help='Left-click at coordinates')
    p_click.add_argument('x', type=int, help='X screen coordinate')
    p_click.add_argument('y', type=int, help='Y screen coordinate')

    # rclick
    p_rclick = sub.add_parser('rclick', help='Right-click at coordinates')
    p_rclick.add_argument('x', type=int, help='X screen coordinate')
    p_rclick.add_argument('y', type=int, help='Y screen coordinate')

    # dclick
    p_dclick = sub.add_parser('dclick', help='Double-click at coordinates')
    p_dclick.add_argument('x', type=int, help='X screen coordinate')
    p_dclick.add_argument('y', type=int, help='Y screen coordinate')

    # drag
    p_drag = sub.add_parser('drag', help='Click and drag')
    p_drag.add_argument('x1', type=int)
    p_drag.add_argument('y1', type=int)
    p_drag.add_argument('x2', type=int)
    p_drag.add_argument('y2', type=int)

    # type
    p_type = sub.add_parser('type', help='Type text')
    p_type.add_argument('text', help='Text to type')

    # key
    p_key = sub.add_parser('key', help='Press named key(s)')
    p_key.add_argument('keys', nargs='+', help='Key name(s): enter, tab, escape, f1, etc.')

    # combo
    p_combo = sub.add_parser('combo', help='Press key combination')
    p_combo.add_argument('combo', help='Key combo like ctrl+a, alt+f4')

    # windows
    sub.add_parser('windows', aliases=['win'], help='List cerf windows')

    # focus
    p_focus = sub.add_parser('focus', help='Focus a window')
    p_focus.add_argument('hwnd', help='Window handle (hex with 0x prefix or decimal)')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 1

    cmd_map = {
        'screenshot': cmd_screenshot, 'ss': cmd_screenshot,
        'click': cmd_click,
        'rclick': cmd_rclick,
        'dclick': cmd_dclick,
        'drag': cmd_drag,
        'type': cmd_type,
        'key': cmd_key,
        'combo': cmd_combo,
        'windows': cmd_windows, 'win': cmd_windows,
        'focus': cmd_focus,
    }

    handler = cmd_map.get(args.command)
    if handler:
        return handler(args)
    else:
        parser.print_help()
        return 1


if __name__ == '__main__':
    sys.exit(main())
