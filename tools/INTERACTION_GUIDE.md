# CERF App Interaction Guide

## Overview

The `tools/interact.py` script provides screenshot, mouse, and keyboard interaction
capabilities for testing WinCE apps running under CERF. It uses Win32 API via ctypes
(no external dependencies beyond PIL and pywin32).

**CRITICAL RULE**: After EVERY mouse/keyboard interaction, take a screenshot and verify
the result before proceeding. Never chain multiple interactions without verification.

## Quick Reference

```bash
# Screenshot (saved to screenshot.png in project root)
python3 tools/interact.py screenshot           # full screen
python3 tools/interact.py screenshot --cerf    # only cerf window region
python3 tools/interact.py screenshot -f path   # custom output path

# Mouse
python3 tools/interact.py click X Y            # left click
python3 tools/interact.py rclick X Y           # right click
python3 tools/interact.py dclick X Y           # double click
python3 tools/interact.py drag X1 Y1 X2 Y2    # click and drag

# Keyboard
python3 tools/interact.py key enter            # press named key
python3 tools/interact.py key tab tab enter    # press multiple keys
python3 tools/interact.py type "hello"         # type text
python3 tools/interact.py combo ctrl+a         # key combination

# Window management
python3 tools/interact.py windows              # list cerf windows with coordinates
python3 tools/interact.py focus 0xHWND         # focus specific window
```

## Step-by-Step Interaction Workflow

### 1. Launch the app
```bash
cd /c/Users/yanet/projects/cerf
./build/Release/x64/cerf.exe --flush-outputs path/to/app.exe > /tmp/app_log.txt 2>&1 &
sleep 5
```

### 2. Enumerate windows to understand UI structure
```bash
python3 tools/interact.py windows
```
This prints the full window tree with:
- Window class and title
- Screen coordinates: `rect=(left,top)-(right,bottom)`
- **Center coordinates**: `center=(x,y)` - use these for clicking
- Window handle: `hwnd=0xXXXX`
- Visibility and enabled state

### 3. Take a screenshot to see the current state
```bash
python3 tools/interact.py screenshot
```
Then read `screenshot.png` to see the app visually.

### 4. Interact (click, type, etc.)
```bash
python3 tools/interact.py click 500 300
```
The tool automatically brings the cerf window to the foreground before every
mouse/keyboard action.

### 5. ALWAYS verify with another screenshot
```bash
python3 tools/interact.py screenshot
```
Read the screenshot and verify the interaction had the expected effect.

### 6. Clean up when done
```bash
taskkill //f //im cerf.exe
```

## Coordinate System

- All coordinates are **screen coordinates** (absolute pixel positions on the monitor)
- The `windows` command shows exact screen coordinates for every control
- Use the `center=(x,y)` values from `windows` output for reliable clicking
- For items not listed in the window tree (e.g., ListView items), estimate from
  the screenshot or use keyboard navigation

## Tips for Reliable Interaction

### Prefer window tree coordinates over visual estimation
The `windows` command gives you exact coordinates for buttons, checkboxes, etc.
Always use these when available rather than guessing from the screenshot.

### Use keyboard for list navigation
For ListViews and other list controls where items aren't in the window tree:
1. Click somewhere in the list to give it focus
2. Use `key up`, `key down`, `key home`, `key end` to navigate
3. Use `key enter` to activate/open the selected item
4. Use letter keys to jump to items starting with that letter

### Handle modal dialogs
Modal dialogs are separate top-level windows. The `windows` command shows them
with their own control tree. The main app window will show as `[V DIS]` (disabled)
while a modal dialog is open.

**Important**: `click` and `key` commands auto-foreground the **main** cerf window,
which steals focus from the dialog. To interact with a modal dialog, use `focus`
first to target it by hwnd, then immediately run the click/key:
```bash
python3 tools/interact.py focus 0xHWND && python3 tools/interact.py click X Y
python3 tools/interact.py focus 0xHWND && python3 tools/interact.py key enter
```

### Escape closes most dialogs
```bash
python3 tools/interact.py focus 0xHWND && python3 tools/interact.py key escape
```

## Available Key Names

backspace, tab, enter/return, shift, ctrl/control, alt/menu, pause, capslock,
escape/esc, space, pageup, pagedown, end, home, left, up, right, down,
printscreen, insert, delete/del, f1-f12, lwin, rwin, apps

## Test Apps

- `tmp/arm_test_apps/solitare.exe` - Solitaire (cards, options dialog with checkboxes)
- `tmp/arm_test_apps/chearts.exe` - Hearts card game
- `tmp/arm_test_apps/Zuma-arm.exe` - Zuma game
- `C:\Users\yanet\Downloads\WinCE6_Emulator\Optional Programs\Total Commander\cecmd.exe` - File manager (dual pane, ListView)
