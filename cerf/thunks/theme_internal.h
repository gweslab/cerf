/* Internal header shared between theme.cpp and theme_subclass.cpp.
   Not for inclusion outside the theme engine. */
#pragma once
#include <windows.h>
#include <commctrl.h>

/* WinCE system color count and desktop max */
#define WCE_NUM_SYSCOLORS 27
#define MAX_DESKTOP_SYSCOLORS 31

/* Themed color/brush accessors (defined in theme.cpp) */
HBRUSH GetThemedBrush(int color_idx);
COLORREF GetThemedColor(int color_idx);

/* Subclass ID shared between theme.cpp and theme_subclass.cpp */
#define THEME_SUBCLASS_ID 0xCE0F0002

/* ThemeSubclassProc (defined in theme_subclass.cpp, installed in theme.cpp) */
LRESULT CALLBACK ThemeSubclassProc(
    HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
    UINT_PTR subclassId, DWORD_PTR refData);
