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

/* Custom hit-test code for the WinCE caption OK button */
#define HT_CAPTIONOK 0x0200

/* NC area painting and hit-testing (defined in theme_nc_paint.cpp) */
int PaintWinCENCArea(HWND hwnd);
LRESULT HitTestWinCECaption(HWND hwnd, POINT pt);

/* ThemeSubclassProc (defined in theme_subclass.cpp, installed in theme.cpp) */
LRESULT CALLBACK ThemeSubclassProc(
    HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
    UINT_PTR subclassId, DWORD_PTR refData);
