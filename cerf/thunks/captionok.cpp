/* WS_EX_CAPTIONOKBTN support.
   The OK button is now drawn by PaintWinCENCArea() in theme.cpp as part of
   the unified WinCE NC area painting, and hit-tested by ThemeSubclassProc.
   These functions are kept as stubs for the Install/Remove interface. */
#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../log.h"
#include <commctrl.h>
#pragma comment(lib, "comctl32")

#define CAPTIONOK_SUBCLASS_ID 0xCE0F0001

LRESULT CALLBACK Win32Thunks::CaptionOkSubclassProc(
    HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam,
    UINT_PTR subclassId, DWORD_PTR refData)
{
    /* No-op — NC painting and hit-testing handled by ThemeSubclassProc */
    return DefSubclassProc(hwnd, msg, wParam, lParam);
}

void Win32Thunks::InstallCaptionOk(HWND hwnd) {
    /* OK button is tracked in captionok_hwnds and drawn by PaintWinCENCArea.
       Force NC recalculation to pick up the button. */
    SetWindowPos(hwnd, NULL, 0, 0, 0, 0,
        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_FRAMECHANGED);
    LOG(API, "[API] InstallCaptionOk(hwnd=%p)\n", hwnd);
}

void Win32Thunks::RemoveCaptionOk(HWND hwnd) {
    LOG(API, "[API] RemoveCaptionOk(hwnd=%p)\n", hwnd);
}
