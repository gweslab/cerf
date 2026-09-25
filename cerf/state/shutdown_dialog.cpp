#define NOMINMAX
#include "shutdown_dialog.h"

#include "../core/cerf_emulator.h"
#include "../core/config_loader.h"
#include "../core/device_config.h"
#include "../cpu/emulated_memory.h"
#include "../host/dialog_band.h"
#include "../host/host_dark_mode.h"
#include "../host/host_dpi.h"
#include "../host/host_window.h"
#include "../version.h"

#include <commctrl.h>
#include <cstdio>

REGISTER_SERVICE(ShutdownDialog);

namespace {
constexpr wchar_t kClass[] = L"CerfShutdownDlg";

constexpr UINT kTimerId = 1;
constexpr int  kSeconds = 15;
constexpr int  kTotalMs = kSeconds * 1000;
constexpr UINT kTickMs  = 15;

constexpr int kContentH   = 244;
constexpr int kIconX      = 16;
constexpr int kIconDy     = 14;
constexpr int kIconSize   = 32;
constexpr int kTextX      = 60;
constexpr int kIntroDy    = 16;
constexpr int kAskDy      = 44;
constexpr int kComboDy    = 64;
constexpr int kComboH     = 26;
constexpr int kBlockDy    = 96;
constexpr int kRowH       = 22;
constexpr int kDescH      = 92;
constexpr int kBarDy      = 52;
constexpr int kBarH       = 16;
constexpr int kBtnW       = 88;
constexpr int kBtnH       = 28;
constexpr int kBtnGap     = 8;
constexpr int kMarginR    = 20;
constexpr int kBtnBottom  = 44;

enum : int { IDC_ACTION = 3000, IDC_SAVE, IDC_SAVE_LINK, IDC_REMEMBER, IDC_DESC };

constexpr wchar_t kSaveLinkMarkup[] =
    L"<a href=\"https://cerf.cx/hibernation-warning\">only for CERF v"
    CERF_VERSION_WSTR L"</a>";

constexpr wchar_t kSaveTail[] = L")";

constexpr wchar_t kSoftText[] =
    L"The guest operating system restarts and keeps everything in RAM, so the "
    L"object store and any open data survive.\r\n\r\n"
    L"A ROM that does not support a warm start can still clear that data itself.";

constexpr wchar_t kHardText[] =
    L"All guest RAM is wiped and the operating system starts with no earlier "
    L"context, the same as a battery pull.\r\n\r\n"
    L"Data that lives in persistent storage - flash, NAND or a disk image - is "
    L"not touched.";
}  /* namespace */

int ShutdownDialog::SelectedAction() const {
    const LRESULT sel = SendMessageW(combo_, CB_GETCURSEL, 0, 0);
    return sel == CB_ERR ? 0 : (int)sel;
}

int ShutdownDialog::BarFillWidth() const {
    const RECT bar = BarRect();
    return (bar.right - bar.left - 2) * remaining_ms_ / kTotalMs;
}

int ShutdownDialog::RemainingSeconds() const {
    return (remaining_ms_ + 999) / 1000;
}

RECT ShutdownDialog::BarRect() const {
    RECT rc;
    GetClientRect(Hwnd(), &rc);
    const int y = band_h_ + S(kBlockDy + kBarDy);
    return { S(kTextX), y, rc.right - S(kMarginR), y + S(kBarH) };
}

RECT ShutdownDialog::CountdownRect() const {
    const RECT bar = BarRect();
    return { bar.left, bar.bottom + S(4), bar.right, bar.bottom + S(22) };
}

void ShutdownDialog::StopTimer() {
    if (!timer_on_) return;
    KillTimer(Hwnd(), kTimerId);
    timer_on_ = false;
    InvalidateRect(Hwnd(), nullptr, TRUE);
}

void ShutdownDialog::SyncActionBlock() {
    const int action = SelectedAction();
    const bool exiting = (action == 0);
    ShowWindow(chk_save_, exiting ? SW_SHOW : SW_HIDE);
    ShowWindow(save_link_, exiting ? SW_SHOW : SW_HIDE);
    ShowWindow(save_tail_, exiting ? SW_SHOW : SW_HIDE);
    ShowWindow(chk_remember_, exiting ? SW_SHOW : SW_HIDE);
    ShowWindow(desc_, exiting ? SW_HIDE : SW_SHOW);
    if (!exiting)
        SetWindowTextW(desc_, action == 1 ? kSoftText : kHardText);
    InvalidateRect(Hwnd(), nullptr, TRUE);
}

void ShutdownDialog::CommitOk() {
    switch (SelectedAction()) {
        case 1: choice_ = ShutdownChoice::SoftReset; break;
        case 2: choice_ = ShutdownChoice::HardReset; break;
        default: {
            const bool save =
                SendMessageW(chk_save_, BM_GETCHECK, 0, 0) == BST_CHECKED;
            if (SendMessageW(chk_remember_, BM_GETCHECK, 0, 0) == BST_CHECKED)
                emu_.Get<ConfigLoader>().SaveLastSaveStateMode(save);
            choice_ = save ? ShutdownChoice::ExitSave : ShutdownChoice::Exit;
            break;
        }
    }
    Finish();
}

void ShutdownDialog::BuildControls(HWND hwnd) {
    HINSTANCE inst = GetModuleHandleW(nullptr);
    RECT rc;
    GetClientRect(hwnd, &rc);
    const int cw = rc.right;
    const int cb = band_h_;

    auto mk = [&](const wchar_t* cls, const wchar_t* text, DWORD style,
                  int x, int y, int w, int h, int id) {
        return CreateWindowExW(0, cls, text, WS_CHILD | WS_VISIBLE | style,
                               x, y, w, h, hwnd, (HMENU)(INT_PTR)id, inst,
                               nullptr);
    };

    const wchar_t* intro = (trigger_ == ShutdownTrigger::DeepSleep)
        ? L"The guest OS has requested a shut down."
        : L"You have requested a shut down.";
    mk(L"STATIC", intro, SS_LEFT, S(kTextX), cb + S(kIntroDy),
       cw - S(kTextX) - S(kMarginR), S(kRowH), -1);

    mk(L"STATIC", L"What do you want to do?", SS_LEFT, S(kTextX),
       cb + S(kAskDy), cw - S(kTextX) - S(kMarginR), S(kRowH), -1);

    combo_ = mk(L"COMBOBOX", L"",
                CBS_DROPDOWNLIST | WS_TABSTOP | WS_VSCROLL, S(kTextX),
                cb + S(kComboDy), cw - S(kTextX) - S(kMarginR),
                S(kComboH) + 3 * S(kRowH), IDC_ACTION);
    SendMessageW(combo_, CB_ADDSTRING, 0, (LPARAM)L"Exit emulator");
    SendMessageW(combo_, CB_ADDSTRING, 0, (LPARAM)L"Soft reset");
    SendMessageW(combo_, CB_ADDSTRING, 0, (LPARAM)L"Hard reset");
    SendMessageW(combo_, CB_SETCURSEL, 0, 0);

    const int block_y = cb + S(kBlockDy);
    const unsigned long long mb =
        emu_.Get<EmulatedMemory>().VolatileByteCount() >> 20;
    wchar_t save_text[64];
    swprintf(save_text, 64, L"Save the state (%llu MB, ", mb);
    chk_save_ = mk(L"BUTTON", save_text, BS_AUTOCHECKBOX | WS_TABSTOP,
                   S(kTextX), block_y, cw - S(kTextX) - S(kMarginR),
                   S(kRowH), IDC_SAVE);
    SendMessageW(chk_save_, BM_SETCHECK,
                 emu_.Get<DeviceConfig>().last_save_state_mode
                     ? BST_CHECKED : BST_UNCHECKED, 0);

    save_link_ = mk(WC_LINK, kSaveLinkMarkup, WS_TABSTOP, S(kTextX), block_y,
                    S(kRowH), S(kRowH), IDC_SAVE_LINK);
    save_tail_ = mk(L"STATIC", kSaveTail, SS_LEFT, S(kTextX), block_y,
                    S(kRowH), S(kRowH), -1);

    chk_remember_ = mk(L"BUTTON", L"Remember this choice",
                       BS_AUTOCHECKBOX | WS_TABSTOP, S(kTextX),
                       block_y + S(kRowH + 2),
                       cw - S(kTextX) - S(kMarginR), S(kRowH), IDC_REMEMBER);

    desc_ = mk(L"STATIC", kSoftText, SS_LEFT, S(kTextX), block_y,
               cw - S(kTextX) - S(kMarginR), S(kDescH), IDC_DESC);
    ShowWindow(desc_, SW_HIDE);

    const int btn_y = rc.bottom - S(kBtnBottom);
    mk(L"BUTTON", L"OK", BS_DEFPUSHBUTTON | WS_TABSTOP,
       cw - S(kMarginR + kBtnGap) - 2 * S(kBtnW), btn_y, S(kBtnW), S(kBtnH),
       IDOK);
    mk(L"BUTTON",
       trigger_ == ShutdownTrigger::DeepSleep ? L"Resume" : L"Cancel",
       BS_PUSHBUTTON | WS_TABSTOP,
       cw - S(kMarginR) - S(kBtnW), btn_y, S(kBtnW), S(kBtnH), IDCANCEL);

    if (timer_on_) {
        deadline_tick_ = GetTickCount64() + kTotalMs;
        SetTimer(hwnd, kTimerId, kTickMs, nullptr);
    }
}

void ShutdownDialog::LayoutSaveRow() {
    const int block_y = band_h_ + S(kBlockDy);
    const int row_h   = S(kRowH);

    SIZE chk = {};
    SendMessageW(chk_save_, BCM_GETIDEALSIZE, 0, (LPARAM)&chk);
    SetWindowPos(chk_save_, nullptr, S(kTextX), block_y, chk.cx, row_h,
                 SWP_NOZORDER | SWP_NOACTIVATE);

    RECT rc;
    GetClientRect(Hwnd(), &rc);
    const int link_x = S(kTextX) + chk.cx;
    SIZE link = {};
    SendMessageW(save_link_, LM_GETIDEALSIZE,
                 rc.right - S(kMarginR) - link_x, (LPARAM)&link);
    const int link_y = block_y + (row_h - link.cy) / 2;
    SetWindowPos(save_link_, nullptr, link_x, link_y, link.cx, link.cy,
                 SWP_NOZORDER | SWP_NOACTIVATE);

    SIZE tail = {};
    HDC dc = GetDC(save_tail_);
    HGDIOBJ old = SelectObject(dc, (HFONT)SendMessageW(save_tail_, WM_GETFONT, 0, 0));
    GetTextExtentPoint32W(dc, kSaveTail, lstrlenW(kSaveTail), &tail);
    SelectObject(dc, old);
    ReleaseDC(save_tail_, dc);
    SetWindowPos(save_tail_, nullptr, link_x + link.cx, link_y, tail.cx,
                 link.cy, SWP_NOZORDER | SWP_NOACTIVATE);
}

void ShutdownDialog::OnShown() {
    LayoutSaveRow();
    SetFocus(combo_);
}

void ShutdownDialog::OnPaint(HDC dc) {
    auto& dm = emu_.Get<HostDarkMode>();
    const bool dark = dm.IsDark();

    emu_.Get<DialogBand>().Paint(dc, Dpi(), 0, 0);

    if (HICON icon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(2)))
        DrawIconEx(dc, S(kIconX), band_h_ + S(kIconDy), icon, S(kIconSize),
                   S(kIconSize), 0, nullptr, DI_NORMAL);

    if (!timer_on_ || SelectedAction() != 0) return;

    const RECT bar = BarRect();
    const RECT crc = CountdownRect();
    RECT strip = { bar.left, bar.top, bar.right, crc.bottom };
    FillRect(dc, &strip, dark ? dm.BgBrush() : GetSysColorBrush(COLOR_BTNFACE));

    FrameRect(dc, &bar, (HBRUSH)GetStockObject(GRAY_BRUSH));
    RECT fill = bar;
    InflateRect(&fill, -1, -1);
    painted_fill_w_ = BarFillWidth();
    fill.right = fill.left + painted_fill_w_;
    HBRUSH red = CreateSolidBrush(RGB(200, 30, 30));
    FillRect(dc, &fill, red);
    DeleteObject(red);

    painted_secs_ = RemainingSeconds();
    wchar_t cd[32];
    swprintf(cd, 32, L"(%ds left)", painted_secs_);
    RECT text_rc = crc;
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, dark ? RGB(160, 160, 160) : RGB(96, 96, 96));
    HFONT   font = dm.UiFont();
    HGDIOBJ old  = SelectObject(dc, font ? font : GetStockObject(DEFAULT_GUI_FONT));
    DrawTextW(dc, cd, -1, &text_rc, DT_CENTER);
    SelectObject(dc, old);
}

void ShutdownDialog::OnCommand(int id, int notify) {
    if (id == IDOK) {
        CommitOk();
        return;
    }
    if (id == IDCANCEL) {
        choice_ = ShutdownChoice::Cancel;
        Finish();
        return;
    }
    if (id == IDC_ACTION) {
        if (notify == CBN_DROPDOWN) StopTimer();
        if (notify == CBN_SELCHANGE) {
            StopTimer();
            SyncActionBlock();
        }
        return;
    }
    if ((id == IDC_SAVE || id == IDC_REMEMBER) && notify == BN_CLICKED)
        StopTimer();
}

bool ShutdownDialog::OnMessage(UINT msg, WPARAM wp, LPARAM lp) {
    if (msg == WM_LBUTTONDOWN) {
        StopTimer();
        return true;
    }
    if (msg == WM_NOTIFY) {
        const auto* nh = reinterpret_cast<const NMHDR*>(lp);
        if (nh->hwndFrom == save_link_ &&
            (nh->code == NM_CLICK || nh->code == NM_RETURN))
            StopTimer();
        return false;
    }
    if (msg != WM_TIMER || wp != kTimerId) return false;

    const ULONGLONG now = GetTickCount64();
    remaining_ms_ = (now >= deadline_tick_)
        ? 0 : (int)(deadline_tick_ - now);
    if (remaining_ms_ <= 0) {
        KillTimer(Hwnd(), kTimerId);
        timer_on_ = false;
        CommitOk();
        return true;
    }
    if (BarFillWidth() != painted_fill_w_) {
        const RECT bar = BarRect();
        InvalidateRect(Hwnd(), &bar, FALSE);
    }
    if (RemainingSeconds() != painted_secs_) {
        const RECT crc = CountdownRect();
        InvalidateRect(Hwnd(), &crc, FALSE);
    }
    return true;
}

void ShutdownDialog::DismissAsCancel() {
    PostDismiss();
}

ShutdownChoice ShutdownDialog::Show(ShutdownTrigger trigger) {
    if (IsOpen()) return ShutdownChoice::Cancel;

    HWND owner = emu_.Get<HostWindow>().Hwnd();
    trigger_        = trigger;
    choice_         = ShutdownChoice::Cancel;
    timer_on_       = (trigger == ShutdownTrigger::WindowClose);
    remaining_ms_   = kTotalMs;
    painted_fill_w_ = -1;
    painted_secs_   = -1;

    const UINT dpi = emu_.Get<HostDpi>().ForWindow(owner);
    auto& band = emu_.Get<DialogBand>();
    band_h_ = band.PixelHeight(dpi);
    const int client_w = band.PixelWidth(dpi);
    const int client_h = band_h_ + MulDiv(kContentH, (int)dpi,
                                          USER_DEFAULT_SCREEN_DPI);

    RunModal(owner, kClass, L"Shut down - CE Runtime Foundation",
             client_w, client_h);
    return choice_;
}
