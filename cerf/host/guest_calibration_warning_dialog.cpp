#define NOMINMAX
#include "guest_calibration_warning_dialog.h"

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "host_dark_mode.h"
#include "host_icon_cache.h"
#include "host_window.h"
#include "live_customizations_transaction.h"

REGISTER_SERVICE(GuestCalibrationWarningDialog);

namespace {

constexpr wchar_t kClass[] = L"CerfGuestCalibrationWarningDlg";

constexpr int kClientW   = 540;
constexpr int kMargin    = 16;
constexpr int kIconBox   = 36;
constexpr int kIconGap   = 12;
constexpr int kParaGap   = 10;
constexpr int kButtonRow = 46;

constexpr int kPairBox   = 20;

constexpr int kSwitchW    = 160;
constexpr int kChangeResW = 150;
constexpr int kCloseW     = 86;
constexpr int kButtonGap  = 8;

enum : int {
    IDC_CHANGE_RES = 4102,
};

struct BodyBlock {
    const wchar_t* icon_a;
    const wchar_t* icon_b;
    const wchar_t* text;
};

const BodyBlock kBody[] = {
    { nullptr, nullptr,
      L"Guest Additions driver detected that guest OS displays a calibration "
      L"window." },
    { nullptr, nullptr,
      L"The enhanced mouse pointer will NOT work on the calibration screen - "
      L"you need to switch to the stock input device. After you complete the "
      L"calibration CERF will switch you back to an enhanced mouse pointer." },
    { nullptr, nullptr,
      L"If this doesn't happen or you want to deal with this manually:" },
    { L"ICON_INPUT_GA_POINTER", nullptr,
      L"If this icon is shown in the status bar, this means you are using "
      L"enhanced Guest Additions mouse pointer. Click it to switch to stock "
      L"input device." },
    { L"ICON_INPUT_STYLUS", nullptr,
      L"This icon represents stock input device is currently active. Click it "
      L"to switch back to an enhanced Guest Additions mouse pointer." },
    { L"ICON_GA", L"ICON_GA_DISABLED",
      L"If you are using non-native resolution, the stock input might freak out "
      L"and wont work. Right click this icon and pick \"Change resolution\" - "
      L"switch it to the stock one and soft reset - this will bring back the "
      L"stock input to a proper functioning state. Once you finish the welcome "
      L"wizard (calibration wizard), you can switch back to any resolution you "
      L"like, the guest OS most likely has a capability to remember that you "
      L"have finished the calibration." },
    { L"ICON_DISPLAY", nullptr,
      L"If you are running a Handheld PC / desktop OS, some versions allow you "
      L"to skip calibration by pressing the Esc key." },
};

}

bool GuestCalibrationWarningDialog::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

void GuestCalibrationWarningDialog::DrawIconPair(HDC dc, const RECT& box,
                                                 const wchar_t* a,
                                                 const wchar_t* b) {
    RECT ra = { box.left, box.top, box.left + kPairBox, box.top + kPairBox };
    emu_.Get<HostIconCache>().DrawCentered(dc, ra, a);

    RECT rb = { box.right - kPairBox, box.bottom - kPairBox, box.right,
                box.bottom };
    emu_.Get<HostIconCache>().DrawCentered(dc, rb, b);

    const bool dark = emu_.Get<HostDarkMode>().IsDark();
    HPEN pen = CreatePen(PS_SOLID, 1,
                         dark ? RGB(110, 110, 110) : RGB(150, 150, 150));
    HGDIOBJ op = SelectObject(dc, pen);
    MoveToEx(dc, box.left, box.bottom, nullptr);
    LineTo(dc, box.right, box.top);
    SelectObject(dc, op);
    DeleteObject(pen);
}

int GuestCalibrationWarningDialog::LayoutBody(HDC dc, int width, bool draw) {
    HFONT font = emu_.Get<HostDarkMode>().UiFont();
    HGDIOBJ of = SelectObject(dc, font ? font : GetStockObject(DEFAULT_GUI_FONT));
    const bool dark = emu_.Get<HostDarkMode>().IsDark();
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, dark ? emu_.Get<HostDarkMode>().TextColor()
                          : GetSysColor(COLOR_BTNTEXT));

    int y = kMargin;
    for (const BodyBlock& b : kBody) {
        const int text_x = kMargin + (b.icon_a ? kIconBox + kIconGap : 0);
        const int text_w = width - text_x - kMargin;

        RECT tr = { text_x, y, text_x + text_w, y };
        DrawTextW(dc, b.text, -1, &tr, DT_WORDBREAK | DT_CALCRECT);
        const int text_h = tr.bottom - tr.top;
        const int row_h  = (b.icon_a && text_h < kIconBox) ? kIconBox : text_h;

        if (draw) {
            RECT dr = { text_x, y, text_x + text_w, y + text_h };
            DrawTextW(dc, b.text, -1, &dr, DT_WORDBREAK);
            if (b.icon_a) {
                RECT ir = { kMargin, y, kMargin + kIconBox, y + kIconBox };
                if (b.icon_b) DrawIconPair(dc, ir, b.icon_a, b.icon_b);
                else emu_.Get<HostIconCache>().DrawCentered(dc, ir, b.icon_a);
            }
        }
        y += row_h + kParaGap;
    }
    SelectObject(dc, of);
    return y - kParaGap + kMargin;
}

void GuestCalibrationWarningDialog::OnPaint(HDC dc) {
    LayoutBody(dc, kClientW, true);
}

void GuestCalibrationWarningDialog::BuildControls(HWND hwnd) {
    HINSTANCE inst = GetModuleHandleW(nullptr);
    const int by = body_h_ + 8;
    auto mk = [&](const wchar_t* text, DWORD style, int x, int w, int id) {
        return CreateWindowExW(0, L"BUTTON", text, WS_CHILD | WS_VISIBLE | style,
                               x, by, w, 30, hwnd, (HMENU)(INT_PTR)id, inst,
                               nullptr);
    };

    const int close_x  = kClientW - kMargin - kCloseW;
    const int chres_x  = close_x - kButtonGap - kChangeResW;
    const int switch_x = chres_x - kButtonGap - kSwitchW;

    mk(L"Switch to stock input", BS_DEFPUSHBUTTON | WS_TABSTOP | WS_GROUP,
       switch_x, kSwitchW, IDOK);
    mk(L"Change resolution", BS_PUSHBUTTON | WS_TABSTOP, chres_x, kChangeResW,
       IDC_CHANGE_RES);
    mk(L"Close", BS_PUSHBUTTON | WS_TABSTOP, close_x, kCloseW, IDCANCEL);

    HFONT gui = emu_.Get<HostDarkMode>().UiFont();
    if (!gui) gui = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
    for (HWND c = GetWindow(hwnd, GW_CHILD); c; c = GetWindow(c, GW_HWNDNEXT))
        SendMessageW(c, WM_SETFONT, (WPARAM)gui, TRUE);
}

void GuestCalibrationWarningDialog::OnCommand(int id, int) {
    if (id == IDOK) {
        choice_ = CalibWarningChoice::SwitchToStock;
        Finish();
    } else if (id == IDC_CHANGE_RES) {
        if (emu_.Get<LiveCustomizationsTransaction>().Open(Hwnd(), true))
            Finish();
    } else if (id == IDCANCEL) {
        Finish();
    }
}

CalibWarningChoice GuestCalibrationWarningDialog::Show() {
    if (IsOpen()) return CalibWarningChoice::Dismissed;

    choice_ = CalibWarningChoice::Dismissed;

    HDC screen = GetDC(nullptr);
    body_h_ = LayoutBody(screen, kClientW, false);
    ReleaseDC(nullptr, screen);

    RunModal(emu_.Get<HostWindow>().Hwnd(), kClass, L"Guest Additions Warning",
             kClientW, body_h_ + kButtonRow);
    return choice_;
}
