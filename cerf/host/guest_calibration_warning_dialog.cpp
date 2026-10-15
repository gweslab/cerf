#define NOMINMAX
#include "guest_calibration_warning_dialog.h"
#include "ui_language.h"

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
    const char* message_key;
};

const BodyBlock kBody[] = {
    { nullptr, nullptr,
      "calibration.detected" },
    { nullptr, nullptr,
      "calibration.pointer_warning" },
    { nullptr, nullptr,
      "calibration.manual_hint" },
    { L"ICON_INPUT_GA_POINTER", nullptr,
      "calibration.guest_pointer_hint" },
    { L"ICON_INPUT_STYLUS", nullptr,
      "calibration.stock_pointer_hint" },
    { L"ICON_GA", L"ICON_GA_DISABLED",
      "calibration.resolution_hint" },
    { L"ICON_DISPLAY", nullptr,
      "calibration.skip_hint" },
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
        const wchar_t* text = emu_.Get<UiLanguage>().Text(b.message_key);
        const int text_x = kMargin + (b.icon_a ? kIconBox + kIconGap : 0);
        const int text_w = width - text_x - kMargin;

        RECT tr = { text_x, y, text_x + text_w, y };
        DrawTextW(dc, text, -1, &tr, DT_WORDBREAK | DT_CALCRECT);
        const int text_h = tr.bottom - tr.top;
        const int row_h  = (b.icon_a && text_h < kIconBox) ? kIconBox : text_h;

        if (draw) {
            RECT dr = { text_x, y, text_x + text_w, y + text_h };
            DrawTextW(dc, text, -1, &dr, DT_WORDBREAK);
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

    mk(emu_.Get<UiLanguage>().Text("calibration.switch_to_stock_input"), BS_DEFPUSHBUTTON | WS_TABSTOP | WS_GROUP,
       switch_x, kSwitchW, IDOK);
    mk(emu_.Get<UiLanguage>().Text("calibration.change_resolution"), BS_PUSHBUTTON | WS_TABSTOP, chres_x, kChangeResW,
       IDC_CHANGE_RES);
    mk(emu_.Get<UiLanguage>().Text("common.close"), BS_PUSHBUTTON | WS_TABSTOP, close_x, kCloseW, IDCANCEL);

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

    RunModal(emu_.Get<HostWindow>().Hwnd(), kClass, emu_.Get<UiLanguage>().Text("calibration.guest_additions_warning"),
             kClientW, body_h_ + kButtonRow);
    return choice_;
}
