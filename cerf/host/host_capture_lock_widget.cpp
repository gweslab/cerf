#define NOMINMAX
#include <windows.h>

#include "../core/cerf_emulator.h"
#include "../core/service.h"
#include "host_input_capture.h"
#include "host_widget.h"
#include "host_widget_registry.h"

#include <string>
#include <vector>

namespace {

constexpr COLORREF kClrLocked = RGB(78, 201, 90);    /* green */
constexpr COLORREF kClrFree   = RGB(140, 140, 140);  /* gray */

/* Segoe MDL2 Assets glyphs (present Win10+). */
constexpr wchar_t kGlyphLock   = L'\xE72E';
constexpr wchar_t kGlyphUnlock = L'\xE785';

/* The input-capture lock as a host-owned widget. WidgetGroup::InputControl
   sorts last, so it stays rightmost in the bar regardless of which device
   widgets are present. */
class HostCaptureLockWidget : public Service, public HostWidget {
public:
    using Service::Service;

    void OnReady() override {
        glyph_font_ = CreateFontW(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                  DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                  CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                  DEFAULT_PITCH | FF_DONTCARE,
                                  L"Segoe MDL2 Assets");
        emu_.Get<HostWidgetRegistry>().Register(this);
    }
    ~HostCaptureLockWidget() override {
        if (glyph_font_) DeleteObject(glyph_font_);
    }

    std::wstring WidgetName() const override { return L"Input Capture"; }
    WidgetGroup  Group() const override { return WidgetGroup::InputControl; }
    std::wstring Tooltip() const override {
        return emu_.Get<HostInputCapture>().IsCaptured()
            ? L"Input captured — Right Ctrl (or click) to release"
            : L"Input free — Right Ctrl (or click) to capture (Alt+Tab etc. -> guest)";
    }
    void OnPrimaryAction() override { emu_.Get<HostInputCapture>().Toggle(); }
    std::vector<WidgetMenuItem> BuildMenu() override {
        /* '\t' right-aligns the Right Ctrl hotkey hint, same as the native
           menu items. The hotkey itself is serviced by HostInputCapture's
           low-level keyboard hook, not a menu accelerator. */
        WidgetMenuItem it;
        it.label    = emu_.Get<HostInputCapture>().IsCaptured()
                          ? L"Release input capture\tRight Ctrl"
                          : L"Capture input\tRight Ctrl";
        it.on_click = [this] { emu_.Get<HostInputCapture>().Toggle(); };
        return { std::move(it) };
    }
    void DrawIcon(HDC dc, const RECT& box) const override {
        const bool cap = emu_.Get<HostInputCapture>().IsCaptured();
        HGDIOBJ of = glyph_font_ ? SelectObject(dc, glyph_font_) : nullptr;
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, cap ? kClrLocked : kClrFree);
        const wchar_t g = cap ? kGlyphLock : kGlyphUnlock;
        RECT r = box;
        DrawTextW(dc, &g, 1, &r, DT_SINGLELINE | DT_VCENTER | DT_CENTER);
        if (of) SelectObject(dc, of);
    }
    bool PollDirty() override {
        const bool cap = emu_.Get<HostInputCapture>().IsCaptured();
        if (cap == last_drawn_cap_) return false;
        last_drawn_cap_ = cap;
        return true;
    }

private:
    HFONT glyph_font_    = nullptr;
    bool  last_drawn_cap_ = false;
};

}  /* namespace */

REGISTER_SERVICE(HostCaptureLockWidget);
