#include "calibration_warning_body.h"

namespace cerffrontend {

namespace {

constexpr int kIconBox = 36;
constexpr int kIconGap = 12;
constexpr int kParaGap = 10;
constexpr int kPairBox = 20;

constexpr Rgb kPairLineDark{110, 110, 110};
constexpr Rgb kPairLineLight{150, 150, 150};

struct BodyBlock {
    const char* icon_a;
    const char* icon_b;
    const char* text;
};

const BodyBlock kBody[] = {
    {nullptr, nullptr, "Guest Additions driver detected that guest OS displays a calibration window."},
    {nullptr, nullptr,
     "The enhanced mouse pointer will NOT work on the calibration screen - you need to switch to the stock "
     "input device. After you complete the calibration CERF will switch you back to an enhanced mouse pointer."},
    {nullptr, nullptr, "If this doesn't happen or you want to deal with this manually:"},
    {"ga_cursor", nullptr,
     "If this icon is shown in the status bar, this means you are using "
     "enhanced Guest Additions mouse pointer. Click it to switch to stock "
     "input device."},
    {"stylus", nullptr,
     "This icon represents stock input device is currently active. Click it "
     "to switch back to an enhanced Guest Additions mouse pointer."},
    {"ga_autoresize", "ga_autoresize_disabled",
     "If you are using non-native resolution, the stock input might freak out "
     "and wont work. Right click this icon and pick \"Change resolution\" - "
     "switch it to the stock one and soft reset - this will bring back the "
     "stock input to a proper functioning state. Once you finish the welcome "
     "wizard (calibration wizard), you can switch back to any resolution you "
     "like, the guest OS most likely has a capability to remember that you "
     "have finished the calibration."},
    {"display", nullptr,
     "If you are running a Handheld PC / desktop OS, some versions allow you "
     "to skip calibration by pressing the Esc key."},
};

void DrawCentered(Painter& p, const Rect& box, const char* stem) {
    p.DrawIcon(box, stem, (box.Width() < box.Height() ? box.Width() : box.Height()) - 4);
}

void DrawIconPair(Painter& p, const Rect& box, const char* a, const char* b, bool dark) {
    DrawCentered(p, {box.left, box.top, box.left + kPairBox, box.top + kPairBox}, a);
    DrawCentered(p, {box.right - kPairBox, box.bottom - kPairBox, box.right, box.bottom}, b);
    const Point line[] = {{box.left, box.bottom}, {box.right, box.top}};
    p.Polyline(line, 2, dark ? kPairLineDark : kPairLineLight, 1);
}

}

int CalibrationWarningBody::Layout(Painter& p, int width, bool draw, bool dark, Rgb text) {
    const Font font{FontFace::kSystem, 0, false};
    int        y = kMargin;
    for (const BodyBlock& b : kBody) {
        const int text_x = kMargin + (b.icon_a ? kIconBox + kIconGap : 0);
        const int text_w = width - text_x - kMargin;
        const int text_h = p.TextHeight(b.text, font, text_w, text::kWordBreak);
        const int row_h  = (b.icon_a && text_h < kIconBox) ? kIconBox : text_h;
        if (draw) {
            p.DrawTextBox({text_x, y, text_x + text_w, y + text_h}, b.text, font, text,
                          text::kWordBreak);
            if (b.icon_a) {
                const Rect ir{kMargin, y, kMargin + kIconBox, y + kIconBox};
                if (b.icon_b) DrawIconPair(p, ir, b.icon_a, b.icon_b, dark);
                else          DrawCentered(p, ir, b.icon_a);
            }
        }
        y += row_h + kParaGap;
    }
    return y - kParaGap + kMargin;
}

}
