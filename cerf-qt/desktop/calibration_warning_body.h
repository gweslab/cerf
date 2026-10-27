#pragma once

#include "../painter.h"

namespace cerffrontend {

struct CalibrationWarningBody {
    static constexpr int kClientW    = 540;
    static constexpr int kMargin     = 16;
    static constexpr int kButtonRow  = 46;
    static constexpr int kButtonTop  = 8;
    static constexpr int kButtonH    = 30;
    static constexpr int kSwitchW    = 160;
    static constexpr int kChangeResW = 150;
    static constexpr int kCloseW     = 86;
    static constexpr int kButtonGap  = 8;

    static int Layout(Painter& p, int width, bool draw, bool dark, Rgb text);
};

}
