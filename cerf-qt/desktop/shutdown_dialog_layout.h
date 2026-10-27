#pragma once

#include "../painter.h"

#include <cstdint>
#include <string>

namespace cerffrontend {

class ShutdownDialogLayout {
public:
    static constexpr int      kBandW     = 400;
    static constexpr int      kBandH     = 112;
    static constexpr int      kContentH  = 244;
    static constexpr int      kIconX     = 16;
    static constexpr int      kIconDy    = 14;
    static constexpr int      kIconSize  = 32;
    static constexpr int      kTextX     = 60;
    static constexpr int      kIntroDy   = 16;
    static constexpr int      kAskDy     = 44;
    static constexpr int      kComboDy   = 64;
    static constexpr int      kComboH    = 26;
    static constexpr int      kBlockDy   = 96;
    static constexpr int      kRowH      = 22;
    static constexpr int      kDescH     = 92;
    static constexpr int      kBarDy     = 52;
    static constexpr int      kBarH      = 16;
    static constexpr int      kBtnW      = 88;
    static constexpr int      kBtnH      = 28;
    static constexpr int      kBtnGap    = 8;
    static constexpr int      kMarginR   = 20;
    static constexpr int      kBtnBottom = 44;
    static constexpr uint32_t kTickMs    = 15;
    static constexpr int      kComboDropRows = 3;

    static constexpr Rgb kBarFill{200, 30, 30};
    static constexpr Rgb kBarFrame{128, 128, 128};
    static constexpr Rgb kCountdownDark{160, 160, 160};
    static constexpr Rgb kCountdownLight{96, 96, 96};

    ShutdownDialogLayout(int dpi, int band_h, int client_w, int client_h)
        : dpi_(dpi), band_h_(band_h), client_w_(client_w), client_h_(client_h) {}

    static int ClientHeight(int dpi, int band_h);

    int  S(int v) const;
    Rect Icon() const;
    Rect Intro() const;
    Rect Question() const;
    Rect Combo() const;
    Rect SaveRow() const;
    Rect Remember() const;
    Rect Description() const;
    Rect Ok() const;
    Rect Cancel() const;
    Rect Bar() const;
    Rect Countdown() const;
    Rect CountdownStrip() const;

    int        BarFillWidth(int remaining_ms) const;
    static int         RemainingSeconds(int remaining_ms);
    static std::string CountdownText(int remaining_ms);
    void       PaintCountdown(Painter& p, Rgb background, bool dark, int remaining_ms) const;

private:
    Rect TextRow(int dy, int height) const;

    int dpi_;
    int band_h_;
    int client_w_;
    int client_h_;
};

}
