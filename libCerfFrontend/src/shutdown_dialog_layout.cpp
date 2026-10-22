#include <cerffrontend/shutdown_dialog_layout.h>

#include <cerffrontend/dpi_scale.h>
#include <cerffrontend/shutdown_prompt.h>

#include <cstdio>

namespace cerffrontend {

int ShutdownDialogLayout::ClientHeight(int dpi, int band_h) {
    return band_h + ScaleForDpi(kContentH, dpi);
}

int ShutdownDialogLayout::S(int v) const { return ScaleForDpi(v, dpi_); }

Rect ShutdownDialogLayout::TextRow(int dy, int height) const {
    const int top = band_h_ + S(dy);
    return {S(kTextX), top, client_w_ - S(kMarginR), top + height};
}

Rect ShutdownDialogLayout::Icon() const {
    const int top = band_h_ + S(kIconDy);
    return {S(kIconX), top, S(kIconX) + S(kIconSize), top + S(kIconSize)};
}

Rect ShutdownDialogLayout::Intro() const { return TextRow(kIntroDy, S(kRowH)); }

Rect ShutdownDialogLayout::Question() const { return TextRow(kAskDy, S(kRowH)); }

Rect ShutdownDialogLayout::Combo() const { return TextRow(kComboDy, S(kComboH)); }

Rect ShutdownDialogLayout::SaveRow() const { return TextRow(kBlockDy, S(kRowH)); }

Rect ShutdownDialogLayout::Remember() const {
    const int top = band_h_ + S(kBlockDy) + S(kRowH + 2);
    return {S(kTextX), top, client_w_ - S(kMarginR), top + S(kRowH)};
}

Rect ShutdownDialogLayout::Description() const { return TextRow(kBlockDy, S(kDescH)); }

Rect ShutdownDialogLayout::Ok() const {
    const int left = client_w_ - S(kMarginR + kBtnGap) - 2 * S(kBtnW);
    const int top  = client_h_ - S(kBtnBottom);
    return {left, top, left + S(kBtnW), top + S(kBtnH)};
}

Rect ShutdownDialogLayout::Cancel() const {
    const int left = client_w_ - S(kMarginR) - S(kBtnW);
    const int top  = client_h_ - S(kBtnBottom);
    return {left, top, left + S(kBtnW), top + S(kBtnH)};
}

Rect ShutdownDialogLayout::Bar() const {
    const int top = band_h_ + S(kBlockDy + kBarDy);
    return {S(kTextX), top, client_w_ - S(kMarginR), top + S(kBarH)};
}

Rect ShutdownDialogLayout::Countdown() const {
    const Rect bar = Bar();
    return {bar.left, bar.bottom + S(4), bar.right, bar.bottom + S(22)};
}

Rect ShutdownDialogLayout::CountdownStrip() const {
    const Rect bar = Bar();
    return {bar.left, bar.top, bar.right, Countdown().bottom};
}

int ShutdownDialogLayout::BarFillWidth(int remaining_ms) const {
    const Rect bar = Bar();
    return (bar.right - bar.left - 2) * remaining_ms / static_cast<int>(ShutdownPrompt::kCountdownMs);
}

int ShutdownDialogLayout::RemainingSeconds(int remaining_ms) { return (remaining_ms + 999) / 1000; }

void ShutdownDialogLayout::PaintCountdown(Painter& p, Rgb background, bool dark, int remaining_ms) const {
    const Rect bar = Bar();
    p.FillRect(CountdownStrip(), background);
    p.Rectangle(bar, kBarFrame, 1, nullptr);
    const Rect fill{bar.left + 1, bar.top + 1, bar.left + 1 + BarFillWidth(remaining_ms), bar.bottom - 1};
    p.FillRect(fill, kBarFill);
    char text[32];
    std::snprintf(text, sizeof text, "(%ds left)", RemainingSeconds(remaining_ms));
    p.DrawTextBox(Countdown(), text, Font{FontFace::kSystem, 0, false},
                  dark ? kCountdownDark : kCountdownLight, text::kCenter);
}

}
