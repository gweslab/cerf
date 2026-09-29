#include "vr41xx_piu_host_pen.h"

void Vr41xxPiuHostPen::Pen(bool down, uint16_t x, uint16_t y) {
    pen_ = Vr41xxPiuPenPoint{down, static_cast<uint16_t>(x & 0x3FFu),
                             static_cast<uint16_t>(y & 0x3FFu)};
    tap_.reset();
}

void Vr41xxPiuHostPen::Tap(uint16_t x, uint16_t y) {
    tap_ = Vr41xxPiuPenPoint{true, static_cast<uint16_t>(x & 0x3FFu),
                             static_cast<uint16_t>(y & 0x3FFu)};
}

std::optional<Vr41xxPiuPenPoint> Vr41xxPiuHostPen::TakePen() { return Take(pen_); }

std::optional<Vr41xxPiuPenPoint> Vr41xxPiuHostPen::TakeTap() { return Take(tap_); }

void Vr41xxPiuHostPen::Clear() {
    pen_.reset();
    tap_.reset();
}

std::optional<Vr41xxPiuPenPoint> Vr41xxPiuHostPen::Take(std::optional<Vr41xxPiuPenPoint>& slot) {
    std::optional<Vr41xxPiuPenPoint> p = slot;
    slot.reset();
    return p;
}
