#pragma once

#include <cstdint>
#include <optional>

struct Vr41xxPiuPenPoint {
    bool     down;
    uint16_t x;
    uint16_t y;
};

class Vr41xxPiuHostPen {
public:
    void Pen(bool down, uint16_t x, uint16_t y);
    void Tap(uint16_t x, uint16_t y);

    std::optional<Vr41xxPiuPenPoint> TakePen();
    std::optional<Vr41xxPiuPenPoint> TakeTap();

    void Clear();

private:
    static std::optional<Vr41xxPiuPenPoint> Take(std::optional<Vr41xxPiuPenPoint>& slot);

    std::optional<Vr41xxPiuPenPoint> pen_;
    std::optional<Vr41xxPiuPenPoint> tap_;
};
