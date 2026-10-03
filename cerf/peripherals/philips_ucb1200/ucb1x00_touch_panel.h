#pragma once

#include "../../host/touch_input.h"

#include <atomic>

class Ucb1x00TouchPanel : public TouchInput {
public:
    using TouchInput::TouchInput;

    bool ShouldRegister() override;

    void OnPenDown(int x, int y) override;
    void OnPenMove(int x, int y) override;
    void OnPenUp  (int x, int y) override;
    void OnCaptureLost() override;

    bool Down();
    int  X() const { return x_.load(std::memory_order_relaxed); }
    int  Y() const { return y_.load(std::memory_order_relaxed); }

private:
    void SetPen(bool down, int x, int y);

    std::atomic<int> x_{0}, y_{0};
};
