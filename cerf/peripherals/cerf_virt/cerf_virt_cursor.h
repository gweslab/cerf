#pragma once

#include "../peripheral_base.h"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <vector>

struct GuestCursorShape {
    bool     visible = false;
    uint8_t  pad[3]  = {};
    uint32_t cx = 0, cy = 0, xhot = 0, yhot = 0, stride = 0;
    std::vector<uint8_t> bits;

    template <typename F>
    static constexpr void Visit(GuestCursorShape& s, F& field) {
        field("visible", s.visible);
        field.Skip(s.pad);
        field("cx", s.cx);
        field("cy", s.cy);
        field("xhot", s.xhot);
        field("yhot", s.yhot);
        field("stride", s.stride);
        field.Skip(s.bits);
    }
};

class CerfVirtCursor : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override;
    uint32_t MmioSize() const override;
    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    uint32_t Seq() const { return seq_.load(); }
    bool GetShape(GuestCursorShape& out);

private:
    std::atomic<uint32_t> seq_{0};
    uint8_t*              stage_ = nullptr;
    std::mutex            shape_mutex_;
    GuestCursorShape      shape_;
    bool                  has_shape_ = false;
};
