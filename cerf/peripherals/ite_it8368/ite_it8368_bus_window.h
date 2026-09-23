#pragma once

#include "../peripheral_base.h"

#include <cstdint>

class IteIt8368BusWindow : public Peripheral {
public:
    using Peripheral::Peripheral;

    void OnReady() override;

    uint16_t ReadHalf(uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

protected:
    virtual bool LanesCrossed() const = 0;
};
