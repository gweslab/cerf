#pragma once

#include <cstdint>
#include <string_view>

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../jit/mips/mips_core_clock.h"
#include "vr41xx_clock_strap.h"

struct Vr41xxClkselRow {
    uint16_t clksp;
    uint16_t pclock_per_masterout;
};

struct Vr41xxCoreClockModel {
    uint64_t        pclock_mult;
    uint64_t        tclock_per_masterout;
    Vr41xxClkselRow rows[8];
};

constexpr bool Vr41xxRowsHoldWholeTClocks(const Vr41xxCoreClockModel& m) {
    for (const Vr41xxClkselRow& r : m.rows) {
        if (r.pclock_per_masterout % m.tclock_per_masterout != 0u) return false;
    }
    return true;
}

template <const std::string_view& Soc, const Vr41xxCoreClockModel& M>
class Vr41xxCoreClockBase : public MipsCoreClock {
    static_assert(M.tclock_per_masterout != 0u && Vr41xxRowsHoldWholeTClocks(M));

public:
    using MipsCoreClock::MipsCoreClock;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == Soc;
    }

    void OnReady() override {
        row_ = &emu_.Get<Vr41xxClockStrap>().StrapRow(M.rows);
    }

    GuestCycleClock::Rate ResetRate() const override {
        return GuestCycleClock::Rate{kVr41xxClkxHz * M.pclock_mult, row_->clksp};
    }

    uint64_t CyclesPerCountTick() const override { return row_->pclock_per_masterout; }

    uint64_t CyclesPerTclkCounterTick() const override {
        return row_->pclock_per_masterout / M.tclock_per_masterout;
    }

private:
    const Vr41xxClkselRow* row_ = nullptr;
};
