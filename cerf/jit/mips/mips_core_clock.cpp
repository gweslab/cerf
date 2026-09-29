#include "mips_core_clock.h"

#include <utility>

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"

uint64_t MipsCoreClock::CyclesPerCountTick() const {
    emu_.Get<Fatal>().Die("MipsCoreClock: CP0 Count read on a core clock with no Count divider");
}

uint64_t MipsCoreClock::CyclesPerTclkCounterTick() const {
    emu_.Get<Fatal>().Die("MipsCoreClock: RTC TClock counter on a core clock with no TClock divider");
}

void MipsCoreClock::RegisterCountRateListener(std::function<void()> fn) {
    count_rate_listeners_.push_back(std::move(fn));
}

void MipsCoreClock::CountRateRestored() {
    for (auto& fn : count_rate_listeners_) fn();
}
