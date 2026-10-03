#include "sa11xx_ssp_clock_input.h"

void Sa11xxSspClockInput::RegisterChangeListener(std::function<void()> fn) {
    listeners_.push_back(std::move(fn));
}

void Sa11xxSspClockInput::NotifyChange() {
    for (auto& fn : listeners_) fn();
}
