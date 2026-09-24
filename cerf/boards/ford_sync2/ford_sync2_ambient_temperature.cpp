#include "ford_sync2_ambient_temperature.h"
#include "../board_context.h"
#include "ford_sync_2_id.h"
#include "../../core/cerf_emulator.h"
#include "../../state/state_stream.h"

REGISTER_SERVICE(FordSync2AmbientTemperature);

bool FordSync2AmbientTemperature::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetBoardId() == BoardId::FordSync2;
}

FordSync2AmbientTemperature::Snapshot FordSync2AmbientTemperature::Read() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_;
}

void FordSync2AmbientTemperature::Set(std::optional<int16_t> half_celsius) {
    /* EA5T-14D544-BA.sec, VNIGeneralSvc.dll sub_C1595D40. */
    if (half_celsius && (*half_celsius < -80 || *half_celsius > 173)) return;
    std::lock_guard<std::mutex> lock(mutex_);
    state_.available = true;
    state_.half_celsius = half_celsius;
    ++state_.revision;
}

void FordSync2AmbientTemperature::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    state_.available = false;
    state_.half_celsius.reset();
    ++state_.revision;
}

void FordSync2AmbientTemperature::SaveState(StateWriter& w) const {
    std::lock_guard<std::mutex> lock(mutex_);
    w.Write<uint8_t>("available", state_.available);
    w.Write<uint8_t>("has_half_celsius", state_.half_celsius.has_value());
    w.Write<int16_t>("half_celsius", state_.half_celsius.value_or(0));
}

void FordSync2AmbientTemperature::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lock(mutex_);
    uint8_t available = 0, valid = 0;
    int16_t half_celsius = 0;
    r.Read("available", available); r.Read("has_half_celsius", valid);
    r.Read("half_celsius", half_celsius);
    state_.available = available != 0;
    state_.half_celsius = valid ? std::optional<int16_t>(half_celsius) : std::nullopt;
    ++state_.revision;
}
