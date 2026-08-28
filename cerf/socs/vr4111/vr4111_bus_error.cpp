#include "vr4111_bus_error.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../vr41xx/vr41xx_icu.h"

REGISTER_SERVICE(Vr4111BusError);

namespace {

constexpr uint16_t kBerrst        = 1u << 0;
constexpr uint16_t kSysint1WrBerr = 1u << 10;

}

bool Vr4111BusError::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSoc() == SocFamily::VR4111;
}

void Vr4111BusError::OnReady() {
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            berrst_ = false;
        }
        Publish(false);
    });
}

void Vr4111BusError::NotifyIllegalWrite() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        berrst_ = true;
    }
    Publish(true);
}

uint16_t Vr4111BusError::ReadStatus() {
    std::lock_guard<std::mutex> lk(mtx_);
    return static_cast<uint16_t>(berrst_ ? kBerrst : 0u);
}

void Vr4111BusError::WriteStatus(uint16_t value) {
    bool level;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (value & kBerrst) berrst_ = false;
        level = berrst_;
    }
    Publish(level);
}

void Vr4111BusError::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    w.Write<uint8_t>(berrst_ ? 1u : 0u);
}

void Vr4111BusError::RestoreState(StateReader& r) {
    uint8_t v = 0;
    r.Read(v);
    std::lock_guard<std::mutex> lk(mtx_);
    berrst_ = v != 0;
}

void Vr4111BusError::PostRestore() {
    bool level;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        level = berrst_;
    }
    Publish(level);
}

void Vr4111BusError::Publish(bool level) {
    emu_.Get<Vr41xxIcu>().SetSysint1Source(kSysint1WrBerr, level);
}
