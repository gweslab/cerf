#include "sa11xx_test_unit.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../guest_cpu_reset.h"
#include "../../state/state_stream.h"
#include "sa1100_id.h"
#include "sa1110_id.h"
#include "sa11xx_gpio.h"

namespace {

/* SA-1110 Developer's Manual App. D.1: TUCR bit 10 MR, bits 31:29 TSEL2..0. SA-1100 TRM §10.8
   (printed 10-31): "Test unit control register (TUCR) to set bit 10." */
constexpr uint32_t kMr        = 1u << 10;
constexpr uint32_t kTselShift = 29u;

constexpr uint32_t kGp21 = 21u;
constexpr uint32_t kGp22 = 22u;
constexpr uint32_t kGp27 = 27u;

}

bool Sa11xxTestUnit::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
}

/* SA-1110 Developer's Manual App. D.1: every TUCR bit resets to 0; §9.6.1.1 RSRR: "Writing a one
   to this bit causes all on-chip resources to reset"; §9.6: "Sleep reset does not affect the
   power manager, RTC, or GPIO wake-up register". SA-1100 TRM §9.6.1.1 carries the same RSRR text. */
void Sa11xxTestUnit::OnReady() {
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) { tucr_ = 0u; });
    emu_.Get<Sa11xxGpio>().RegisterPinConfigListener([this] { NotifyChange(); });
}

void Sa11xxTestUnit::Write(uint32_t value) {
    tucr_ = value;
    NotifyChange();
}

/* App. D.1 MR: "1 - GP 21 and GP 22 are reserved for use as MBGNT and MBREQ, respectively",
   "0 - GP 21 and GP 22 are not used for an alternate function"; §10.8: GPDR bit 21 set and bit 22
   clear, GAFR bits 21 and 22 set, TUCR bit 10 set. §9.1.2: GP 21 alternate TIC_ACK/MBGNT. */
Sa11xxTestUnit::Mbgnt Sa11xxTestUnit::MbgntPin() const {
    const auto& gpio = emu_.Get<Sa11xxGpio>();
    const Sa11xxGpio::PinConfig gp21 = gpio.Pin(kGp21);
    if ((tucr_ & kMr) != 0u) {
        const Sa11xxGpio::PinConfig gp22 = gpio.Pin(kGp22);
        const bool configured = gp21.alternate && gp21.output && gp22.alternate && !gp22.output;
        return configured ? Mbgnt::Arbiter : Mbgnt::Undetermined;
    }
    if (gp21.alternate || !gp21.output) return Mbgnt::Undetermined;
    return gp21.latch ? Mbgnt::High : Mbgnt::Low;
}

bool Sa11xxTestUnit::Gp27Clock3686400() const {
    const Sa11xxGpio::PinConfig gp27 = emu_.Get<Sa11xxGpio>().Pin(kGp27);
    if (!gp27.alternate || !gp27.output) return false;
    const uint32_t tsel = tucr_ >> kTselShift;
    return tsel == 0x1u || tsel == 0x5u;
}

void Sa11xxTestUnit::RegisterChangeListener(std::function<void()> fn) {
    listeners_.push_back(std::move(fn));
}

void Sa11xxTestUnit::NotifyChange() {
    for (auto& fn : listeners_) fn();
}

void Sa11xxTestUnit::Save(StateWriter& w) const {
    w.Write("tucr", tucr_);
}

void Sa11xxTestUnit::Restore(StateReader& r) {
    r.Read("tucr", tucr_);
}

REGISTER_SERVICE(Sa11xxTestUnit);
