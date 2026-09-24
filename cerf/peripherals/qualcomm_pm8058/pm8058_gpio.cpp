#include "pm8058_gpio.h"

#include "../../boards/board_context.h"
#include "../../boards/nokia_lumia_800/nokia_lumia_800_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/state_stream.h"

namespace {

/* Linux drivers/mfd/pm8058-core.c pm8058_gpio_mux_cfg:
   "bit 7 - write / bit 6:4 - bank select", the low nibble carrying that
   bank's contents. */
constexpr uint8_t kWrite      = 1u << 7;
constexpr uint8_t kBankShift  = 4u;
constexpr uint8_t kBankMask   = 0x7u;
constexpr uint8_t kDataMask   = 0xFu;

}  // namespace

bool Pm8058Gpio::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::NokiaLumia800;
}

void Pm8058Gpio::OnReady() {
    Reset();
    emu_.Get<GuestCpuReset>().RegisterResetListener(
        [this](ResetLineKind) { Reset(); });
}

void Pm8058Gpio::Reset() {
    for (uint32_t g = 0; g < kGpios; ++g) {
        read_bank_[g] = 0;
        for (uint32_t b = 0; b < kBanks; ++b) bank_data_[g][b] = 0;
    }
}

uint8_t Pm8058Gpio::ReadReg(uint16_t reg) {
    const uint32_t gpio = (uint32_t)(reg - kRegBase);
    return (uint8_t)(bank_data_[gpio][read_bank_[gpio]] & kDataMask);
}

void Pm8058Gpio::WriteReg(uint16_t reg, uint8_t value) {
    const uint32_t gpio = (uint32_t)(reg - kRegBase);
    const uint32_t bank = (value >> kBankShift) & kBankMask;

    if (bank >= kBanks) {
        emu_.Get<Fatal>().Die(
            "pm8058 gpio %u: the 0x%02X written to register 0x%03X selects "
            "bank %u, and only banks 0 through %u are named",
            gpio, value, reg, bank, kBanks - 1u);
    }

    if ((value & kWrite) != 0u) {
        bank_data_[gpio][bank] = (uint8_t)(value & kDataMask);
    } else {
        read_bank_[gpio] = (uint8_t)bank;
    }
}

void Pm8058Gpio::SaveState(StateWriter& w) {
    for (uint32_t g = 0; g < kGpios; ++g) {
        w.Write<uint8_t>("read_bank", read_bank_[g]);
        for (uint32_t b = 0; b < kBanks; ++b) w.Write<uint8_t>("bank_data", bank_data_[g][b]);
    }
}

void Pm8058Gpio::RestoreState(StateReader& r) {
    for (uint32_t g = 0; g < kGpios; ++g) {
        r.Read("read_bank", read_bank_[g]);
        if (read_bank_[g] >= kBanks) {
            r.Reject(
                "pm8058 gpio %u: restored read bank %u is outside the %u the "
                "part has", g, read_bank_[g], kBanks);
        }
        for (uint32_t b = 0; b < kBanks; ++b) r.Read("bank_data", bank_data_[g][b]);
    }
}

REGISTER_SERVICE(Pm8058Gpio);
