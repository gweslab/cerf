#include "wm9705_codec.h"

#include "../../boards/board_context.h"
#include "../../boards/falcon_pc3xx/falcon_4220_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../state/state_stream.h"

namespace {
/* AC'97 vendor/device-ID registers + WM9705 identity. Values from the Linux
   wm97xx driver (include/linux/wm97xx.h: WM97XX_ID1 0x574d, WM9705_ID2 0x4c05)
   and confirmed against touch.dll sub_18E1CE8, which reads regs 0x7C/0x7E and
   requires vendor 0x574D + device 0x4C05 (WM9705) to enable the touchscreen. */
constexpr uint32_t kRegVendorId1 = 0x7Cu;
constexpr uint32_t kRegVendorId2 = 0x7Eu;
constexpr uint16_t kWm97xxId1    = 0x574Du;
constexpr uint16_t kWm9705Id2    = 0x4C05u;

/* WM9705 polling-mode ADC (Linux wm97xx.h + wm9705.c wm9705_poll_sample):
   a write to DIGITISER1 with POLL set starts a conversion on the channel in
   ADCSEL[14:12]; the device clears POLL when the conversion completes and
   returns the channel-tagged 12-bit result in DIGITISER_RD. */
constexpr uint32_t kRegDigitiser1  = 0x76u;  // AC97_WM97XX_DIGITISER1
constexpr uint32_t kRegDigitiserRd = 0x7Au;  // AC97_WM97XX_DIGITISER_RD
constexpr uint16_t kWmPoll         = 0x8000u;  // WM97XX_POLL
constexpr uint16_t kWmAdcselMask   = 0x7000u;  // WM97XX_ADCSEL_MASK
constexpr uint16_t kAdcselX        = 0x1000u;  // WM97XX_ADCSEL_X
constexpr uint16_t kAdcselY        = 0x2000u;  // WM97XX_ADCSEL_Y
constexpr uint16_t kAdcselPres     = 0x3000u;  // WM97XX_ADCSEL_PRES
constexpr uint16_t kAdcselBmon     = 0x5000u;  // WM97XX battery-monitor channel
/* battdrvr.dll sub_17F1668 reads battery mV = 3300 * adc / 4096 and treats
   >= 3100 mV as full; the WM9705 AUX ADC is 12-bit (wm97xx.h), so full-scale
   0x0FFF (3299 mV) reports a fully-charged battery. */
constexpr uint16_t kBmonAdc        = 0x0FFFu;
}  // namespace

bool Wm9705Codec::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Falcon4220;
}

void Wm9705Codec::OnReady() {
    reg_[kRegVendorId1] = kWm97xxId1;
    reg_[kRegVendorId2] = kWm9705Id2;
}

uint16_t Wm9705Codec::ReadReg(uint32_t reg) {
    return reg < kNumRegs ? reg_[reg] : 0u;
}

void Wm9705Codec::WriteReg(uint32_t reg, uint16_t value) {
    if (reg >= kNumRegs) return;
    reg_[reg] = value;
    if (reg != kRegDigitiser1 || (value & kWmPoll) == 0u) return;

    /* Complete a polling-mode ADC conversion (wm9705.c wm9705_poll_sample):
       publish the channel-tagged result in DIGITISER_RD, then clear POLL so the
       guest's "spin while POLL set" loop exits. */
    const uint16_t adcsel = value & kWmAdcselMask;
    switch (adcsel) {
        case kAdcselBmon:
            reg_[kRegDigitiserRd] = static_cast<uint16_t>(kAdcselBmon | kBmonAdc);
            break;
        case kAdcselX:
        case kAdcselY:
        case kAdcselPres:
            /* Only touch.dll's init panel-probe (sub_18E1B84) register-POLLs
               these channels, and it checks just the returned tag; runtime
               coordinates stream over AC-link slot 5. No pen at init, so the
               faithful sample is pen-up: tag set, PEN_DOWN (bit 15) clear. */
            reg_[kRegDigitiserRd] = adcsel;
            break;
        default:
            /* WIPER / AUX channels are never polled by the Falcon ROM. */
            LOG(Caution, "Wm9705Codec: unmodeled ADC POLL adcsel=0x%04X "
                         "(DIGITISER1=0x%04X)\n", adcsel, value);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    reg_[kRegDigitiser1] = static_cast<uint16_t>(value & ~kWmPoll);
}

void Wm9705Codec::SaveState(StateWriter& w) {
    w.WriteBytes("reg", reg_, sizeof(reg_));
}

void Wm9705Codec::RestoreState(StateReader& r) {
    r.ReadBytes("reg", reg_, sizeof(reg_));
}

REGISTER_SERVICE_AS(Wm9705Codec, Ac97Codec);
