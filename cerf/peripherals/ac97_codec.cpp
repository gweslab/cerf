#include "ac97_codec.h"

#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../state/state_stream.h"

namespace {

constexpr uint32_t kFixedRateHz = 48000u;
constexpr uint16_t kFixedRate   = 0xBB80u;

}  // namespace

/* AC '97 Component Specification Revision 2.1 section 7 (page 47): a warm
   reset "will restart AC '97's digital interface (resetting PR4 to zero)". */
void Ac97Codec::WarmReset() {
    Poke(kRegPowerdown, static_cast<uint16_t>(Peek(kRegPowerdown) & ~kPr4));
}

/* AC '97 Component Specification Revision 2.1 Table 19: "PR4 Digital Interface
   (AC-link) powerdown (external clk off)". */
bool Ac97Codec::LinkPoweredDown() {
    return (Peek(kRegPowerdown) & kPr4) != 0u;
}

bool Ac97Codec::IsRateRegister(uint32_t reg) const { return reg == kRegDacRate || reg == kRegAdcRate; }

/* AC '97 Component Specification Revision 2.2 section 5.8.3 (page 61): "if the value written to the
   register is supported that value will be echoed back when read, otherwise the closest (higher in
   case of a tie) sample rate supported is returned". */
uint16_t Ac97Codec::NearestSupported(uint16_t value) const {
    uint32_t        count = 0;
    const uint16_t* rates = SupportedRates(count);
    uint16_t        best  = rates[0];
    for (uint32_t i = 1; i < count; ++i) {
        const uint32_t d    = value > rates[i] ? value - rates[i] : rates[i] - value;
        const uint32_t dbest = value > best ? value - best : best - value;
        if (d < dbest || (d == dbest && rates[i] > best)) best = rates[i];
    }
    return best;
}

/* AC '97 Component Specification Revision 2.2 section 5.8.3 (page 61): with VRA 0 "the registers are forced
   to BB80h". */
bool Ac97Codec::WriteRateRegister(uint32_t reg, uint16_t value) {
    if (!IsRateRegister(reg)) return false;
    if ((Peek(kRegExtAudioCtrl) & kVra) == 0u) {
        Poke(reg, kFixedRate);
        unsettled_ = static_cast<uint8_t>(unsettled_ & ~RateBit(reg));
        return true;
    }
    if (!RateWriteTakesEffect(reg)) {
        unsettled_ = static_cast<uint8_t>(unsettled_ | RateBit(reg));
        return true;
    }
    const uint16_t latched = NearestSupported(value);
    unsettled_ = static_cast<uint8_t>(unsettled_ & ~RateBit(reg));
    Poke(reg, latched);
    if (reg == kRegDacRate) dac_rate_ = latched;
    if (reg == kRegAdcRate) adc_rate_ = latched;
    return true;
}

bool Ac97Codec::RateWriteTakesEffect(uint32_t) { return true; }

void Ac97Codec::OnExtAudioCtrlWrite() {
    if ((Peek(kRegExtAudioCtrl) & kVra) != 0u) return;
    for (uint32_t reg = kRegDacRate; reg <= kRegAdcRate; reg += 2u) {
        if (IsRateRegister(reg)) Poke(reg, kFixedRate);
    }
    ResetRates();
}

uint16_t Ac97Codec::ReadStored(uint32_t reg) {
    if (IsRateRegister(reg) && (unsettled_ & RateBit(reg)) != 0u) {
        emu_.Get<Fatal>().Die("Ac97Codec: read of rate register 0x%02X after a rate write with its converter "
                              "powered down; not modelled", reg);
    }
    return Peek(reg);
}

void Ac97Codec::ResetRates() {
    dac_rate_  = kFixedRateHz;
    adc_rate_  = kFixedRateHz;
    unsettled_ = 0u;
}

void Ac97Codec::SaveRates(StateWriter& w) const {
    w.Write<uint32_t>("codec_dac_rate", dac_rate_);
    w.Write<uint32_t>("codec_adc_rate", adc_rate_);
    w.Write<uint8_t>("codec_rate_unsettled", unsettled_);
}

void Ac97Codec::RestoreRates(StateReader& r) {
    r.Read("codec_dac_rate", dac_rate_);
    r.Read("codec_adc_rate", adc_rate_);
    r.Read("codec_rate_unsettled", unsettled_);
}

uint16_t Ac97Codec::GpioSlotStatus(uint64_t frame) {
    emu_.Get<Fatal>().Die("Ac97Codec: slot-12 GPIO status at frame %llu from a codec that does not model it",
                          static_cast<unsigned long long>(frame));
}
