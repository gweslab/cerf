#include "../vr41xx/vr41xx_siu.h"

#include "../../boards/board_context.h"
#include "vr4102_id.h"
#include "../../core/cerf_emulator.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

class Vr4102Siu : public Vr41xxSiu {
public:
    using Vr41xxSiu::Vr41xxSiu;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Vr4102;
    }

protected:
    /* 0x09 is undocumented (VR4102 UM ch.24 ends at 0x08 SIUIRSEL) - grounded from the
       MobilePro serial.dll baud setup (sub_158116C), which pulses bit 0 as a divisor-
       reload strobe. */
    uint32_t ReadChipExtReg(uint32_t idx) override {
        if (idx == 9u) return baud_reload_;
        return Vr41xxSiu::ReadChipExtReg(idx);
    }
    void WriteChipExtReg(uint32_t idx, uint32_t value) override {
        if (idx == 9u) { baud_reload_ = static_cast<uint8_t>(value & 0xFFu); return; }
        Vr41xxSiu::WriteChipExtReg(idx, value);
    }
    void ResetChip() override                      { baud_reload_ = 0; }
    void SaveChipState(StateWriter& w) override    { w.Write("baud_reload", baud_reload_); }
    void RestoreChipState(StateReader& r) override { r.Read("baud_reload", baud_reload_); }

private:
    uint8_t baud_reload_ = 0;   /* SIU 0x09 divisor-reload strobe */
};

}  /* namespace */

REGISTER_SERVICE(Vr4102Siu);
