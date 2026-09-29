#include "../vr41xx/vr41xx_rtc.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "vr4122_id.h"

#include <cstdint>

namespace {

/* VR4122 RTC (VR4131 UM U15350EJ2V0UM Table 13-1): one contiguous window at
   0x0F000100 - ETIME/ECMP/RTCLong1/RTCLong2 at offset 0x00-0x1E (same as the
   VR4102/4121 RTC1 block), TClock at 0x20-0x26 and RTCINTREG at 0x3E folded into
   this window, where the VR4102/4121 place them in a separate RTC2 block. */
class Vr4122Rtc : public Vr41xxRtc {
public:
    using Vr41xxRtc::Vr41xxRtc;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Vr4122;
    }

    uint32_t MmioBase() const override { return 0x0F000100u; }
    uint32_t MmioSize() const override { return 0x40u; }     /* 0x100-0x13F, GIU at 0x140 */

    /* Table 13-1: TCLKLREG 0x120-0x126, RTCINTREG 0x13E == RTC2-block 0x00-0x06/0x1E at +0x20. */
    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (off >= 0x20u) return ReadHalf2(off - 0x20u);
        return Vr41xxRtc::ReadHalf(addr);
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off >= 0x20u) { WriteHalf2(off - 0x20u, value); return; }
        Vr41xxRtc::WriteHalf(addr, value);
    }
};

}  /* namespace */

REGISTER_SERVICE_AS(Vr4122Rtc, Vr41xxRtc);
