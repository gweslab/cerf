#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "vr4122_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "vr4122_clock_state.h"

#include <cstdint>

namespace {

/* VR4122 BCU (Bus Control Unit) at 0x0F000000 (VR4131 UM U15350EJ2V0UM Table 7-1;
   NetBSD vripreg.h VR4122_BCU_ADDR). BCU registers 0x00-0x16; DMAAU follows at 0x20. */
constexpr uint32_t kBase = 0x0F000000u;
constexpr uint32_t kSize = 0x20u;

/* BCUCNTREG1 (R/W): D13:12 PAGESIZE, D10 PAGEROM2, D8 PAGEROM0, D6 ROMWEN2, D4 ROMWEN0,
   D2 HLDEN R/W; D15:14/D11/D9/D7/D5/D3/D1:0 RFU (R, read 0); RTCRST = After reset = 0
   (VR4131 UM U15350EJ2V0UM 7.2.1, p.134). */
constexpr uint32_t kOffCntReg1  = 0x00u;
constexpr uint16_t kCntReg1Mask = 0x3554u;

constexpr uint32_t kOffClkSpeed = 0x14u;   /* CLKSPEEDREG (R), VR4131 UM Table 7-1 */

/* REVIDREG (R): D15:12 RID, D11:8 MJREV, D7:4 RFU read-0, D3:0 MNREV; RTCRST column
   RID=0100 (VR4131 UM 7.2.6 p.141; NetBSD bcureg.h:405 BCUREVID_REG_W 0x010, :411
   BCUREVID_RID_4122 0x4). Guest reads it into $zero in the vector templates
   @0x9F03C0AC-B4 / @0x9F03C0C0-C4 (installer sub_9F03C044). */
constexpr uint32_t kOffRevId = 0x10u;
constexpr uint16_t kRevId    = 0x4000u;

class Vr4122Bcu : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Vr4122;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().RegisterResetListener(
            [this](ResetLineKind) { cntreg1_ = 0; });
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint16_t ReadHalf(uint32_t addr) override {
        switch (addr - kBase) {
            case kOffCntReg1:  return cntreg1_;
            case kOffRevId:    return kRevId;
            case kOffClkSpeed: return emu_.Get<Vr4122ClockState>().ClkSpeedReg();
            default: HaltUnsupportedAccess("VR4122 BCU ReadHalf", addr, 0);
        }
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        if (addr - kBase == kOffCntReg1) {
            cntreg1_ = static_cast<uint16_t>(value & kCntReg1Mask);
            return;
        }
        HaltUnsupportedAccess("VR4122 BCU WriteHalf", addr, value);
    }

    void SaveState(StateWriter& w) override { w.Write("cntreg1", cntreg1_); }
    void RestoreState(StateReader& r) override { r.Read("cntreg1", cntreg1_); }

private:
    uint16_t cntreg1_ = 0;
};

}  /* namespace */

REGISTER_SERVICE(Vr4122Bcu);
