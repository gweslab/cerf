#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x10C001C0u;

/* Clock Control Register (§6.3.1): CHICLKDIV[7:0]<31:24>, CHIMCLKSEL<21>, CHICLKDIR<20>,
   ENCHIMCLK<19>, ENVIDCLK<18>, ENMBUSCLK<17>, ENSPICLK<16>, ENTIMERCLK<15>, SIBMCLKDIR<13>,
   ENSIBMCLK<11>, SIBMCLKDIV[2:0]<10:8>, CSERSEL<7> reset 1, CSERDIV[2:0]<6:4>, ENCSERCLK<3>,
   ENIRCLK<2>, ENUARTACLK<1>, ENUARTBCLK<0>. Bits 23, 22 and 14 "must be zero". */
constexpr uint32_t kMustBeZero = (1u << 23) | (1u << 22) | (1u << 14);
constexpr uint32_t kCserSel    = 1u << 7;

class Pr31x00Clock : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd) return false;
        const std::string_view soc = bd->GetSocId();
        return soc == SocId::Pr31500 || soc == SocId::Pr31700;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return 0x4u; }

    uint32_t ReadWord(uint32_t addr) override {
        if (addr == kBase) return ctl_;
        HaltUnsupportedAccess("PR31x00 CLOCK ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        if (addr != kBase) HaltUnsupportedAccess("PR31x00 CLOCK WriteWord", addr, value);
        if (value & kMustBeZero) {
            HaltUnsupportedAccess("PR31x00 CLOCK reserved bits 23/22/14", addr, value);
        }
        ctl_ = value;
    }

    uint8_t  ReadByte(uint32_t addr) override { HaltUnsupportedAccess("PR31x00 CLOCK ReadByte", addr, 0); }
    uint16_t ReadHalf(uint32_t addr) override { HaltUnsupportedAccess("PR31x00 CLOCK ReadHalf", addr, 0); }
    void WriteByte(uint32_t addr, uint8_t  v) override { HaltUnsupportedAccess("PR31x00 CLOCK WriteByte", addr, v); }
    void WriteHalf(uint32_t addr, uint16_t v) override { HaltUnsupportedAccess("PR31x00 CLOCK WriteHalf", addr, v); }

    void SaveState(StateWriter& w) override { w.Write("ctl", ctl_); }
    void RestoreState(StateReader& r) override { r.Read("ctl", ctl_); }

private:
    uint32_t ctl_ = kCserSel;
};

}  /* namespace */

REGISTER_SERVICE(Pr31x00Clock);
