#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/state_stream.h"
#include "../board_context.h"

#include <cstdint>

namespace {

/* casio_cassiopeia_e55 serial.dll sub_14A2228 @0x14A2370/@0x14A2380. */
constexpr uint32_t kBase = 0x14008000u;
constexpr uint32_t kSize = 0x1000u;

/* casio_cassiopeia_e55 nk.exe @0x9E817DD4 lh 2($a1) / @0x9E817DD8 srl 8 / @0x9E817DDC and,
   branches @0x9E817DE0, @0x9E817DE8, @0x9E817DF0; @0x9E817E3C, @0x9E817E98, @0x9E818144,
   @0x9E818388, @0x9E8183E8; sub_9E815378 @0x9E81538C; sub_9E8144D4 @0x9E81484C. */
constexpr uint32_t kOffIntr       = 0x002u;
constexpr uint16_t kEnableMask    = 0x0700u;
constexpr uint16_t kSource0Status = 0x0001u;

/* casio_cassiopeia_e55 nk.exe sub_9E8144D4 @0x9E814BF0 lh / ori 2 / @0x9E814BF8 sh, then
   @0x9E814C30 lh / andi 0xFFFD / @0x9E814C38 sh; sub_9E816964 @0x9E816A68 lhu /
   andi 0xFFFD / @0x9E816A70 sh. */
constexpr uint32_t kOffReg0A    = 0x00Au;
constexpr uint16_t kReg0ABit1   = 0x0002u;

/* casio_cassiopeia_e55 nk.exe @0x9E818048 lh 0x404($a0) / ori 0x200 / @0x9E818050 sh;
   sub_9E83CA38 @0x9E83CA4C lhu 0xB4008404 / andi 0xFDFF / @0x9E83CA58 sh. */
constexpr uint32_t kOffReg404   = 0x404u;
constexpr uint16_t kReg404Bit9  = 0x0200u;

class CasioCassiopeiaE55ModemSocket : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::CasioCassiopeiaE55;
    }

    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            enable_ = 0u;
        });
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint16_t ReadHalf(uint32_t addr) override {
        if (addr - kBase == kOffIntr) {
            return enable_;
        }
        if (addr - kBase == kOffReg0A) {
            return 0u;
        }
        if (addr - kBase == kOffReg404) {
            return 0u;
        }
        return Peripheral::ReadHalf(addr);
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        if (addr - kBase == kOffIntr) {
            if (value & ~static_cast<uint16_t>(kEnableMask | kSource0Status)) {
                HaltUnsupportedAccess("WriteHalf", addr, value);
            }
            enable_ = static_cast<uint16_t>(value & kEnableMask);
            return;
        }
        if (addr - kBase == kOffReg0A) {
            if (value & ~static_cast<uint16_t>(kReg0ABit1)) {
                HaltUnsupportedAccess("WriteHalf", addr, value);
            }
            return;
        }
        if (addr - kBase == kOffReg404) {
            if (value & ~static_cast<uint16_t>(kReg404Bit9)) {
                HaltUnsupportedAccess("WriteHalf", addr, value);
            }
            return;
        }
        Peripheral::WriteHalf(addr, value);
    }

    void SaveState(StateWriter& w) override {
        w.Write(enable_);
    }
    void RestoreState(StateReader& r) override {
        r.Read(enable_);
    }

private:
    uint16_t enable_ = 0u;
};

}  /* namespace */

REGISTER_SERVICE(CasioCassiopeiaE55ModemSocket);
