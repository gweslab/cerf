#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* Magicbus Control 1 Register, IFR offset $0E0 (TMPR3911 §11.4.1). */
constexpr uint32_t kBase = 0x10C000E0u;

/* §11.4.1: EMPTY<30> read-only, reset 1 (TX holding + shift empty). */
constexpr uint32_t kEmpty = 1u << 30;
/* §11.4.1: ENMBUS<1> module enable; with it clear the module is idle. */
constexpr uint32_t kEnMbus = 1u << 1;
/* §11.4.1: ENDMARX<16>..bit0 are R/W; 28-17 reserved, 31-29 read-only. */
constexpr uint32_t kWritable = 0x0001FFFFu;

class Pr31x00Magicbus : public Peripheral {
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
        if (addr == kBase) return kEmpty | ctl_;
        HaltUnsupportedAccess("PR31x00 MAGICBUS ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        if (addr != kBase) HaltUnsupportedAccess("PR31x00 MAGICBUS WriteWord", addr, value);
        if (value & kEnMbus) {
            HaltUnsupportedAccess("PR31x00 MAGICBUS ENMBUS (unmodelled transfer)", addr, value);
        }
        ctl_ = value & kWritable;
    }

    uint8_t  ReadByte(uint32_t addr) override { HaltUnsupportedAccess("PR31x00 MAGICBUS ReadByte", addr, 0); }
    uint16_t ReadHalf(uint32_t addr) override { HaltUnsupportedAccess("PR31x00 MAGICBUS ReadHalf", addr, 0); }
    void WriteByte(uint32_t addr, uint8_t  v) override { HaltUnsupportedAccess("PR31x00 MAGICBUS WriteByte", addr, v); }
    void WriteHalf(uint32_t addr, uint16_t v) override { HaltUnsupportedAccess("PR31x00 MAGICBUS WriteHalf", addr, v); }

    void SaveState(StateWriter& w) override { w.Write("ctl", ctl_); }
    void RestoreState(StateReader& r) override { r.Read("ctl", ctl_); }

private:
    uint32_t ctl_ = 0;
};

}  /* namespace */

REGISTER_SERVICE(Pr31x00Magicbus);
