#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "imx31_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

constexpr uint32_t kL2cBase        = 0x30000000u;
constexpr uint32_t kL2cSize        = 0x00001000u;

constexpr uint32_t kCacheIdConst   = 0xD5000041u;
constexpr uint32_t kCacheTypeConst = 0x1C100100u;
constexpr uint32_t kAuxCtrlReset   = 0xE4020FFFu;

class Imx31L2c : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx31;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kL2cBase; }
    uint32_t MmioSize() const override { return kL2cSize; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    /* JIT-thread-only register file (no worker thread). */
    void SaveState(StateWriter& w) override {
        w.Write("control", control_);
        w.Write("aux_control", aux_control_);
        w.Write("debug_control", debug_control_);
        w.Write("lockdown_d", lockdown_d_);
        w.Write("lockdown_i", lockdown_i_);
        w.Write("line_data", line_data_);
        w.Write("line_tag", line_tag_);
    }
    void RestoreState(StateReader& r) override {
        r.Read("control", control_);
        r.Read("aux_control", aux_control_);
        r.Read("debug_control", debug_control_);
        r.Read("lockdown_d", lockdown_d_);
        r.Read("lockdown_i", lockdown_i_);
        r.Read("line_data", line_data_);
        r.Read("line_tag", line_tag_);
    }

private:
    uint32_t control_       = 0u;
    uint32_t aux_control_   = kAuxCtrlReset;
    uint32_t debug_control_ = 0u;
    uint32_t lockdown_d_    = 0u;
    uint32_t lockdown_i_    = 0u;
    uint32_t line_data_     = 0u;
    uint32_t line_tag_      = 0u;
};

uint32_t Imx31L2c::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    switch (off) {
    case 0x000: return kCacheIdConst;
    case 0x004: return kCacheTypeConst;
    case 0x100: return control_;
    case 0x104: return aux_control_;
    case 0x730: return 0u;
    case 0x770: return 0u;
    case 0x77C: return 0u;
    case 0x7B0: return 0u;
    case 0x7B8: return 0u;
    case 0x7BC: return 0u;
    case 0x7F0: return 0u;
    case 0x7F8: return 0u;
    case 0x7FC: return 0u;
    case 0x900: return lockdown_d_;
    case 0x904: return lockdown_i_;
    case 0xF00: return 0u;
    case 0xF10: return line_data_;
    case 0xF30: return line_tag_;
    case 0xF40: return debug_control_;
    default:    HaltUnsupportedAccess("ReadWord", addr, 0);
    }
}

void Imx31L2c::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    switch (off) {
    case 0x000: case 0x004: case 0xF00:
        break;
    case 0x100: control_       = value; break;
    case 0x104: aux_control_   = value; break;
    case 0x730: case 0x770: case 0x77C:
    case 0x7B0: case 0x7B8: case 0x7BC:
    case 0x7F0: case 0x7F8: case 0x7FC:
        break;
    case 0x900: lockdown_d_    = value; break;
    case 0x904: lockdown_i_    = value; break;
    case 0xF10: line_data_     = value; break;
    case 0xF30: line_tag_      = value; break;
    case 0xF40: debug_control_ = value; break;
    default:    HaltUnsupportedAccess("WriteWord", addr, value);
    }
}

}  /* namespace */

REGISTER_SERVICE(Imx31L2c);
