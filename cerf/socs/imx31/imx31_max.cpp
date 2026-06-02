#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

constexpr uint32_t kMaxBase     = 0x43F04000u;
constexpr uint32_t kMaxSize     = 0x00004000u;
constexpr uint32_t kMprReset    = 0x00543210u;

constexpr uint32_t kSlavePorts  = 5u;
constexpr uint32_t kMasterPorts = 6u;

class Imx31Max : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override {
        for (uint32_t i = 0; i < kSlavePorts; ++i) mpr_[i] = kMprReset;
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kMaxBase; }
    uint32_t MmioSize() const override { return kMaxSize; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    uint32_t mpr_   [kSlavePorts]  = {};   /* offset 0x000 + N*0x100 */
    uint32_t sgpcr_ [kSlavePorts]  = {};   /* offset 0x010 + N*0x100 */
    uint32_t mgpcr_ [kMasterPorts] = {};   /* offset 0x800 + M*0x100 */

    enum class Kind { Mpr, Sgpcr, Mgpcr, Invalid };

    static Kind ClassifyOffset(uint32_t off, uint32_t* slot_out) {
        if (off < 0x800) {
            const uint32_t port    = off / 0x100;
            const uint32_t in_port = off % 0x100;
            if (port >= kSlavePorts) return Kind::Invalid;
            if (in_port == 0x000) { *slot_out = port; return Kind::Mpr; }
            if (in_port == 0x010) { *slot_out = port; return Kind::Sgpcr; }
            return Kind::Invalid;
        }
        if (off >= 0x800 && off < 0xE00 && (off & 0xFFu) == 0u) {
            *slot_out = (off - 0x800u) / 0x100u;
            if (*slot_out >= kMasterPorts) return Kind::Invalid;
            return Kind::Mgpcr;
        }
        return Kind::Invalid;
    }
};

uint32_t Imx31Max::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t slot;
    switch (ClassifyOffset(off, &slot)) {
    case Kind::Mpr:   return mpr_[slot];
    case Kind::Sgpcr: return sgpcr_[slot];
    case Kind::Mgpcr: return mgpcr_[slot];
    case Kind::Invalid:
    default:          HaltUnsupportedAccess("ReadWord", addr, 0);
    }
}

void Imx31Max::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    uint32_t slot;
    switch (ClassifyOffset(off, &slot)) {
    case Kind::Mpr:   mpr_[slot]   = value; break;
    case Kind::Sgpcr: sgpcr_[slot] = value; break;
    case Kind::Mgpcr: mgpcr_[slot] = value; break;
    case Kind::Invalid:
    default:          HaltUnsupportedAccess("WriteWord", addr, value);
    }
}

}  /* namespace */

REGISTER_SERVICE(Imx31Max);
