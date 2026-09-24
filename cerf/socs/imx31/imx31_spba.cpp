#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "imx31_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

constexpr uint32_t kSpbaBase     = 0x5003C000u;
constexpr uint32_t kSpbaSize     = 0x00004000u;       /* 16 KB per Table 41-2 row */
constexpr uint32_t kPrrCount     = 32u;                /* 31 peripherals + SPBA itself */
constexpr uint32_t kPrrLast      = (kPrrCount - 1u) * 4u;

constexpr uint32_t kRoiMasterA   = 0b01u;              /* ARM port */

class Imx31Spba : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx31;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kSpbaBase; }
    uint32_t MmioSize() const override { return kSpbaSize; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    /* Per-PRR latched state. RAR is the 3-bit access mask the owner
       master wrote; owned_by_arm tracks whether the ARM (master A)
       currently owns the register. */
    struct Prr {
        uint8_t rar          = 0b111u;  /* reset value of RAR */
        bool    owned_by_arm = false;

        template <typename F>
        static constexpr void Visit(Prr& p, F& field) {
            field("rar", p.rar);
            field("owned_by_arm", p.owned_by_arm);
        }
    };
    Prr prrs_[kPrrCount];

    static bool OffsetToIndex(uint32_t off, uint32_t* index_out) {
        if (off > kPrrLast || (off & 0x3u) != 0) return false;
        *index_out = off / 4u;
        return true;
    }
};

uint32_t Imx31Spba::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t idx;
    if (!OffsetToIndex(off, &idx)) HaltUnsupportedAccess("ReadWord", addr, 0);

    const Prr& p = prrs_[idx];
    const uint32_t rar = static_cast<uint32_t>(p.rar) & 0x7u;
    const uint32_t roi = p.owned_by_arm ? kRoiMasterA : 0u;
    const uint32_t rmo = p.owned_by_arm ? 0b11u       : 0u;
    const uint32_t v   = (rmo << 30) | (roi << 16) | rar;
    LOG(Periph, "[SPBA] read  PRR%u (0x%08X) -> 0x%08X\n", idx, addr, v);
    return v;
}

void Imx31Spba::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    uint32_t idx;
    if (!OffsetToIndex(off, &idx)) HaltUnsupportedAccess("WriteWord", addr, value);

    Prr& p = prrs_[idx];
    p.rar          = static_cast<uint8_t>(value & 0x7u);
    p.owned_by_arm = (p.rar != 0u);
    LOG(Periph, "[SPBA] write PRR%u (0x%08X) := 0x%08X (RAR=%u owned_by_arm=%d)\n",
        idx, addr, value, p.rar, p.owned_by_arm);
}

void Imx31Spba::SaveState(StateWriter& w) {
    static_assert(StateVisitCoversAllBytes<Prr>(
                      [](Prr& p, StateFieldBytes& f) { Prr::Visit(p, f); }),
                  "Prr::Visit must name or skip every field of Prr");
    StateWriteField field(w);
    for (Prr& p : prrs_) Prr::Visit(p, field);
}

void Imx31Spba::RestoreState(StateReader& r) {
    StateReadField field(r);
    for (Prr& p : prrs_) Prr::Visit(p, field);
}

}  /* namespace */

REGISTER_SERVICE(Imx31Spba);
