#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../host/guest_deep_sleep.h"
#include "../../state/state_stream.h"
#include "sa1110_id.h"
#include "sa1100_id.h"

namespace {

/* SA-1110 Power Manager - Dev Man §9.5.7-9.5.8. PSSR (+0x4) bits 4:0
   are W1C; POSR (+0x1C) bit 0 OOK (32-kHz oscillator stable) reads 1 -
   the emulated oscillator is stable from reset. */

class Sa11xxPowerManager : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x90020000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    uint32_t pmcr_ = 0;
    uint32_t pssr_ = 0;
    uint32_t pspr_ = 0;
    uint32_t pwer_ = 0;
    uint32_t pcfr_ = 0;
    uint32_t ppcr_ = 0;
    uint32_t pgsr_ = 0;

    uint32_t ReadReg(uint32_t off) const;
    void     WriteReg(uint32_t off, uint32_t value);

    static bool IsKnown(uint32_t off) {
        switch (off) {
            case 0x00: case 0x04: case 0x08: case 0x0C:
            case 0x10: case 0x14: case 0x18: case 0x1C:
                return true;
            default:
                return false;
        }
    }
};

uint32_t Sa11xxPowerManager::ReadReg(uint32_t off) const {
    switch (off) {
        case 0x00: return pmcr_;
        case 0x04: return pssr_ & 0x1Fu;     /* bits 4:0 PH|DH|VFS|BFS|SSS */
        case 0x08: return pspr_;
        case 0x0C: return pwer_;
        case 0x10: return pcfr_;
        case 0x14: return ppcr_;
        case 0x18: return pgsr_ & 0x0FFFFFFFu;  /* bits 27:0 SS27..SS0 */
        case 0x1C: return 0x1u;              /* POSR.OOK always set */
        default:   return 0;
    }
}

void Sa11xxPowerManager::WriteReg(uint32_t off, uint32_t value) {
    switch (off) {
        case 0x00:
            /* PMCR bit0 SF forces sleep mode (Dev Man §9.5.7.1; HW clears it on
               wake). HW halts the chip until a wake event resets it (§9.5.3.3);
               GuestDeepSleep halts the CPU and runs the recovery prompt. */
            if (value & 0x1u) {
                pssr_ |= 0x1u;   /* §9.5.7.5 SSS: sleep entered via the SF bit */
                emu_.Get<GuestDeepSleep>().Enter();
            }
            pmcr_ = value & ~0x1u;
            break;
        case 0x04: pssr_ &= ~(value & 0x1Fu); break;  /* W1C on bits 4:0 */
        case 0x08: pspr_ = value; break;
        case 0x0C: pwer_ = value; break;
        case 0x10: pcfr_ = value; break;
        case 0x14: ppcr_ = value; break;
        case 0x18: pgsr_ = value & 0x0FFFFFFFu; break;
        case 0x1C: break;                    /* POSR is read-only */
        default:   break;
    }
}

uint8_t Sa11xxPowerManager::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("ReadByte", addr, 0);
    return static_cast<uint8_t>((ReadReg(base) >> shift) & 0xFFu);
}

uint32_t Sa11xxPowerManager::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return ReadReg(off);
}

void Sa11xxPowerManager::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("WriteByte", addr, value);
    const uint32_t cur     = ReadReg(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    WriteReg(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Sa11xxPowerManager::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    WriteReg(off, value);
}

void Sa11xxPowerManager::SaveState(StateWriter& w) {
    w.Write("pmcr", pmcr_);
    w.Write("pssr", pssr_);
    w.Write("pspr", pspr_);
    w.Write("pwer", pwer_);
    w.Write("pcfr", pcfr_);
    w.Write("ppcr", ppcr_);
    w.Write("pgsr", pgsr_);
}

void Sa11xxPowerManager::RestoreState(StateReader& r) {
    r.Read("pmcr", pmcr_);
    r.Read("pssr", pssr_);
    r.Read("pspr", pspr_);
    r.Read("pwer", pwer_);
    r.Read("pcfr", pcfr_);
    r.Read("ppcr", ppcr_);
    r.Read("pgsr", pgsr_);
}

}  /* namespace */

REGISTER_SERVICE(Sa11xxPowerManager);
