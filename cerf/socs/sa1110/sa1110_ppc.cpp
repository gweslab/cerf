#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

/* SA-1110 Dev Man §11.13.8: PPDR/PPSR/PPAR/PSDR/PPFR at +0x00/04/08/0C/10. */

class Sa1110Ppc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::SA1110;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x90060000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    uint32_t regs_[5] = {};  /* PPDR, PPSR, PPAR, PSDR, PPFR */

    static bool OffsetToIndex(uint32_t off, uint32_t* index_out) {
        if (off > 0x10 || (off & 0x3u) != 0) return false;
        *index_out = off / 4u;
        return true;
    }
};

uint8_t Sa1110Ppc::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    uint32_t index;
    if (!OffsetToIndex(base, &index)) HaltUnsupportedAccess("ReadByte", addr, 0);
    return static_cast<uint8_t>((regs_[index] >> shift) & 0xFFu);
}

uint32_t Sa1110Ppc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t index;
    if (!OffsetToIndex(off, &index)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return regs_[index];
}

void Sa1110Ppc::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    uint32_t index;
    if (!OffsetToIndex(base, &index)) HaltUnsupportedAccess("WriteByte", addr, value);
    const uint32_t cur     = regs_[index];
    const uint32_t cleared = cur & ~(0xFFu << shift);
    regs_[index] = cleared | (static_cast<uint32_t>(value) << shift);
}

void Sa1110Ppc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    uint32_t index;
    if (!OffsetToIndex(off, &index)) HaltUnsupportedAccess("WriteWord", addr, value);
    regs_[index] = value;
}

}  /* namespace */

REGISTER_SERVICE(Sa1110Ppc);
