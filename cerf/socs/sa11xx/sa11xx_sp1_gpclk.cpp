#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

namespace {

/* SA-1110 Dev Man §11.9.2-11.9.4: the Serial Port 1 GPCLK block (0x80020000)
   defines registers only at +0x60..+0x70; +0x78..+0xFFFF is reserved and on
   real HW reads 0 / ignores writes. Reserved offsets here do the same - the
   G138 OAL's SP1 reset writes 2/4 to +0x80 and 0x10 to +0x84. */

class Sa11xxSp1Gpclk : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x80020000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    uint32_t gpclkr0_ = 0;  /* SUS=0 reset state per §11.9.2. */
    uint32_t gpclkr1_ = 0;
    uint32_t gpclkr2_ = 0;
    uint32_t gpclkr3_ = 0;

    uint32_t ReadReg(uint32_t off) const;
    void     WriteReg(uint32_t off, uint32_t value);
};

uint32_t Sa11xxSp1Gpclk::ReadReg(uint32_t off) const {
    switch (off) {
        case 0x60: return gpclkr0_ & 0x33u;     /* bits 5,4,0 used + 1 reserved-bit space */
        case 0x64: return gpclkr1_ & 0x02u;     /* bit 1 TXE */
        case 0x6C: return gpclkr2_ & 0x0Fu;     /* bits 3:0 = BRD[11:8] */
        case 0x70: return gpclkr3_ & 0xFFu;     /* bits 7:0 = BRD[7:0] */
        default:   return 0;
    }
}

void Sa11xxSp1Gpclk::WriteReg(uint32_t off, uint32_t value) {
    switch (off) {
        case 0x60: gpclkr0_ = value & 0x33u; break;
        case 0x64: gpclkr1_ = value & 0x02u; break;
        case 0x6C: gpclkr2_ = value & 0x0Fu; break;
        case 0x70: gpclkr3_ = value & 0xFFu; break;
        default:   break;
    }
}

static bool IsGpclkOffset(uint32_t off) {
    return off == 0x60 || off == 0x64 || off == 0x6C || off == 0x70;
}

uint8_t Sa11xxSp1Gpclk::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsGpclkOffset(base)) return 0;   /* reserved: reads 0. */
    return static_cast<uint8_t>((ReadReg(base) >> shift) & 0xFFu);
}

uint32_t Sa11xxSp1Gpclk::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsGpclkOffset(off)) return 0;    /* reserved: reads 0. */
    return ReadReg(off);
}

void Sa11xxSp1Gpclk::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsGpclkOffset(base)) {            /* reserved: write ignored. */
        LOG(Periph, "[Sa11xxSp1Gpclk] reserved write +0x%02X (ignored)\n", off);
        return;
    }
    const uint32_t cur     = ReadReg(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    WriteReg(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Sa11xxSp1Gpclk::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsGpclkOffset(off)) {             /* reserved: write ignored. */
        LOG(Periph, "[Sa11xxSp1Gpclk] reserved write +0x%02X = 0x%08X (ignored)\n",
            off, value);
        return;
    }
    WriteReg(off, value);
}

void Sa11xxSp1Gpclk::SaveState(StateWriter& w) {
    w.Write("gpclkr0", gpclkr0_);
    w.Write("gpclkr1", gpclkr1_);
    w.Write("gpclkr2", gpclkr2_);
    w.Write("gpclkr3", gpclkr3_);
}

void Sa11xxSp1Gpclk::RestoreState(StateReader& r) {
    r.Read("gpclkr0", gpclkr0_);
    r.Read("gpclkr1", gpclkr1_);
    r.Read("gpclkr2", gpclkr2_);
    r.Read("gpclkr3", gpclkr3_);
}

}  /* namespace */

REGISTER_SERVICE(Sa11xxSp1Gpclk);
