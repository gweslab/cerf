#include "sa11xx_lcd.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../host/host_window.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

bool Sa11xxLcd::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
}

void Sa11xxLcd::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void Sa11xxLcd::PublishScreenSizeOnEnableEdge(uint32_t old_lccr0,
                                              uint32_t new_lccr0) {
    if (((old_lccr0 & 0x1u) == 0u) && ((new_lccr0 & 0x1u) != 0u)) {
        emu_.Get<HostWindow>().OnLcdEnabled();
    }
}

uint32_t Sa11xxLcd::ReadReg(uint32_t off) const {
    switch (off) {
        case 0x00: return lccr0_;
        case 0x04: return lcsr_;
        case 0x10: return dbar1_;
        case 0x14: return dbar1_;                  /* DCAR1 mirrors DBAR1 (no DMA modelled) */
        case 0x18: return dbar2_;
        case 0x1C: return dbar2_;                  /* DCAR2 mirrors DBAR2 */
        case 0x20: return lccr1_;
        case 0x24: return lccr2_;
        case 0x28: return lccr3_;
        default:   return 0;
    }
}

void Sa11xxLcd::WriteReg(uint32_t off, uint32_t value) {
    /* LCSR acks excluded: per-frame W1C would flood the log. */
    if (off != 0x04) LOG(Lcd, "Sa11xxLcd write +0x%02X = 0x%08X\n", off, value);
    switch (off) {
        case 0x00: {
            const uint32_t old = lccr0_;
            lccr0_ = value;
            PublishScreenSizeOnEnableEdge(old, value);
            /* §11.7.11: LCSR.LDD asserts on 1→0 of LCCR0.LEN (last frame
               complete after disable). Kernel sub_800AABBC spins on this
               bit; without it the JIT hangs in that polling loop forever. */
            if ((old & 0x1u) != 0u && (value & 0x1u) == 0u) lcsr_ |= 0x1u;
            break;
        }
        case 0x04: lcsr_ &= ~value; break;         /* §11.7.11: status W1C */
        case 0x10: dbar1_ = value; break;
        case 0x14: break;                          /* DCAR1 R-O */
        case 0x18: dbar2_ = value; break;
        case 0x1C: break;                          /* DCAR2 R-O */
        case 0x20: lccr1_ = value; break;
        case 0x24: lccr2_ = value; break;
        case 0x28: lccr3_ = value; break;
        default:   break;
    }
}

uint8_t Sa11xxLcd::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("ReadByte", addr, 0);
    return static_cast<uint8_t>((ReadReg(base) >> shift) & 0xFFu);
}

uint32_t Sa11xxLcd::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return ReadReg(off);
}

void Sa11xxLcd::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("WriteByte", addr, value);
    const uint32_t cur     = ReadReg(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    WriteReg(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Sa11xxLcd::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    WriteReg(off, value);
}

void Sa11xxLcd::SaveState(StateWriter& w) {
    w.Write("lccr0", lccr0_);
    w.Write("lcsr", lcsr_);
    w.Write("dbar1", dbar1_);
    w.Write("dbar2", dbar2_);
    w.Write("lccr1", lccr1_);
    w.Write("lccr2", lccr2_);
    w.Write("lccr3", lccr3_);
}

void Sa11xxLcd::RestoreState(StateReader& r) {
    r.Read("lccr0", lccr0_);
    r.Read("lcsr", lcsr_);
    r.Read("dbar1", dbar1_);
    r.Read("dbar2", dbar2_);
    r.Read("lccr1", lccr1_);
    r.Read("lccr2", lccr2_);
    r.Read("lccr3", lccr3_);
}

REGISTER_SERVICE(Sa11xxLcd);
