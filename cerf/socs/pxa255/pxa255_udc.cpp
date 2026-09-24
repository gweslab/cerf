#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "pxa255_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* PXA255 USB Device Controller (§12, base 0x40600000), modeled disconnected: no
   USB host, so no events. Per-endpoint UDCCS0-15 read their reset values (IN
   TFS=1, OUT/control 0), interrupt status (USIR0/1) reads 0, control/mask
   registers are plain storage. */
class Pxa255Udc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Pxa255;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        /* Tables 12-14..12-19: IN endpoints reset with TFS=1 (transmit FIFO has
           room); OUT and control endpoints reset to 0. */
        for (uint32_t n = 0; n < 16u; ++n)
            udccs_[n] = ((kUdccsInMask >> n) & 1u) ? 0x01u : 0x00u;
    }

    uint32_t MmioBase() const override { return 0x40600000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    static constexpr uint32_t kUdccrRwMask = 0xA5u;  /* REM|SRM|RSM|UDE */
    static constexpr uint32_t kUicrMask    = 0xFFu;  /* IM0..IM7 / IM8..IM15 */
    /* IN endpoints (Bulk/Iso/Interrupt IN = EP 1,3,5,6,8,10,11,13,15) reset TFS=1
       with only FST writable (Tables 12-15/17/19); OUT + control endpoints reset
       0 with FST + DME/DRWF writable (Tables 12-14/16/18). */
    static constexpr uint32_t kUdccsInMask = 0xAD6Au;
    static constexpr uint32_t kUdccsInRw   = 0x20u;  /* FST. */
    static constexpr uint32_t kUdccsOutRw  = 0x28u;  /* FST | DME/DRWF. */
    static constexpr uint32_t kUdccfrRw    = 0x84u;  /* UDCCFR AREN | ACM. */
    static constexpr uint32_t kUdccfrMb1   = 0x7Bu;  /* UDCCFR must-be-1 bits [6:3]/[1:0]. */

    uint32_t udccr_  = 0xA0u;  /* §12.6.1 reset: REM=1, SRM=1. */
    uint32_t udccfr_ = 0xFFu;  /* §12.6.2 Table 12-13 reset: AREN|MB1|ACM|MB1. */
    uint32_t uicr0_  = 0xFFu;  /* §12.6.9  Table 12-20 reset: all EP int masked. */
    uint32_t uicr1_  = 0xFFu;  /* §12.6.10 Table 12-21 reset: all EP int masked. */
    uint32_t udccs_[16] = {};  /* per-endpoint control/status, reset in OnReady. */
};

uint32_t Pxa255Udc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off >= 0x10u && off <= 0x4Cu && (off & 0x3u) == 0u)
        return udccs_[(off - 0x10u) >> 2];   /* UDCCS0-15 disconnected-idle state. */
    switch (off) {
        case 0x00: return udccr_;
        case 0x04: return 0u;      /* §12.7 Table 12-33: reserved. */
        case 0x08: return udccfr_; /* UDCCFR §12.6.2. */
        case 0x0C: return 0u;      /* §12.7 Table 12-33: reserved. */
        case 0x50: return uicr0_;
        case 0x54: return uicr1_;
        case 0x58: return 0u;  /* USIR0 §12.6.11: no host → no pending int. */
        case 0x5C: return 0u;  /* USIR1: no host → no pending int. */
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa255Udc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off >= 0x10u && off <= 0x4Cu && (off & 0x3u) == 0u) {
        const uint32_t n = (off - 0x10u) >> 2;
        const bool in_ep = ((kUdccsInMask >> n) & 1u) != 0u;
        /* No host attached, so the W1C status bits never set: a write keeps only
           the RW config (FST, plus DME/DRWF on OUT/control) and the read-only
           TFS=1 on IN endpoints. */
        udccs_[n] = (value & (in_ep ? kUdccsInRw : kUdccsOutRw)) | (in_ep ? 0x01u : 0x00u);
        return;
    }
    switch (off) {
        case 0x00: udccr_ = value & kUdccrRwMask; return;
        case 0x04: return;  /* §12.7 Table 12-33: reserved. */
        /* UDCCFR §12.6.2 Table 12-13: AREN (bit7) + ACM (bit2) R/W; the MB1 bits
           [6:3]/[1:0] always read 1; [31:8] reserved. */
        case 0x08: udccfr_ = (value & kUdccfrRw) | kUdccfrMb1; return;
        case 0x0C: return;  /* §12.7 Table 12-33: reserved. */
        case 0x50: uicr0_ = value & kUicrMask;    return;
        case 0x54: uicr1_ = value & kUicrMask;    return;
        case 0x58: return;  /* USIR0 W1C: status bits never set with no host. */
        case 0x5C: return;  /* USIR1 W1C. */
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa255Udc::SaveState(StateWriter& w) {
    w.Write("udccr", udccr_); w.Write("udccfr", udccfr_); w.Write("uicr0", uicr0_); w.Write("uicr1", uicr1_);
    w.WriteBytes("udccs", udccs_, sizeof(udccs_));
}

void Pxa255Udc::RestoreState(StateReader& r) {
    r.Read("udccr", udccr_); r.Read("udccfr", udccfr_); r.Read("uicr0", uicr0_); r.Read("uicr1", uicr1_);
    r.ReadBytes("udccs", udccs_, sizeof(udccs_));
}

}  /* namespace */

REGISTER_SERVICE(Pxa255Udc);
