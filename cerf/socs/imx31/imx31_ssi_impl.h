#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace cerf_imx31_ssi_detail {

/* MCIMX31RM Table 45-4/45-6 (Ch 45 SSI). 32-bit registers, 16 KB window. */
constexpr uint32_t kSize = 0x00004000u;

constexpr uint32_t kOffStx0  = 0x00u;
constexpr uint32_t kOffStx1  = 0x04u;
constexpr uint32_t kOffSrx0  = 0x08u;
constexpr uint32_t kOffSrx1  = 0x0Cu;
constexpr uint32_t kOffScr   = 0x10u;
constexpr uint32_t kOffSisr  = 0x14u;
constexpr uint32_t kOffSier  = 0x18u;
constexpr uint32_t kOffStcr  = 0x1Cu;
constexpr uint32_t kOffSrcr  = 0x20u;
constexpr uint32_t kOffStccr = 0x24u;
constexpr uint32_t kOffSrccr = 0x28u;
constexpr uint32_t kOffSfcsr = 0x2Cu;
constexpr uint32_t kOffSacnt = 0x38u;
constexpr uint32_t kOffSacadd= 0x3Cu;
constexpr uint32_t kOffSacdat= 0x40u;
constexpr uint32_t kOffSatag = 0x44u;
constexpr uint32_t kOffStmsk = 0x48u;
constexpr uint32_t kOffSrmsk = 0x4Cu;

/* SISR bits (Table 45-6): TFE0 b0, TFE1 b1, TDE0 b12, TDE1 b13. Report the
   TX FIFO/data always empty so the audio driver never blocks writing. */
constexpr uint32_t kSisrReady = (1u << 0) | (1u << 1) | (1u << 12) | (1u << 13);
/* Error flags TUE0/1 b8/9, ROE0/1 b10/11 are write-1-to-clear. */
constexpr uint32_t kSisrW1c = (1u << 8) | (1u << 9) | (1u << 10) | (1u << 11);

/* SFCSR (Figure 45-32): RFCNT1[31:28]/TFCNT1[27:24]/RFCNT0[15:12]/TFCNT0[11:8]
   are read-only FIFO occupancy counters; RFWM/TFWM watermark nibbles are R/W.
   With no real samples the FIFOs are always empty/drained, so the counter
   fields must read 0 — only the watermark bits read back as written. */
constexpr uint32_t kSfcsrWatermarkMask = 0x00FF00FFu;

template <uint32_t kBase>
class Imx31SsiImpl : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        switch (addr - kBase) {
            case kOffSrx0: case kOffSrx1: return 0;
            case kOffSisr:  return kSisrReady | (sisr_err_ & kSisrW1c);
            case kOffScr:   return scr_;
            case kOffSier:  return sier_;
            case kOffStcr:  return stcr_;
            case kOffSrcr:  return srcr_;
            case kOffStccr: return stccr_;
            case kOffSrccr: return srccr_;
            case kOffSfcsr: return sfcsr_ & kSfcsrWatermarkMask;
            case kOffSacnt: return sacnt_;
            case kOffSacadd:return sacadd_;
            case kOffSacdat:return sacdat_;
            case kOffSatag: return satag_;
            case kOffStmsk: return stmsk_;
            case kOffSrmsk: return srmsk_;
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        switch (addr - kBase) {
            /* Audio careful stub (§0.3): TX samples are discarded, no output. */
            case kOffStx0: case kOffStx1: return;
            case kOffSisr:  sisr_err_ &= ~(value & kSisrW1c); return;
            case kOffScr:   scr_   = value; return;
            case kOffSier:  sier_  = value; return;
            case kOffStcr:  stcr_  = value; return;
            case kOffSrcr:  srcr_  = value; return;
            case kOffStccr: stccr_ = value; return;
            case kOffSrccr: srccr_ = value; return;
            case kOffSfcsr: sfcsr_ = value; return;
            case kOffSacnt: sacnt_ = value; return;
            case kOffSacadd:sacadd_= value; return;
            case kOffSacdat:sacdat_= value; return;
            case kOffSatag: satag_ = value; return;
            case kOffStmsk: stmsk_ = value; return;
            case kOffSrmsk: srmsk_ = value; return;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

private:
    uint32_t scr_ = 0, sier_ = 0, stcr_ = 0, srcr_ = 0, stccr_ = 0, srccr_ = 0,
             sfcsr_ = 0, sacnt_ = 0, sacadd_ = 0, sacdat_ = 0, satag_ = 0,
             stmsk_ = 0, srmsk_ = 0, sisr_err_ = 0;
};

}  /* namespace cerf_imx31_ssi_detail */
