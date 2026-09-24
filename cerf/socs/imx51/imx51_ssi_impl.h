#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../freescale_sdma_bus.h"

#include <cstdint>

namespace cerf_imx51_ssi_detail {

/* i.MX51 SSI audio port, MCIMX51RM Ch 56 - an audio careful-stub with a data
   sink (agent_docs/rules.md): registers are modeled per the shared SSI IP
   documented in MCIMX31RM Ch 45 (identical block), i.MX51 contributes only the
   reset values below (MCIMX51RM Ch 56 register summary, p56-25/26). */
constexpr uint32_t kSize = 0x00004000u;   /* AIPS slot, MCIMX51RM Table 2-1 */

constexpr uint32_t kOffStx0   = 0x00u;
constexpr uint32_t kOffStx1   = 0x04u;
constexpr uint32_t kOffSrx0   = 0x08u;
constexpr uint32_t kOffSrx1   = 0x0Cu;
constexpr uint32_t kOffScr    = 0x10u;
constexpr uint32_t kOffSisr   = 0x14u;
constexpr uint32_t kOffSier   = 0x18u;
constexpr uint32_t kOffStcr   = 0x1Cu;
constexpr uint32_t kOffSrcr   = 0x20u;
constexpr uint32_t kOffStccr  = 0x24u;
constexpr uint32_t kOffSrccr  = 0x28u;
constexpr uint32_t kOffSfcsr  = 0x2Cu;
constexpr uint32_t kOffStr    = 0x30u;
constexpr uint32_t kOffSacnt  = 0x38u;
constexpr uint32_t kOffSacadd = 0x3Cu;
constexpr uint32_t kOffSacdat = 0x40u;
constexpr uint32_t kOffSatag  = 0x44u;
constexpr uint32_t kOffStmsk  = 0x48u;
constexpr uint32_t kOffSrmsk  = 0x4Cu;

/* SISR bits (MCIMX31RM Table 45-6): TFE0 b0, TFE1 b1, TDE0 b12, TDE1 b13.
   The FIFOs drain instantly, so the ready set reads constant - which equals
   the MCIMX51RM Ch 56 SISR reset value 0x3003. */
constexpr uint32_t kSisrReady = (1u << 0) | (1u << 1) | (1u << 12) | (1u << 13);
/* TUE0/1 b8/b9, ROE0/1 b10/b11 are write-1-to-clear. */
constexpr uint32_t kSisrW1c = (1u << 8) | (1u << 9) | (1u << 10) | (1u << 11);

/* SFCSR (MCIMX31RM Figure 45-32): RFCNT/TFCNT occupancy nibbles read 0 with
   instant drain; only the R/W watermark nibbles read back. */
constexpr uint32_t kSfcsrWatermarkMask = 0x00FF00FFu;

template <uint32_t kBase>
class Imx51SsiImpl : public Peripheral, public FreescaleSdmaPeripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override {
        sisr_err_ = 0;
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        switch (addr - kBase) {
            case kOffStx0: case kOffStx1:
            case kOffSrx0: case kOffSrx1: return 0;
            case kOffSisr:  return kSisrReady | (sisr_err_ & kSisrW1c);
            case kOffScr:   return scr_;
            case kOffSier:  return sier_;
            case kOffStcr:  return stcr_;
            case kOffSrcr:  return srcr_;
            case kOffStccr: return stccr_;
            case kOffSrccr: return srccr_;
            case kOffSfcsr: return sfcsr_ & kSfcsrWatermarkMask;
            case kOffStr:   return str_;
            case kOffSacnt: return sacnt_;
            case kOffSacadd:return sacadd_;
            case kOffSacdat:return sacdat_;
            case kOffSatag: return satag_;
            case kOffStmsk: return stmsk_;
            case kOffSrmsk: return srmsk_;
        }
        return 0;
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        switch (addr - kBase) {
            /* TX samples are discarded - there is no audio sink yet. */
            case kOffStx0: case kOffStx1: return;
            case kOffSisr:  sisr_err_ &= ~(value & kSisrW1c); return;
            case kOffScr:   scr_   = value; return;
            case kOffSier:  sier_  = value; return;
            case kOffStcr:  stcr_  = value; return;
            case kOffSrcr:  srcr_  = value; return;
            case kOffStccr: stccr_ = value; return;
            case kOffSrccr: srccr_ = value; return;
            case kOffSfcsr: sfcsr_ = value; return;
            case kOffStr:   str_   = value; return;
            case kOffSacnt: sacnt_ = value; return;
            case kOffSacadd:sacadd_= value; return;
            case kOffSacdat:sacdat_= value; return;
            case kOffSatag: satag_ = value; return;
            case kOffStmsk: stmsk_ = value; return;
            case kOffSrmsk: srmsk_ = value; return;
        }
    }

    /* FreescaleSdmaPeripheral: SDMA memory->peripheral scripts deliver PCM here.
       Discarding keeps an unclaimed audio channel completing at HSTART instead
       of halting (agent_docs/rules.md audio careful-stub). */
    void SdmaTxByte(uint8_t) override {}

    /* Words per transmit frame: DC4-DC0 + 1 (MCIMX31RM Table 45-14). */
    uint32_t TxWordsPerFrame() const { return ((stccr_ >> 8) & 0x1Fu) + 1u; }

    /* Bits per transmit word: WL[3:0] indexes 2,4,..,32 (MCIMX31RM Table 45-15). */
    uint32_t TxWordLengthBits() const { return (((stccr_ >> 13) & 0xFu) + 1u) * 2u; }

    /* f_bit = ssi_clk / [(DIV2+1) x (7 x PSR + 1) x (PM+1) x 2],
       f_frame = f_bit / [(DC+1) x WL] (MCIMX31RM Figure 45-42, same SSI IP). */
    uint32_t TxFrameRateHz(uint32_t ssi_clk_hz) const {
        const uint32_t div2 = (stccr_ >> 18) & 0x1u;
        const uint32_t psr  = (stccr_ >> 17) & 0x1u;
        const uint32_t pm   = stccr_ & 0xFFu;
        const uint32_t bit_div = (div2 + 1u) * (7u * psr + 1u) * (pm + 1u) * 2u;
        const uint32_t frame_bits = TxWordsPerFrame() * TxWordLengthBits();
        if (bit_div == 0 || frame_bits == 0) return 0;
        return ssi_clk_hz / bit_div / frame_bits;
    }

    /* SCR bit0 SSIEN, bit1 TE (MCIMX31RM Figure 45-24). */
    bool TxEnabled() const { return (scr_ & 0x1u) != 0 && (scr_ & 0x2u) != 0; }

    /* SISR TUE0 (bit 8): the transmitter ran out of data for a frame. */
    void NoteTxUnderrun() { sisr_err_ |= (1u << 8); }

    void SaveState(StateWriter& w) override {
        w.Write("scr", scr_);    w.Write("sier", sier_);   w.Write("stcr", stcr_);   w.Write("srcr", srcr_);
        w.Write("stccr", stccr_);  w.Write("srccr", srccr_);  w.Write("sfcsr", sfcsr_);
        w.Write("sacnt", sacnt_);  w.Write("sacadd", sacadd_); w.Write("sacdat", sacdat_); w.Write("satag", satag_);
        w.Write("stmsk", stmsk_);  w.Write("srmsk", srmsk_);  w.Write("str", str_);
        w.Write("sisr_err", sisr_err_);
    }
    void RestoreState(StateReader& r) override {
        r.Read("scr", scr_);    r.Read("sier", sier_);   r.Read("stcr", stcr_);   r.Read("srcr", srcr_);
        r.Read("stccr", stccr_);  r.Read("srccr", srccr_);  r.Read("sfcsr", sfcsr_);
        r.Read("sacnt", sacnt_);  r.Read("sacadd", sacadd_); r.Read("sacdat", sacdat_); r.Read("satag", satag_);
        r.Read("stmsk", stmsk_);  r.Read("srmsk", srmsk_);  r.Read("str", str_);
        r.Read("sisr_err", sisr_err_);
    }

private:
    /* Reset values, MCIMX51RM Ch 56 register summary (p56-25/26). */
    uint32_t sier_  = 0x00003003u;
    uint32_t stcr_  = 0x00000200u;
    uint32_t srcr_  = 0x00000200u;
    uint32_t stccr_ = 0x00040000u;
    uint32_t srccr_ = 0x00040000u;
    uint32_t sfcsr_ = 0x00810081u;
    uint32_t str_   = 0x00001111u;
    uint32_t scr_ = 0, sacnt_ = 0, sacadd_ = 0, sacdat_ = 0, satag_ = 0,
             stmsk_ = 0, srmsk_ = 0, sisr_err_ = 0;
};

}  /* namespace cerf_imx51_ssi_detail */
