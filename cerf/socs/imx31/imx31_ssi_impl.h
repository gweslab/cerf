#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include "../../jit/guest_cycle_clock.h"
#include "imx31_ccm.h"
#include "imx31_id.h"
#include "../freescale_ssi_transmitter.h"
#include "../guest_cpu_reset.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

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

constexpr uint32_t kSfcsrWatermarkMask = 0x00FF00FFu;

/* MCIMX31RM Table 45-4 reset values. */
constexpr uint32_t kSisrReset  = 0x00003003u;
constexpr uint32_t kSierReset  = 0x00003003u;
constexpr uint32_t kTrcrReset  = 0x00000200u;
constexpr uint32_t kTrccrReset = 0x00040000u;
constexpr uint32_t kSfcsrReset = 0x00810081u;

/* §45.3.3.2: "The SSI transmit FIFO registers are 8x24-bit registers". */
constexpr uint32_t kTxFifoDepth = 8u;

constexpr uint32_t kFrameSyncSetupClocks = 0u;

constexpr uint32_t kStcrTxdir = 1u << 5;
constexpr uint32_t kStcrTfdir = 1u << 6;

/* Table 45-15: 8, 10, 12, 16, 18, 20, 22 and 24 bits are supported. */
constexpr bool WordLengthSupported(uint32_t bits) {
    return (bits >= 8u && bits <= 12u) || (bits >= 16u && bits <= 24u);
}

template <uint32_t kBase>
class Imx31SsiImpl : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx31;
    }
    void OnReady() override {
        tx_.Attach();
        ResetRegisters();
        /* MCIMX31RM §3.6.3 / §3.6.5: a global or watchdog reset resets all peripherals. */
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            ResetRegisters();
        });
        emu_.Get<GuestCycleClock>().RegisterRateListener([this] {
            tx_.OnCpuRate();
            Notify();
        });
        emu_.Get<Imx31Ccm>().RegisterRateListener([this] {
            if (!SsiEnabled()) return;
            tx_.SetShape(TxShape());
            Notify();
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        switch (addr - kBase) {
            case kOffSrx0: case kOffSrx1: return 0;
            case kOffSisr:
                /* Table 45-9 SSIEN: disabled, "all SSI status bits are preset to the same state
                   produced by the power-on reset" (Table 45-4 SISR reset 0x3003). */
                if (SsiEnabled()) {
                    emu_.Get<Fatal>().Die("SSI %08X: SISR read with SSIEN set (SCR 0x%08X); the "
                                          "frame-sync, time-slot and receive flags are not "
                                          "modeled", kBase, scr_);
                }
                return kSisrReset;
            case kOffScr:   return scr_;
            case kOffSier:  return sier_;
            case kOffStcr:  return stcr_;
            case kOffSrcr:  return srcr_;
            case kOffStccr: return stccr_;
            case kOffSrccr: return srccr_;
            case kOffSfcsr:
                return (sfcsr_ & kSfcsrWatermarkMask) |
                       (tx_.Level() << cerf_freescale_ssi::kSfcsrTfcnt0Shift);
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
            case kOffStx0:
                tx_.WriteStx0(scr_, stcr_);
                Notify();
                return;
            case kOffStx1:
                emu_.Get<Fatal>().Die("SSI %08X: STX1 write 0x%08X; transmit FIFO 1 is not modeled",
                                      kBase, value);
            /* §45.3.3.8: "This register is read-only". */
            case kOffSisr:  return;
            case kOffScr:   WriteScr(value); return;
            case kOffSier:  WriteTxControl(sier_, value); return;
            case kOffStcr:  WriteTxControl(stcr_, value); return;
            case kOffSrcr:  srcr_  = value; return;
            case kOffStccr: WriteTxControl(stccr_, value); return;
            case kOffSrccr: srccr_ = value; return;
            case kOffSfcsr: WriteTxControl(sfcsr_, value); return;
            case kOffSacnt: sacnt_ = value; return;
            case kOffSacadd:sacadd_= value; return;
            case kOffSacdat:sacdat_= value; return;
            case kOffSatag: satag_ = value; return;
            case kOffStmsk: WriteTxControl(stmsk_, value); return;
            case kOffSrmsk: srmsk_ = value; return;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    void RegisterTxControlListener(std::function<void()> fn) {
        tx_control_listeners_.push_back(std::move(fn));
    }

    FreescaleSsiTransmitter& Transmitter() { return tx_; }

    bool SsiEnabled() const { return (scr_ & cerf_freescale_ssi::kScrSsien) != 0u; }

    /* Words per transmit frame: DC+1 (MCIMX31RM Table 45-14 DC4-DC0). */
    uint32_t TxWordsPerFrame() const { return ((stccr_ >> 8) & 0x1Fu) + 1u; }

    /* Bits per transmit word: WL[3:0] indexes 2,4,..,32 (Table 45-15). */
    uint32_t TxWordLengthBits() const { return (((stccr_ >> 13) & 0xFu) + 1u) * 2u; }

    /* MCIMX31RM p.45-16: "The word length is fixed to 32 in I2S Master mode". */
    uint32_t TxSlotBits() const {
        const uint32_t i2s = (scr_ >> cerf_freescale_ssi::kScrI2sShift) & 0x3u;
        return i2s == cerf_freescale_ssi::kI2sMaster ? 32u : TxWordLengthBits();
    }

    /* Figure 45-42: f_bit = ssi_clk / [(DIV2+1) x (7 x PSR + 1) x (PM+1) x 2],
       f_frame = f_bit / [(DC+1) x WL]. Table 45-2 (p.45-15): STCR[5] TXDIR,
       SCR[6:5] I2S mode; Table 45-14: I2S master words are 32 bits. */
    uint32_t TxFrameRateHz(uint32_t ssi_clk_hz) {
        if ((stcr_ & kStcrTxdir) == 0u) {
            emu_.Get<Fatal>().Die("SSI %08X: the transmit clock is external (STCR 0x%08X); "
                                  "its frame rate is set off-chip", kBase, stcr_);
        }
        const uint32_t i2s = (scr_ >> cerf_freescale_ssi::kScrI2sShift) & 0x3u;
        if (i2s == cerf_freescale_ssi::kI2sSlave) {
            emu_.Get<Fatal>().Die("SSI %08X: I2S slave mode (SCR 0x%08X) takes an external "
                                  "clock", kBase, scr_);
        }
        const uint32_t wl = TxWordLengthBits();
        if (!WordLengthSupported(wl)) {
            emu_.Get<Fatal>().Die("SSI %08X: STCCR 0x%08X word length %u bits is not "
                                  "supported (Table 45-15)", kBase, stccr_, wl);
        }
        const uint32_t div2 = (stccr_ >> 18) & 0x1u;
        const uint32_t psr  = (stccr_ >> 17) & 0x1u;
        const uint32_t pm   = stccr_ & 0xFFu;
        /* zune_keel wavedev_wm8978.dll sub_30E1D4C: WM8978 slave, SYSCLK = MCLK = SYS_CLK. */
        const uint64_t bit_div = (div2 == 0u && psr == 0u && pm == 0u)
            ? 4u
            : static_cast<uint64_t>(div2 + 1u) * (7u * psr + 1u) * (pm + 1u) * 2u;
        const uint64_t frame_div = bit_div * TxWordsPerFrame() * TxSlotBits();
        if (ssi_clk_hz == 0u || ssi_clk_hz % frame_div != 0u) {
            emu_.Get<Fatal>().Die("SSI %08X: a %u Hz ssi clock over %llu is not a whole frame "
                                  "rate", kBase, ssi_clk_hz,
                                  static_cast<unsigned long long>(frame_div));
        }
        return static_cast<uint32_t>(ssi_clk_hz / frame_div);
    }

    uint32_t SsiClockHz() const {
        return emu_.Get<Imx31Ccm>().SsiClockHz(kBase == 0x43FA0000u ? 1u : 2u);
    }

    void SaveState(StateWriter& w) override {
        w.Write("scr", scr_);    w.Write("sier", sier_);   w.Write("stcr", stcr_);   w.Write("srcr", srcr_);
        w.Write("stccr", stccr_);  w.Write("srccr", srccr_);  w.Write("sfcsr", sfcsr_);  w.Write("sacnt", sacnt_);
        w.Write("sacadd", sacadd_); w.Write("sacdat", sacdat_); w.Write("satag", satag_);  w.Write("stmsk", stmsk_);
        w.Write("srmsk", srmsk_);
        tx_.Save(w);
    }
    void RestoreState(StateReader& r) override {
        r.Read("scr", scr_);    r.Read("sier", sier_);   r.Read("stcr", stcr_);   r.Read("srcr", srcr_);
        r.Read("stccr", stccr_);  r.Read("srccr", srccr_);  r.Read("sfcsr", sfcsr_);  r.Read("sacnt", sacnt_);
        r.Read("sacadd", sacadd_); r.Read("sacdat", sacdat_); r.Read("satag", satag_);  r.Read("stmsk", stmsk_);
        r.Read("srmsk", srmsk_);
        tx_.Restore(r);
    }
    void PostRestore() override { tx_.PostRestore(); }

private:
    /* Table 45-2 / p.45-15: I2S master forces network mode; I2S slave takes the frame sync
       from off chip; §45.1.2.1 normal mode transmits in the first time slot only. */
    FreescaleSsiFrameShape TxShape() {
        const uint32_t i2s = (scr_ >> cerf_freescale_ssi::kScrI2sShift) & 0x3u;
        if (!SsiEnabled() || i2s == cerf_freescale_ssi::kI2sSlave ||
            (stcr_ & (kStcrTxdir | kStcrTfdir)) != (kStcrTxdir | kStcrTfdir)) {
            return FreescaleSsiFrameShape{};
        }
        const uint32_t slots = TxWordsPerFrame();
        const uint32_t all   = slots >= 32u ? 0xFFFFFFFFu : (1u << slots) - 1u;
        const bool net = i2s == cerf_freescale_ssi::kI2sMaster ||
                         (scr_ & cerf_freescale_ssi::kScrNet) != 0u;
        return FreescaleSsiFrameShape{TxFrameRateHz(SsiClockHz()), slots,
                                      net ? (~stmsk_ & all) : 1u, TxSlotBits()};
    }

    void WriteScr(uint32_t value) {
        if (scr_ == value) return;
        const uint32_t old = scr_;
        scr_ = value;
        tx_.WriteScr(old, scr_, TxShape());
        Notify();
    }

    void WriteTxControl(uint32_t& reg, uint32_t value) {
        if (reg == value) return;
        reg = value;
        tx_.WriteDmaControl(sier_, stcr_, sfcsr_);
        if (SsiEnabled()) tx_.SetShape(TxShape());
        Notify();
    }

    void Notify() {
        for (auto& fn : tx_control_listeners_) fn();
    }

    void ResetRegisters() {
        scr_   = 0u;
        sier_  = kSierReset;
        stcr_  = kTrcrReset;
        srcr_  = kTrcrReset;
        stccr_ = kTrccrReset;
        srccr_ = kTrccrReset;
        sfcsr_ = kSfcsrReset;
        sacnt_ = sacadd_ = sacdat_ = satag_ = stmsk_ = srmsk_ = 0u;
        tx_.Reset();
        tx_.WriteDmaControl(sier_, stcr_, sfcsr_);
    }

    uint32_t scr_ = 0, sier_ = 0, stcr_ = 0, srcr_ = 0, stccr_ = 0, srccr_ = 0,
             sfcsr_ = 0, sacnt_ = 0, sacadd_ = 0, sacdat_ = 0, satag_ = 0,
             stmsk_ = 0, srmsk_ = 0;
    FreescaleSsiTransmitter tx_{emu_, kBase, kTxFifoDepth, kFrameSyncSetupClocks};
    std::vector<std::function<void()>> tx_control_listeners_;
};

}
