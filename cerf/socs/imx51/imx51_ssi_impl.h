#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "imx51_ssi_slave_format.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../freescale_sdma_bus.h"
#include "../freescale_ssi_transmitter.h"
#include "../guest_cpu_reset.h"

#include <cstdint>
#include <functional>
#include <utility>
#include <vector>

namespace cerf_imx51_ssi_detail {

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

constexpr uint32_t kSfcsrWatermarkMask = 0x00FF00FFu;

/* MCIMX51RM Table 56-7 reset values. */
constexpr uint32_t kSisrReset  = 0x00003003u;
constexpr uint32_t kSierReset  = 0x00003003u;
constexpr uint32_t kTrcrReset  = 0x00000200u;
constexpr uint32_t kTrccrReset = 0x00040000u;
constexpr uint32_t kSfcsrReset = 0x00810081u;
constexpr uint32_t kStrReset   = 0x00001111u;

/* MCIMX51RM §56.1.2.1.1: "15 data words can be transferred before the core must write new
   data to the STX0 register". */
constexpr uint32_t kTxFifoDepth = 15u;

/* MCIMX51RM Table 56-12 TE: "SSI expects 4 setup clock cycles before arrival of frame-sync". */
constexpr uint32_t kFrameSyncSetupClocks = 4u;

/* MCIMX51RM Table 56-15 STCR TXDIR [5], TFDIR [6]; Table 56-22 SACNT AC97EN [0]. */
constexpr uint32_t kStcrTxdir   = 1u << 5;
constexpr uint32_t kStcrTfdir   = 1u << 6;
constexpr uint32_t kSacntAc97en = 1u << 0;

constexpr uint32_t SsiIndex(uint32_t base) {
    return base == 0x83FCC000u ? 1u : base == 0x70014000u ? 2u : 3u;
}

template <uint32_t kBase>
class Imx51SsiImpl : public Peripheral, public FreescaleSdmaPeripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override {
        tx_.Attach();
        ResetRegisters();
        /* MCIMX51RM Table 54-10: system_rst_b "Resets functional modules" in every reset row. */
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            ResetRegisters();
        });
        emu_.Get<GuestCycleClock>().RegisterRateListener([this] {
            tx_.OnCpuRate();
            Notify();
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        switch (addr - kBase) {
            case kOffStx0: case kOffStx1:
            case kOffSrx0: case kOffSrx1: return 0;
            case kOffSisr:
                /* Table 56-12 SSIEN: disabled, "all SSI status bits are preset to the same state
                   produced by the power-on reset" (Table 56-7 SISR reset 0x3003). */
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
            case kOffStx0:
                tx_.WriteStx0(scr_, stcr_);
                Notify();
                return;
            case kOffStx1:
                emu_.Get<Fatal>().Die("SSI %08X: STX1 write 0x%08X; transmit FIFO 1 is not modeled",
                                      kBase, value);
            /* Table 56-13 TUE0: "It is also cleared by writing '1' to this bit". */
            case kOffSisr:
                if ((value & cerf_freescale_ssi::kSisrTue0) != 0u) tx_.ClearUnderrun();
                return;
            case kOffScr:   WriteScr(value); return;
            case kOffSier:  WriteTxControl(sier_, value); return;
            case kOffStcr:  WriteTxControl(stcr_, value); return;
            case kOffSrcr:  srcr_  = value; return;
            case kOffStccr: WriteTxControl(stccr_, value); return;
            case kOffSrccr: srccr_ = value; return;
            case kOffSfcsr: WriteTxControl(sfcsr_, value); return;
            case kOffStr:   str_   = value; return;
            case kOffSacnt: WriteTxControl(sacnt_, value); return;
            case kOffSacadd:sacadd_= value; return;
            case kOffSacdat:sacdat_= value; return;
            case kOffSatag: satag_ = value; return;
            case kOffStmsk: WriteTxControl(stmsk_, value); return;
            case kOffSrmsk: srmsk_ = value; return;
        }
    }

    void SdmaTxByte(uint8_t) override {}

    void RegisterTxControlListener(std::function<void()> fn) {
        tx_control_listeners_.push_back(std::move(fn));
    }

    FreescaleSsiTransmitter& Transmitter() { return tx_; }

    bool SsiEnabled() const { return (scr_ & cerf_freescale_ssi::kScrSsien) != 0u; }

    /* MCIMX51RM Table 56-15 TXDIR / TFDIR: 0 = "Transmit Clock is external" / "Frame Sync is
       external"; §56.1.2.5: AC97 mode forces TFDIR to 1 internally. */
    bool TxClockExternal() const {
        return (stcr_ & (kStcrTxdir | kStcrTfdir)) == 0u && (sacnt_ & kSacntAc97en) == 0u;
    }
    uint32_t Stcr() const  { return stcr_; }
    uint32_t Sacnt() const { return sacnt_; }

    void SaveState(StateWriter& w) override {
        w.Write("scr", scr_);    w.Write("sier", sier_);   w.Write("stcr", stcr_);   w.Write("srcr", srcr_);
        w.Write("stccr", stccr_);  w.Write("srccr", srccr_);  w.Write("sfcsr", sfcsr_);
        w.Write("sacnt", sacnt_);  w.Write("sacadd", sacadd_); w.Write("sacdat", sacdat_); w.Write("satag", satag_);
        w.Write("stmsk", stmsk_);  w.Write("srmsk", srmsk_);  w.Write("str", str_);
        tx_.Save(w);
    }
    void RestoreState(StateReader& r) override {
        r.Read("scr", scr_);    r.Read("sier", sier_);   r.Read("stcr", stcr_);   r.Read("srcr", srcr_);
        r.Read("stccr", stccr_);  r.Read("srccr", srccr_);  r.Read("sfcsr", sfcsr_);
        r.Read("sacnt", sacnt_);  r.Read("sacadd", sacadd_); r.Read("sacdat", sacdat_); r.Read("satag", satag_);
        r.Read("stmsk", stmsk_);  r.Read("srmsk", srmsk_);  r.Read("str", str_);
        tx_.Restore(r);
    }
    void PostRestore() override { tx_.PostRestore(); }

private:
    /* MCIMX51RM p.56-16: in I2S slave mode "each frame sync transition is the start of a new
       frame", one data word per transition. */
    FreescaleSsiFrameShape TxShape() {
        const uint32_t i2s = (scr_ >> cerf_freescale_ssi::kScrI2sShift) & 0x3u;
        if (!SsiEnabled() || i2s != cerf_freescale_ssi::kI2sSlave || !TxClockExternal()) {
            return FreescaleSsiFrameShape{};
        }
        const auto& slave = emu_.Get<Imx51SsiSlaveFormat>();
        const FreescaleAudioFormat format = slave.Format(SsiIndex(kBase));
        if (format.channels != 2u) {
            emu_.Get<Fatal>().Die("SSI %08X: an I2S slave stream of %u channels", kBase,
                                  format.channels);
        }
        return FreescaleSsiFrameShape{2ull * format.rate_hz, 1u, 1u,
                                      slave.FrameSyncBitClocks(SsiIndex(kBase))};
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
        str_   = kStrReset;
        sacnt_ = sacadd_ = sacdat_ = satag_ = stmsk_ = srmsk_ = 0u;
        tx_.Reset();
        tx_.WriteDmaControl(sier_, stcr_, sfcsr_);
    }

    uint32_t scr_ = 0, sier_ = 0, stcr_ = 0, srcr_ = 0, stccr_ = 0, srccr_ = 0, sfcsr_ = 0,
             str_ = 0, sacnt_ = 0, sacadd_ = 0, sacdat_ = 0, satag_ = 0, stmsk_ = 0, srmsk_ = 0;
    FreescaleSsiTransmitter tx_{emu_, kBase, kTxFifoDepth, kFrameSyncSetupClocks};
    std::vector<std::function<void()>> tx_control_listeners_;
};

}
