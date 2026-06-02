#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../cpu/emulated_memory.h"
#include "imx31_avic.h"

#include <cstdint>

namespace {

/* MCIMX31RM Table 40-10 (page 40-37): SDMA AP register block. */
constexpr uint32_t kBase = 0x53FD4000u;
constexpr uint32_t kSize = 0x00004000u;

constexpr uint32_t kOffMc0ptr      = 0x000u;
constexpr uint32_t kOffIntr        = 0x004u;
constexpr uint32_t kOffStopStat    = 0x008u;
constexpr uint32_t kOffHstart      = 0x00Cu;
constexpr uint32_t kOffEvtovr      = 0x010u;
constexpr uint32_t kOffDspovr      = 0x014u;
constexpr uint32_t kOffHostovr     = 0x018u;
constexpr uint32_t kOffEvtpend     = 0x01Cu;
constexpr uint32_t kOffReset       = 0x024u;
constexpr uint32_t kOffEvterr      = 0x028u;
constexpr uint32_t kOffIntrmask    = 0x02Cu;
constexpr uint32_t kOffPsw         = 0x030u;
constexpr uint32_t kOffEvterrdbg   = 0x034u;
constexpr uint32_t kOffConfig      = 0x038u;
constexpr uint32_t kOffOnceEnb     = 0x040u;
constexpr uint32_t kOffOnceData    = 0x044u;
constexpr uint32_t kOffOnceInstr   = 0x048u;
constexpr uint32_t kOffOnceStat    = 0x04Cu;
constexpr uint32_t kOffOnceCmd     = 0x050u;
constexpr uint32_t kOffEvtMirror   = 0x054u;
constexpr uint32_t kOffIllinstaddr = 0x058u;
constexpr uint32_t kOffChn0addr    = 0x05Cu;
constexpr uint32_t kOffXtrigConf1  = 0x070u;
constexpr uint32_t kOffXtrigConf2  = 0x074u;
constexpr uint32_t kOffChnenblBase = 0x080u;
constexpr uint32_t kOffChnpriBase  = 0x100u;
constexpr uint32_t kChannelCount   = 32u;

/* MCIMX31RM Table 40-10 reset values. */
constexpr uint32_t kResetDspovr      = 0xFFFFFFFFu;
constexpr uint32_t kResetConfig      = 0x00000003u;
constexpr uint32_t kResetOnceStat    = 0x0000E000u;
constexpr uint32_t kResetIllinstaddr = 0x00000001u;
constexpr uint32_t kResetChn0addr    = 0x00000050u;

/* MCIMX31RM Table 40-25 RESET register: bit 0 RESET, bit 1 RESCHED. */
constexpr uint32_t kResetBitReset = 1u << 0;

/* SDMA AVIC interrupt source (MCIMX31RM Table 2-3). */
constexpr uint32_t kAvicSourceSdma = 34u;

/* BD first-word bits + CCB layout, decompiled from CSPDDK: bit23 EXTD
   selects 12-byte vs 8-byte BD stride, so a wrong stride walks garbage. */
constexpr uint32_t kBdDone = 1u << 16;
constexpr uint32_t kBdError = 1u << 20;
constexpr uint32_t kBdExtd = 1u << 23;
constexpr uint32_t kCcbStride = 16u;
constexpr uint32_t kCcbBaseBdOff = 4u;
constexpr uint32_t kMaxBdWalk = 256u;

class Imx31Sdma : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override {
        ResetCore();
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        switch (off) {
            case kOffMc0ptr:      return mc0ptr_;
            case kOffIntr:        return intr_;
            case kOffStopStat:    return stop_stat_;
            case kOffHstart:      return hstart_;
            case kOffEvtovr:      return evtovr_;
            case kOffDspovr:      return dspovr_;
            case kOffHostovr:     return hostovr_;
            case kOffEvtpend:     return evtpend_;
            case kOffReset:       return reset_;
            case kOffEvterr:      return evterr_;
            case kOffIntrmask:    return intrmask_;
            case kOffPsw:         return psw_;
            case kOffEvterrdbg:   return evterrdbg_;
            case kOffConfig:      return config_;
            case kOffOnceEnb:     return once_enb_;
            case kOffOnceData:    return once_data_;
            case kOffOnceInstr:   return once_instr_;
            case kOffOnceStat:    return once_stat_;
            case kOffOnceCmd:     return once_cmd_;
            case kOffEvtMirror:   return evt_mirror_;
            case kOffIllinstaddr: return illinstaddr_;
            case kOffChn0addr:    return chn0addr_;
            case kOffXtrigConf1:  return xtrig_conf1_;
            case kOffXtrigConf2:  return xtrig_conf2_;
        }
        if (off >= kOffChnenblBase && off < kOffChnenblBase + kChannelCount * 4
            && (off & 0x3u) == 0) {
            return chnenbl_[(off - kOffChnenblBase) / 4];
        }
        if (off >= kOffChnpriBase && off < kOffChnpriBase + kChannelCount * 4
            && (off & 0x3u) == 0) {
            return chnpri_[(off - kOffChnpriBase) / 4];
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;
        switch (off) {
            case kOffMc0ptr:    mc0ptr_ = value; return;
            /* Table 40-12: INTR is per-bit w1c. The OAL handler
               (OEMInterruptHandler sub_8823CB44) clears the channel bit
               here; the AVIC line is level-driven, so re-evaluate it or it
               re-fires forever. */
            case kOffIntr:      intr_ &= ~value; RefreshIrq(); return;
            /* HSTART bit N starts channel N (Table 40-12). Audio careful
               stub (§0.3): signal completion of the channel's BDs instead
               of running the SDMA scripts. */
            case kOffHstart:
                if (value != 0) CompleteChannels(value);
                return;
            /* STOP_STAT (Figure 40-15) is w1c: writing 1 to bit N clears HE[N]
               and HSTART[N], stopping channel N. CERF completes channels
               synchronously on HSTART (HE/HSTART never linger set), so the stop
               clears already-idle bits. */
            case kOffStopStat:
                hstart_    &= ~value;
                stop_stat_ &= ~value;
                return;
            case kOffEvtovr:    evtovr_  = value; return;
            case kOffDspovr:    dspovr_  = value; return;
            case kOffHostovr:   hostovr_ = value; return;
            /* EVTPEND bit N manually triggers channel N (§40.8.3).
               Silent accept would make kernel-launched DMA reads return zero. */
            case kOffEvtpend:
                if (value != 0) HaltUnsupportedAccess("WriteWord EVTPEND (manual channel trigger)", addr, value);
                return;
            /* RESET register bit 0 = SDMA software reset, self-clearing
               once the reset completes. Bit 1 RESCHED is unrelated. */
            case kOffReset:
                if (value & kResetBitReset) ResetCore();
                else                        reset_ = value & ~kResetBitReset;
                return;
            case kOffIntrmask:    intrmask_    = value; RefreshIrq(); return;
            case kOffConfig:      config_      = value; return;
            case kOffOnceEnb:     once_enb_    = value; return;
            case kOffOnceData:    once_data_   = value; return;
            case kOffOnceInstr:   once_instr_  = value; return;
            case kOffOnceCmd:     once_cmd_    = value; return;
            case kOffIllinstaddr: illinstaddr_ = value; return;
            case kOffChn0addr:    chn0addr_    = value; return;
            case kOffXtrigConf1:  xtrig_conf1_ = value; return;
            case kOffXtrigConf2:  xtrig_conf2_ = value; return;
        }
        if (off >= kOffChnenblBase && off < kOffChnenblBase + kChannelCount * 4
            && (off & 0x3u) == 0) {
            chnenbl_[(off - kOffChnenblBase) / 4] = value;
            return;
        }
        if (off >= kOffChnpriBase && off < kOffChnpriBase + kChannelCount * 4
            && (off & 0x3u) == 0) {
            chnpri_[(off - kOffChnpriBase) / 4] = value;
            return;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

private:
    /* Audio careful stub: signal BD completion + raise SDMA IRQ; no bytes moved. */
    void CompleteChannels(uint32_t channels) {
        if (mc0ptr_ == 0) {
            HaltUnsupportedAccess("HSTART before MC0PTR set", kBase + kOffHstart, channels);
            return;
        }
        auto& mem = emu_.Get<EmulatedMemory>();
        for (uint32_t n = 0; n < kChannelCount; ++n) {
            if ((channels & (1u << n)) == 0) continue;
            uint8_t* ccb = mem.TryTranslateWrite(mc0ptr_ + n * kCcbStride + kCcbBaseBdOff);
            if (ccb == nullptr) continue;
            uint32_t bd_pa = *reinterpret_cast<uint32_t*>(ccb);
            for (uint32_t i = 0; i < kMaxBdWalk; ++i) {
                uint8_t* bd = mem.TryTranslateWrite(bd_pa);
                if (bd == nullptr) break;
                uint32_t* word = reinterpret_cast<uint32_t*>(bd);
                if ((*word & kBdDone) == 0) break;  /* not owned by SDMA */
                const bool extd = (*word & kBdExtd) != 0;
                *word &= ~(kBdDone | kBdError);
                intr_ |= (1u << n);
                bd_pa += extd ? 12u : 8u;
            }
        }
        RefreshIrq();
    }

    void RefreshIrq() {
        /* MCIMX31RM §40.10.3.11: an AP interrupt is sent only for channels
           whose INTRMASK (HIMASK) bit is set. */
        auto& avic = emu_.Get<Imx31Avic>();
        if ((intr_ & intrmask_) != 0) avic.AssertSource(kAvicSourceSdma);
        else                          avic.DeassertSource(kAvicSourceSdma);
    }

    void ResetCore() {
        mc0ptr_      = 0;
        intr_        = 0;
        stop_stat_   = 0;
        hstart_      = 0;
        evtovr_      = 0;
        dspovr_      = kResetDspovr;
        hostovr_     = 0;
        evtpend_     = 0;
        reset_       = 0;
        evterr_      = 0;
        intrmask_    = 0;
        psw_         = 0;
        evterrdbg_   = 0;
        config_      = kResetConfig;
        once_enb_    = 0;
        once_data_   = 0;
        once_instr_  = 0;
        once_stat_   = kResetOnceStat;
        once_cmd_    = 0;
        evt_mirror_  = 0;
        illinstaddr_ = kResetIllinstaddr;
        chn0addr_    = kResetChn0addr;
        xtrig_conf1_ = 0;
        xtrig_conf2_ = 0;
        for (uint32_t i = 0; i < kChannelCount; ++i) {
            chnenbl_[i] = 0;
            chnpri_[i]  = 0;
        }
    }

    uint32_t mc0ptr_      = 0;
    uint32_t intr_        = 0;
    uint32_t stop_stat_   = 0;
    uint32_t hstart_      = 0;
    uint32_t evtovr_      = 0;
    uint32_t dspovr_      = kResetDspovr;
    uint32_t hostovr_     = 0;
    uint32_t evtpend_     = 0;
    uint32_t reset_       = 0;
    uint32_t evterr_      = 0;
    uint32_t intrmask_    = 0;
    uint32_t psw_         = 0;
    uint32_t evterrdbg_   = 0;
    uint32_t config_      = kResetConfig;
    uint32_t once_enb_    = 0;
    uint32_t once_data_   = 0;
    uint32_t once_instr_  = 0;
    uint32_t once_stat_   = kResetOnceStat;
    uint32_t once_cmd_    = 0;
    uint32_t evt_mirror_  = 0;
    uint32_t illinstaddr_ = kResetIllinstaddr;
    uint32_t chn0addr_    = kResetChn0addr;
    uint32_t xtrig_conf1_ = 0;
    uint32_t xtrig_conf2_ = 0;
    uint32_t chnenbl_[kChannelCount] = {};
    uint32_t chnpri_[kChannelCount]  = {};
};

}  /* namespace */

REGISTER_SERVICE(Imx31Sdma);
