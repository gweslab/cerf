#pragma once

#include "../peripherals/peripheral_base.h"

#include "../boards/board_context.h"
#include "../core/byte_order.h"
#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../cpu/emulated_memory.h"
#include "../peripherals/peripheral_dispatcher.h"
#include "../state/state_stream.h"
#include "freescale_module_clocks.h"
#include "freescale_sdma_bus.h"
#include "freescale_sdma_regs.h"
#include "guest_cpu_reset.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <mutex>
#include <vector>

/* Shared core for the Freescale SDMA, same IP on i.MX31 (MCIMX31RM Ch 40) and
   i.MX51 (MCIMX51RM Ch 52) but with a divergent register layout. This core owns
   the same-offset registers + the shared logic; each concrete owns its divergent
   registers (ReadExtra/WriteExtra) and INTC line (AssertIrqLine). */
namespace cerf_freescale_sdma_detail {

template <uint32_t kBase, const std::string_view& kSoc>
class FreescaleSdmaBase : public Peripheral, public FreescaleSdmaBus,
                          public FreescaleSdmaChannelHost {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == kSoc;
    }
    void OnReady() override {
        module_clocks_ = &emu_.Get<FreescaleModuleClocks>();
        ResetCore();
        /* MCIMX31RM §40.8.3, §40.14.1; MCIMX51RM Table 54-10 system_rst_b. */
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            std::lock_guard<std::recursive_mutex> lk(state_mu_);
            ResetCore();
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSdmaSize; }

    uint32_t ReadWord(uint32_t addr) override {
        std::lock_guard<std::recursive_mutex> lk(state_mu_);
        const uint32_t off = addr - kBase;
        switch (off) {
            case kOffMc0ptr:      return mc0ptr_;
            case kOffIntr:
                return intr_;
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
            case kOffIllinstaddr: return illinstaddr_;
            case kOffChn0addr:    return chn0addr_;
            case kOffXtrigConf1:  return xtrig_conf1_;
            case kOffXtrigConf2:  return xtrig_conf2_;
        }
        if (off >= kOffChnpriBase && off < kOffChnpriBase + kChannelCount * 4
            && (off & 0x3u) == 0) {
            return chnpri_[(off - kOffChnpriBase) / 4];
        }
        uint32_t idx = 0;
        if (ChnenblIndex(off, idx)) return chnenbl_[idx];
        uint32_t out = 0;
        if (ReadExtra(off, out)) return out;
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        std::lock_guard<std::recursive_mutex> lk(state_mu_);
        const uint32_t off = addr - kBase;
        switch (off) {
            case kOffMc0ptr:    mc0ptr_ = value; return;
            /* INTR is per-bit w1c; the AP line is level-driven, so re-evaluate it
               or it re-fires forever. */
            case kOffIntr:
                intr_ &= ~value; RefreshIrq(); return;
            /* HSTART bit N starts channel N: signal completion of its BDs. */
            case kOffHstart:    if (value != 0) CompleteChannels(value); return;
            /* STOP_STAT is w1c: writing 1 to bit N clears HE[N]/HSTART[N]. CERF
               completes channels synchronously on HSTART, so this clears idle bits. */
            case kOffStopStat:  ReleaseClaims(value);
                                hstart_ &= ~value; stop_stat_ &= ~value; return;
            case kOffEvtovr:    evtovr_  = value; return;
            case kOffDspovr:    dspovr_  = value; return;
            case kOffHostovr:   hostovr_ = value; return;
            /* EVTPEND manually triggers a channel; silent accept would make a
               kernel-launched DMA read return zero. */
            case kOffEvtpend:
                if (value != 0) HaltUnsupportedAccess("WriteWord EVTPEND (manual channel trigger)", addr, value);
                return;
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
        if (off >= kOffChnpriBase && off < kOffChnpriBase + kChannelCount * 4
            && (off & 0x3u) == 0) {
            chnpri_[(off - kOffChnpriBase) / 4] = value;
            return;
        }
        uint32_t idx = 0;
        if (ChnenblIndex(off, idx)) { chnenbl_[idx] = value; return; }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::recursive_mutex> lk(state_mu_);
        w.Write("mc0ptr", mc0ptr_);    w.Write("intr", intr_);      w.Write("stop_stat", stop_stat_);  w.Write("hstart", hstart_);
        w.Write("evtovr", evtovr_);    w.Write("dspovr", dspovr_);    w.Write("hostovr", hostovr_);    w.Write("evtpend", evtpend_);
        w.Write("reset", reset_);     w.Write("evterr", evterr_);    w.Write("intrmask", intrmask_);   w.Write("psw", psw_);
        w.Write("evterrdbg", evterrdbg_); w.Write("config", config_);    w.Write("once_enb", once_enb_);   w.Write("once_data", once_data_);
        w.Write("once_instr", once_instr_);w.Write("once_stat", once_stat_); w.Write("once_cmd", once_cmd_);   w.Write("illinstaddr", illinstaddr_);
        w.Write("chn0addr", chn0addr_);  w.Write("xtrig_conf1", xtrig_conf1_);w.Write("xtrig_conf2", xtrig_conf2_);
        w.WriteBytes("chnpri", chnpri_, sizeof(chnpri_));
        w.WriteBytes("chnenbl", chnenbl_, sizeof(chnenbl_));
        w.WriteBytes("rx_cursor", rx_cursor_, sizeof(rx_cursor_));
        uint8_t claimed[kChannelCount] = {};
        for (uint32_t i = 0; i < kChannelCount; ++i) claimed[i] = claimed_[i] ? 1u : 0u;
        w.WriteBytes("claimed", claimed, sizeof(claimed));
        w.WriteBytes("ctx_watermark", ctx_watermark_, sizeof(ctx_watermark_));
        w.Write("ctx_loaded", ctx_loaded_);
        for (auto* s : sinks_) s->SaveSinkState(w);
    }
    void RestoreState(StateReader& r) override {
        std::lock_guard<std::recursive_mutex> lk(state_mu_);
        r.Read("mc0ptr", mc0ptr_);    r.Read("intr", intr_);      r.Read("stop_stat", stop_stat_);  r.Read("hstart", hstart_);
        r.Read("evtovr", evtovr_);    r.Read("dspovr", dspovr_);    r.Read("hostovr", hostovr_);    r.Read("evtpend", evtpend_);
        r.Read("reset", reset_);     r.Read("evterr", evterr_);    r.Read("intrmask", intrmask_);   r.Read("psw", psw_);
        r.Read("evterrdbg", evterrdbg_); r.Read("config", config_);    r.Read("once_enb", once_enb_);   r.Read("once_data", once_data_);
        r.Read("once_instr", once_instr_);r.Read("once_stat", once_stat_); r.Read("once_cmd", once_cmd_);   r.Read("illinstaddr", illinstaddr_);
        r.Read("chn0addr", chn0addr_);  r.Read("xtrig_conf1", xtrig_conf1_);r.Read("xtrig_conf2", xtrig_conf2_);
        r.ReadBytes("chnpri", chnpri_, sizeof(chnpri_));
        r.ReadBytes("chnenbl", chnenbl_, sizeof(chnenbl_));
        r.ReadBytes("rx_cursor", rx_cursor_, sizeof(rx_cursor_));
        uint8_t claimed[kChannelCount] = {};
        r.ReadBytes("claimed", claimed, sizeof(claimed));
        for (uint32_t i = 0; i < kChannelCount; ++i) claimed_[i] = claimed[i] != 0u;
        r.ReadBytes("ctx_watermark", ctx_watermark_, sizeof(ctx_watermark_));
        r.Read("ctx_loaded", ctx_loaded_);
        for (auto* s : sinks_) s->RestoreSinkState(r);
    }

    void PostRestore() override {
        std::lock_guard<std::recursive_mutex> lk(state_mu_);
        RefreshIrq();
        for (auto* s : sinks_) s->PostRestoreSink();
    }

    bool ChannelWatermark(uint32_t channel, uint32_t& value) const override {
        if (channel >= kChannelCount || (ctx_loaded_ & (1u << channel)) == 0u) return false;
        value = ctx_watermark_[channel];
        return true;
    }

    void RegisterSdmaEvent(uint32_t event, FreescaleSdmaPeripheral* p,
                           bool is_tx) override {
        if (event < kMaxDmaEvents) dma_events_[event] = DmaEventBinding{p, is_tx, true};
    }

    void RegisterChannelSink(FreescaleSdmaChannelSink* sink) override {
        sinks_.push_back(sink);
    }

    /* MCIMX51RM Table 52-96 (p.52-230/231): the SDMA resets D of each processed
       BD; I interrupts the AP. */
    void SignalChannelBdDone(uint32_t channel, uint32_t bd_pa) override {
        std::lock_guard<std::recursive_mutex> lk(state_mu_);
        if (channel >= kChannelCount || !claimed_[channel]) return;
        uint8_t* bd = emu_.Get<EmulatedMemory>().TryTranslateWrite(bd_pa);
        if (bd == nullptr) return;
        uint32_t* word = reinterpret_cast<uint32_t*>(bd);
        const bool want_irq = (*word & kBdIntr) != 0;
        *word &= ~(kBdDone | kBdError);
        if (want_irq) intr_ |= (1u << channel);
        RefreshIrq();
    }

    /* Fill consecutive owned (Done) RX buffer descriptors of the channel(s) bound
       (CHNENBL) to `event` with the received bytes, write each BD's received count
       into its mode/count word, and hand it back to the host (Done cleared) so the
       guest's DMA reader sees the data; then raise the channel IRQ. */
    bool SdmaRxDeliver(uint32_t event, const uint8_t* data,
                       std::size_t n) override {
        std::lock_guard<std::recursive_mutex> lk(state_mu_);
        if (event >= kMaxDmaEvents || !dma_events_[event].used
            || dma_events_[event].is_tx || mc0ptr_ == 0)
            return false;
        const uint32_t chans = Chnenbl(event);

        if (chans == 0) return false;
        module_clocks_->RequireRunning(FreescaleModule::kSdma, "runs a receive channel");
        auto& mem = emu_.Get<EmulatedMemory>();
        std::size_t off = 0;
        bool delivered = false;
        for (uint32_t nch = 0; nch < kChannelCount && off < n; ++nch) {
            if ((chans & (1u << nch)) == 0) continue;
            uint8_t* ccb = mem.TryTranslateWrite(mc0ptr_ + nch * kCcbStride + kCcbBaseBdOff);
            if (ccb == nullptr) continue;
            /* The SDMA fills BDs in ring order from currentBDptr, wrapping at the
               W flag (MCIMX51RM Fig 52-82); track that position per channel so each
               received frame lands in the BD the guest's reader advances to, not
               always base. */
            const uint32_t base = *reinterpret_cast<uint32_t*>(ccb);
            if (rx_cursor_[nch] == 0) rx_cursor_[nch] = base;
            uint32_t bd_pa = rx_cursor_[nch];

            for (uint32_t i = 0; i < kMaxBdWalk && off < n; ++i) {
                uint8_t* bd = mem.TryTranslateWrite(bd_pa);
                if (bd == nullptr) break;
                uint32_t* word = reinterpret_cast<uint32_t*>(bd);

                if ((*word & kBdDone) == 0) break;          /* host owns -> not armed */
                const bool wrap     = (*word & kBdWrap) != 0;
                const bool want_irq = (*word & kBdIntr) != 0;
                const uint32_t stride = BdStride(*word);
                const uint32_t cap = *word & 0xFFFFu;        /* BD buffer size */
                const uint32_t buf_pa = word[1];
                uint32_t took = 0;
                for (; took < cap && off < n; ++took, ++off) {
                    uint8_t* dst = mem.TryTranslateWrite(buf_pa + took);
                    if (dst == nullptr) break;
                    *dst = data[off];
                }
                *word = (*word & ~(0xFFFFu | kBdDone | kBdError)) | took;

                if (want_irq) intr_ |= (1u << nch);
                delivered = true;
                bd_pa = wrap ? base : bd_pa + stride;
            }
            rx_cursor_[nch] = bd_pa;
        }

        if (delivered) RefreshIrq();
        return delivered;
    }

protected:
    /* Per-SoC interrupt line. i.MX31 -> Imx31Avic::Assert/DeassertSource(34);
       i.MX51 -> Imx51Tzic::AssertIrq/DeAssertIrq(6). */
    virtual void AssertIrqLine()   = 0;
    virtual void DeassertIrqLine() = 0;

    /* Per-SoC read-only divergent registers (EVT_MIRROR, and the i.MX51-only
       SDMA_LOCK / EVT_MIRROR2 / OTB / profile registers). True if handled. */
    virtual bool ReadExtra(uint32_t /*off*/, uint32_t& /*out*/) { return false; }

    /* CHNENBL RAM window: MCIMX31RM Table 40-10 (0x080, n=0..31),
       MCIMX51RM Table 52-9 (0x200, n=0..47). */
    virtual uint32_t ChnenblBase()  const = 0;
    virtual uint32_t ChnenblCount() const = 0;

    /* BD slot stride: 8 bytes (mode+buffer) or 12 (plus the extended-buffer word),
       set by the BD format the channel's SDMA script uses (MCIMX51RM Sec 52.23.1.1). */
    virtual uint32_t BdStride(uint32_t word0) const {
        return (word0 & kBdExtd) ? 12u : 8u;
    }

private:
    /* CHNENBL[event] = channel bitmask (MCIMX51RM Section 52.4.3.3). */
    uint32_t Chnenbl(uint32_t event) const {
        return event < ChnenblCount() ? chnenbl_[event] : 0u;
    }

    bool ChnenblIndex(uint32_t off, uint32_t& idx) const {
        const uint32_t base = ChnenblBase();
        if (off < base || off >= base + ChnenblCount() * 4 || (off & 0x3u) != 0)
            return false;
        idx = (off - base) / 4;
        return true;
    }

    void CompleteChannels(uint32_t channels) {
        if (mc0ptr_ == 0)
            HaltUnsupportedAccess("HSTART before MC0PTR set", kBase + kOffHstart, channels);
        module_clocks_->RequireRunning(FreescaleModule::kSdma, "starts a channel");
        auto& mem = emu_.Get<EmulatedMemory>();
        for (uint32_t n = 0; n < kChannelCount; ++n) {
            if ((channels & (1u << n)) == 0) continue;
            const int ev = EventForChannel(n);

            if (claimed_[n]) continue;              /* a sink already owns the data movement */
            if (OfferChannelToSinks(n, ev)) { claimed_[n] = true; continue; }

            FreescaleSdmaPeripheral* tx = nullptr;
            if (ev >= 0 && dma_events_[ev].used) {
                if (!dma_events_[ev].is_tx) continue;   /* bound RX: completes only via SdmaRxDeliver */
                tx = dma_events_[ev].p;                 /* bound TX: drain mem->peripheral below */
            } else if (n != 0) {
                /* Channel n runs an SDMA script this core does not model: it is
                   neither channel 0 (the bootload script, MCIMX51RM Sec 52.23.1.2)
                   nor a channel CHNENBL-bound to an emulated peripheral. */
                char what[128];
                std::snprintf(what, sizeof(what),
                              "HSTART on unmodeled SDMA channel %u (event=%d, "
                              "evtovr=0x%08X, hostovr=0x%08X)",
                              n, ev, evtovr_, hostovr_);
                HaltUnsupportedAccess(what, kBase + kOffHstart, uint32_t(1u << n));
            }
            uint8_t* ccb = mem.TryTranslateWrite(mc0ptr_ + n * kCcbStride + kCcbBaseBdOff);
            if (ccb == nullptr) continue;
            uint32_t bd_pa = *reinterpret_cast<uint32_t*>(ccb);
            for (uint32_t i = 0; i < kMaxBdWalk; ++i) {
                uint8_t* bd = mem.TryTranslateWrite(bd_pa);
                if (bd == nullptr) break;
                uint32_t* word = reinterpret_cast<uint32_t*>(bd);
                if ((*word & kBdDone) == 0) break;  /* not owned by SDMA */
                const uint32_t stride = BdStride(*word);
                const bool want_irq = (*word & kBdIntr) != 0;
                const bool wrap     = (*word & kBdWrap) != 0;
                if (tx != nullptr) {
                    const uint32_t count = *word & 0xFFFFu;
                    const uint32_t buf_pa = word[1];
                    for (uint32_t k = 0; k < count; ++k) {
                        uint8_t* src = mem.TryTranslateWrite(buf_pa + k);
                        if (src == nullptr) break;
                        tx->SdmaTxByte(*src);
                    }
                }
                if (n == 0u) RunChannelZeroCommand(*word, word[1]);
                *word &= ~(kBdDone | kBdError);
                if (want_irq) intr_ |= (1u << n);
                /* W marks the ring's last BD (MCIMX51RM Table 52-96); the BD after
                   it is the base, whose Done this walk already cleared. */
                if (wrap) break;
                bd_pa += stride;
            }
        }
        RefreshIrq();
    }

    /* MCIMX51RM Table 52-97: C0_SETCTX "cccc c111" loads the context of channel ccccc from the
       buffer; Table 52-43 / MCIMX31RM Table 40-39: GR7 is context word 9. */
    void RunChannelZeroCommand(uint32_t word0, uint32_t buf_pa) {
        const uint32_t command = word0 >> 24;
        if ((command & 0x7u) != 0x7u) return;
        const uint32_t channel = command >> 3;
        const uint32_t count   = word0 & 0xFFFFu;
        if (count < kContextGr7Word + 1u || claimed_[channel]) {
            HaltUnsupportedAccess("C0_SETCTX of a running channel or without GR7",
                                  kBase + kOffHstart, word0);
        }
        uint8_t* gr7 = emu_.Get<EmulatedMemory>().TryTranslateWrite(buf_pa + kContextGr7Word * 4u);
        if (gr7 == nullptr) {
            HaltUnsupportedAccess("C0_SETCTX buffer does not translate", kBase + kOffHstart, buf_pa);
        }
        ctx_watermark_[channel] = cerf::le::U32(gr7);
        ctx_loaded_ |= 1u << channel;
    }

    bool OfferChannelToSinks(uint32_t n, int ev) {
        uint8_t* ccb = emu_.Get<EmulatedMemory>().TryTranslateWrite(
            mc0ptr_ + n * kCcbStride + kCcbBaseBdOff);
        if (ccb == nullptr) return false;
        const uint32_t base_bd_pa = *reinterpret_cast<uint32_t*>(ccb);
        uint8_t* bd = emu_.Get<EmulatedMemory>().TryTranslateWrite(base_bd_pa);
        if (bd == nullptr) return false;
        const FreescaleSdmaChannelStart info{n, ev, base_bd_pa,
                                             BdStride(cerf::le::U32(bd))};
        for (auto* s : sinks_)
            if (s->ClaimChannel(info)) return true;
        return false;
    }

    void ReleaseClaims(uint32_t channels) {
        for (uint32_t n = 0; n < kChannelCount; ++n) {
            if ((channels & (1u << n)) == 0 || !claimed_[n]) continue;
            claimed_[n] = false;
            for (auto* s : sinks_) s->ReleaseChannel(n);
        }
    }

    /* The peripheral DMA-request event mapped to channel `chan`, or -1 if none
       (reverse of CHNENBL: each event's register holds a one-bit channel mask). */
    int EventForChannel(uint32_t chan) const {
        for (uint32_t e = 0; e < kMaxDmaEvents; ++e)
            if (Chnenbl(e) & (1u << chan)) return static_cast<int>(e);
        return -1;
    }

    void RefreshIrq() {
        /* Any set INTR/HI[i] bit drives the AP IRQ (MCIMX51RM Table 52-13); HI[i]
           is raised per-BD by the word0 I flag (Table 52-96). INTRMASK (§52.12.3.11)
           is the EVTERR DMA-request-error mask (unmodeled here), not a completion gate. */
        if (intr_ != 0) AssertIrqLine();
        else            DeassertIrqLine();
    }

    void ResetCore() {
        mc0ptr_ = 0; intr_ = 0; stop_stat_ = 0; hstart_ = 0; evtovr_ = 0;
        dspovr_ = kResetDspovr; hostovr_ = 0; evtpend_ = 0; reset_ = 0; evterr_ = 0;
        intrmask_ = 0; psw_ = 0; evterrdbg_ = 0; config_ = kResetConfig;
        once_enb_ = 0; once_data_ = 0; once_instr_ = 0; once_stat_ = kResetOnceStat;
        once_cmd_ = 0; illinstaddr_ = kResetIllinstaddr; chn0addr_ = kResetChn0addr;
        xtrig_conf1_ = 0; xtrig_conf2_ = 0;
        for (uint32_t i = 0; i < kChannelCount; ++i) {
            chnpri_[i] = 0; rx_cursor_[i] = 0;
            if (claimed_[i]) { claimed_[i] = false; for (auto* s : sinks_) s->ReleaseChannel(i); }
        }
        for (uint32_t i = 0; i < kMaxDmaEvents; ++i) chnenbl_[i] = 0;
        for (uint32_t i = 0; i < kChannelCount; ++i) ctx_watermark_[i] = 0;
        ctx_loaded_ = 0;
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
    uint32_t illinstaddr_ = kResetIllinstaddr;
    uint32_t chn0addr_    = kResetChn0addr;
    uint32_t xtrig_conf1_ = 0;
    uint32_t xtrig_conf2_ = 0;
    uint32_t chnpri_[kChannelCount] = {};
    uint32_t chnenbl_[kMaxDmaEvents] = {};
    uint32_t rx_cursor_[kChannelCount] = {};   /* per-channel RX BD ring fill position (0 = uninit -> base) */
    uint32_t ctx_watermark_[kChannelCount] = {};
    uint32_t ctx_loaded_ = 0;
    static constexpr uint32_t kContextGr7Word = 9u;

    struct DmaEventBinding {
        FreescaleSdmaPeripheral* p     = nullptr;
        bool                     is_tx = false;
        bool                     used  = false;
    };
    DmaEventBinding dma_events_[kMaxDmaEvents] = {};

    bool claimed_[kChannelCount] = {};
    std::vector<FreescaleSdmaChannelSink*> sinks_;
    FreescaleModuleClocks* module_clocks_ = nullptr;

    mutable std::recursive_mutex state_mu_;
};

}  /* namespace cerf_freescale_sdma_detail */
