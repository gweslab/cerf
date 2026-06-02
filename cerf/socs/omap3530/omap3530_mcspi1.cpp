#include "omap3530_mcspi1.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "omap3530_sdma.h"

namespace {

constexpr uint32_t kOffRevision      = 0x00;
constexpr uint32_t kOffSysconfig     = 0x10;
constexpr uint32_t kOffSysstatus     = 0x14;
constexpr uint32_t kOffIrqstatus     = 0x18;
constexpr uint32_t kOffIrqenable     = 0x1C;
constexpr uint32_t kOffWakeupenable  = 0x20;
constexpr uint32_t kOffSyst          = 0x24;
constexpr uint32_t kOffModulctrl     = 0x28;
constexpr uint32_t kOffChconfBase    = 0x2C;
constexpr uint32_t kChStride         = 0x14;

constexpr uint32_t kOffChconf        = 0x00;
constexpr uint32_t kOffChstatus      = 0x04;
constexpr uint32_t kOffChctrl        = 0x08;
constexpr uint32_t kOffTx            = 0x0C;
constexpr uint32_t kOffRx            = 0x10;

constexpr uint32_t kSysconfigSoftReset = 1u << 1;
constexpr uint32_t kSysstatusResetDone = 1u << 0;
constexpr uint32_t kChstatRxFull       = 1u << 0;
constexpr uint32_t kChstatTxEmpty      = 1u << 1;
constexpr uint32_t kChstatEot          = 1u << 2;
constexpr uint32_t kChctrlEn           = 1u << 0;
constexpr uint32_t kChconfDmawEnable   = 1u << 14;
constexpr uint32_t kChconfDmarEnable   = 1u << 15;
constexpr uint32_t kRevisionValue      = 0x00000021u;

}  /* namespace */

REGISTER_SERVICE(Omap3530Mcspi1);

bool Omap3530Mcspi1::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetSoc() == SocFamily::OMAP3530;
}

void Omap3530Mcspi1::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void Omap3530Mcspi1::RegisterSlave(uint32_t channel, McspiSlave* slave) {
    if (channel >= kNumChannels) {
        LOG(Caution, "Omap3530Mcspi1::RegisterSlave channel %u out of range\n",
            channel);
        return;
    }
    std::lock_guard<std::mutex> lk(mu_);
    channels_[channel].slave = slave;
}

uint32_t Omap3530Mcspi1::WordLength(const Channel& c) const {
    /* CHCONF.WL = bits[11:7], encoding (WL-1). Effective bits = WL+1. */
    return ((c.chconf >> 7) & 0x1Fu) + 1u;
}

void Omap3530Mcspi1::PerformTransfer(uint32_t ch, uint32_t tx_word) {
    Channel& c = channels_[ch];
    const uint32_t wl   = WordLength(c);
    const uint32_t mask = (wl >= 32u) ? 0xFFFFFFFFu : ((1u << wl) - 1u);
    const uint32_t out  = tx_word & mask;
    const uint32_t in   = c.slave ? c.slave->Transfer(out, wl) : 0u;
    c.rx      = in & mask;
    c.rx_full = true;
}

uint32_t Omap3530Mcspi1::ReadWord(uint32_t addr) {
    std::lock_guard<std::mutex> lk(mu_);
    const uint32_t off = addr - MmioBase();

    if (off >= kOffChconfBase) {
        const uint32_t rel = off - kOffChconfBase;
        const uint32_t ch  = rel / kChStride;
        const uint32_t cof = rel % kChStride;
        if (ch >= kNumChannels) {
            HaltUnsupportedAccess("ReadWord(channel out-of-range)", addr, 0);
        }
        Channel& c = channels_[ch];
        switch (cof) {
        case kOffChconf:   return c.chconf;
        case kOffChstatus: return (c.rx_full ? kChstatRxFull : 0u)
                                | kChstatTxEmpty
                                | (c.rx_full ? kChstatEot : 0u);
        case kOffChctrl:   return c.chctrl;
        case kOffTx:       return 0u;
        case kOffRx: {
            const uint32_t v = c.rx;
            c.rx_full = false;
            return v;
        }
        }
        HaltUnsupportedAccess("ReadWord(channel reg)", addr, 0);
    }

    switch (off) {
    case kOffRevision:     return kRevisionValue;
    case kOffSysconfig:    return sysconfig_;
    case kOffSysstatus:    return kSysstatusResetDone;
    case kOffIrqstatus:    return irqstatus_;
    case kOffIrqenable:    return irqenable_;
    case kOffWakeupenable: return wakeupenable_;
    case kOffSyst:         return syst_;
    case kOffModulctrl:    return modulctrl_;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Omap3530Mcspi1::WriteWord(uint32_t addr, uint32_t value) {
    uint32_t fire_tx_mask = 0;
    uint32_t fire_rx_mask = 0;
    {
        std::lock_guard<std::mutex> lk(mu_);
        const uint32_t off = addr - MmioBase();

        if (off >= kOffChconfBase) {
            const uint32_t rel = off - kOffChconfBase;
            const uint32_t ch  = rel / kChStride;
            const uint32_t cof = rel % kChStride;
            if (ch >= kNumChannels) {
                HaltUnsupportedAccess("WriteWord(channel out-of-range)",
                                      addr, value);
            }
            Channel& c = channels_[ch];
            switch (cof) {
            case kOffChconf:   c.chconf = value; goto fire_then_release;
            case kOffChstatus: goto fire_then_release;
            case kOffChctrl:   c.chctrl = value; goto fire_then_release;
            case kOffTx:
                if (c.chctrl & kChctrlEn) {
                    PerformTransfer(ch, value);
                    if (c.chconf & kChconfDmarEnable)
                        fire_rx_mask |= (1u << ch);
                    if (c.chconf & kChconfDmawEnable)
                        fire_tx_mask |= (1u << ch);
                }
                goto fire_then_release;
            case kOffRx:       goto fire_then_release;
            }
            HaltUnsupportedAccess("WriteWord(channel reg)", addr, value);
        }

        switch (off) {
        case kOffRevision:     goto fire_then_release;
        case kOffSysconfig:
            sysconfig_ = value;
            if (value & kSysconfigSoftReset) {
                sysconfig_ &= ~kSysconfigSoftReset;
                irqstatus_ = 0;
                irqenable_ = 0;
                modulctrl_ = 0;
                for (auto& c : channels_) {
                    c.chconf  = 0;
                    c.chctrl  = 0;
                    c.rx      = 0;
                    c.rx_full = false;
                }
            }
            goto fire_then_release;
        case kOffSysstatus:    goto fire_then_release;
        case kOffIrqstatus:    irqstatus_ &= ~value; goto fire_then_release;  /* W1C */
        case kOffIrqenable:    irqenable_    = value; goto fire_then_release;
        case kOffWakeupenable: wakeupenable_ = value; goto fire_then_release;
        case kOffSyst:         syst_         = value; goto fire_then_release;
        case kOffModulctrl:    modulctrl_    = value; goto fire_then_release;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    fire_then_release:;
    }
    if (fire_tx_mask == 0 && fire_rx_mask == 0) return;
    auto& sdma = emu_.Get<Omap3530Sdma>();
    /* RX events first so the data is consumed before TX overwrites it
       (our McSPI has no FIFO; rx_full bit clobbers if TX advances
       before RX is read). */
    for (uint32_t ch = 0; ch < kNumChannels; ++ch) {
        if (fire_rx_mask & (1u << ch)) {
            sdma.RaiseSyncEvent(Omap3530Sdma::kSyncSpi1Rx0 + 2u * ch);
        }
    }
    for (uint32_t ch = 0; ch < kNumChannels; ++ch) {
        if (fire_tx_mask & (1u << ch)) {
            sdma.RaiseSyncEvent(Omap3530Sdma::kSyncSpi1Tx0 + 2u * ch);
        }
    }
}
