#define NOMINMAX

#include "omap3530_sdma_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../irq_controller.h"

#include <cstdint>
#include <cstring>
#include <mutex>

namespace {

constexpr uint32_t kCcrOff       = 0x00u;
constexpr uint32_t kClnkCtrlOff  = 0x04u;
constexpr uint32_t kCicrOff      = 0x08u;
constexpr uint32_t kCsrOff       = 0x0Cu;
constexpr uint32_t kCsdpOff      = 0x10u;
constexpr uint32_t kCenOff       = 0x14u;
constexpr uint32_t kCfnOff       = 0x18u;
constexpr uint32_t kCssaOff      = 0x1Cu;
constexpr uint32_t kCdsaOff      = 0x20u;
constexpr uint32_t kCseiOff      = 0x24u;
constexpr uint32_t kCsfiOff      = 0x28u;
constexpr uint32_t kCdeiOff      = 0x2Cu;
constexpr uint32_t kCdfiOff      = 0x30u;
constexpr uint32_t kCsacOff      = 0x34u;
constexpr uint32_t kCdacOff      = 0x38u;
constexpr uint32_t kCcenOff      = 0x3Cu;
constexpr uint32_t kCcfnOff      = 0x40u;
constexpr uint32_t kColorOff     = 0x44u;

constexpr uint32_t kChannelStride = 0x60u;
constexpr uint32_t kChannelBase   = 0x80u;

constexpr uint32_t kCcrEnable            = 1u << 7;
constexpr uint32_t kCcrFs                = 1u << 5;
constexpr uint32_t kCcrBs                = 1u << 18;
constexpr uint32_t kCcrConstFillEnable   = 1u << 16;
constexpr uint32_t kCcrTransparentCopyEn = 1u << 17;
constexpr uint32_t kCcrSelSrcDstSync     = 1u << 24;

constexpr uint32_t kCsdpSrcEndianBig = 1u << 21;
constexpr uint32_t kCsdpDstEndianBig = 1u << 19;

constexpr uint32_t kCsrFrame    = 1u << 3;
constexpr uint32_t kCsrLast     = 1u << 4;
constexpr uint32_t kCsrBlock    = 1u << 5;
constexpr uint32_t kCsrPkt      = 1u << 7;
constexpr uint32_t kCsrMisAlign = 1u << 11;

constexpr uint32_t kClnkEnable  = 1u << 15;

constexpr uint32_t kOcpSoftReset = 1u << 1;

constexpr uint32_t kRevision = 0x00000040u;
constexpr uint32_t kCaps0    = 0x000C0000u;
constexpr uint32_t kCaps2    = 0x000001FFu;
constexpr uint32_t kCaps3    = 0x000000F3u;
constexpr uint32_t kCaps4    = 0x00001FFDu;

uint32_t ExtractSyncSource(uint32_t ccr) {
    return (ccr & 0x1Fu) | ((ccr & 0x00180000u) >> 14);
}

uint32_t ElementSize(uint32_t csdp) {
    return 1u << (csdp & 0x3u);
}

uint32_t ByteSwap(uint32_t value, uint32_t es) {
    switch (es) {
    case 1: return value & 0xFFu;
    case 2: return ((value & 0xFFu) << 8) | ((value >> 8) & 0xFFu);
    case 4: return ((value & 0xFFu) << 24) |
                   ((value & 0xFF00u) << 8) |
                   ((value & 0xFF0000u) >> 8) |
                   ((value >> 24) & 0xFFu);
    default: return value;
    }
}

bool IsAligned(uint32_t addr, uint32_t es) {
    return (addr & (es - 1u)) == 0u;
}

}  /* namespace */

void Omap3530SdmaBase::OnReady() {
    channels_.resize(ChannelCount());
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t Omap3530SdmaBase::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off & 3u) HaltUnsupportedAccess("ReadWord (misaligned)", addr, 0);

    std::lock_guard<std::recursive_mutex> lk(state_mu_);

    if (off < kChannelBase) {
        if (off == 0x000u) return kRevision;
        if (off >= 0x008u && off < 0x018u) return irqstatus_l_[(off - 0x008u) / 4u];
        if (off >= 0x018u && off < 0x028u) return irqenable_l_[(off - 0x018u) / 4u];
        if (off == 0x028u) return sysstatus_;
        if (off == 0x02Cu) return ocp_sysconfig_;
        if (off == 0x064u) return kCaps0;
        if (off == 0x06Cu) return kCaps2;
        if (off == 0x070u) return kCaps3;
        if (off == 0x074u) return kCaps4;
        if (off == 0x078u) return gcr_;
        return 0u;
    }

    const uint32_t rel = off - kChannelBase;
    const uint32_t count = static_cast<uint32_t>(channels_.size());
    if (rel >= count * kChannelStride) return 0u;
    const int ch = static_cast<int>(rel / kChannelStride);
    const uint32_t sub = rel % kChannelStride;
    const Channel& c = channels_[ch];
    switch (sub) {
    case kCcrOff:      return c.ccr;
    case kClnkCtrlOff: return c.clnk_ctrl;
    case kCicrOff:     return c.cicr;
    case kCsrOff:      return c.csr;
    case kCsdpOff:     return c.csdp;
    case kCenOff:      return c.cen;
    case kCfnOff:      return c.cfn;
    case kCssaOff:     return c.cssa;
    case kCdsaOff:     return c.cdsa;
    case kCseiOff:     return c.csei;
    case kCsfiOff:     return c.csfi;
    case kCdeiOff:     return c.cdei;
    case kCdfiOff:     return c.cdfi;
    case kCsacOff:     return c.csac;
    case kCdacOff:     return c.cdac;
    case kCcenOff:     return c.ccen;
    case kCcfnOff:     return c.ccfn;
    case kColorOff:    return c.color;
    default:           return 0u;
    }
}

void Omap3530SdmaBase::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off & 3u) HaltUnsupportedAccess("WriteWord (misaligned)", addr, value);

    std::lock_guard<std::recursive_mutex> lk(state_mu_);

    if (off < kChannelBase) {
        if (off == 0x000u) return;
        if (off >= 0x008u && off < 0x018u) {
            irqstatus_l_[(off - 0x008u) / 4u] &= ~value;
            UpdateIrqLines();
            return;
        }
        if (off >= 0x018u && off < 0x028u) {
            irqenable_l_[(off - 0x018u) / 4u] = value;
            UpdateIrqLines();
            return;
        }
        if (off == 0x028u) return;
        if (off == 0x02Cu) {
            if (value & kOcpSoftReset) {
                for (auto& c : channels_) c = Channel{};
                std::memset(irqstatus_l_, 0, sizeof(irqstatus_l_));
                std::memset(irqenable_l_, 0, sizeof(irqenable_l_));
                gcr_       = 0x10u;
                sysstatus_ = 1u;
                UpdateIrqLines();
            }
            /* SOFTRESET auto-clears (TRM §9.4.20): always reads 0. */
            ocp_sysconfig_ = value & ~kOcpSoftReset;
            return;
        }
        if (off == 0x064u || off == 0x06Cu ||
            off == 0x070u || off == 0x074u) return;
        if (off == 0x078u) { gcr_ = value; return; }
        return;
    }

    const uint32_t rel = off - kChannelBase;
    const uint32_t count = static_cast<uint32_t>(channels_.size());
    if (rel >= count * kChannelStride) return;
    const int ch = static_cast<int>(rel / kChannelStride);
    const uint32_t sub = rel % kChannelStride;
    Channel& c = channels_[ch];

    switch (sub) {
    case kCcrOff: {
        const bool was_enabled = (c.ccr & kCcrEnable) != 0u;
        c.ccr = value;
        if (!was_enabled && (value & kCcrEnable) != 0u) {
            /* New transfer: clear sticky end-of-transfer flags from any
               prior run (BSP DmaConfigure doesn't W1C-clear CSR, so the
               SW-trigger while-loop in RunSwTransfer would exit on the
               very first iteration if BLOCK survived from last time). */
            c.csr &= ~(kCsrBlock | kCsrFrame | kCsrLast | kCsrPkt);
            c.active = false;
            c.ccen = 0;
            c.ccfn = 0;
            if (ExtractSyncSource(value) == 0u) {
                RunSwTransfer(ch);
                UpdateIrqLines();
            }
        }
        return;
    }
    case kClnkCtrlOff: c.clnk_ctrl = value; return;
    case kCicrOff:
        c.cicr = value;
        UpdateIrqLines();
        return;
    case kCsrOff:
        /* W1C: write-1-to-clear. */
        c.csr &= ~value;
        UpdateIrqLines();
        return;
    case kCsdpOff:  c.csdp  = value; return;
    case kCenOff:   c.cen   = value & 0x00FFFFFFu; return;
    case kCfnOff:   c.cfn   = value & 0x0000FFFFu; return;
    case kCssaOff:  c.cssa  = value; return;
    case kCdsaOff:  c.cdsa  = value; return;
    case kCseiOff:  c.csei  = value & 0x0000FFFFu; return;
    case kCsfiOff:  c.csfi  = value; return;
    case kCdeiOff:  c.cdei  = value & 0x0000FFFFu; return;
    case kCdfiOff:  c.cdfi  = value; return;
    case kCsacOff:  c.csac  = value; return;
    case kCdacOff:  c.cdac  = value; return;
    case kCcenOff:  c.ccen  = value & 0x00FFFFFFu; return;
    case kCcfnOff:  c.ccfn  = value & 0x0000FFFFu; return;
    case kColorOff: c.color = value; return;
    default: return;
    }
}

void Omap3530SdmaBase::RaiseSyncEvent(uint32_t source) {
    if (source == 0u) return;
    std::lock_guard<std::recursive_mutex> lk(state_mu_);
    const uint32_t count = static_cast<uint32_t>(channels_.size());
    for (uint32_t ch = 0; ch < count; ++ch) {
        Channel& c = channels_[ch];
        if ((c.ccr & kCcrEnable) == 0u) continue;
        if (ExtractSyncSource(c.ccr) != source) continue;
        if ((c.csr & kCsrBlock) != 0u) continue;
        ExecuteSyncUnit(static_cast<int>(ch));
    }
    UpdateIrqLines();
}

void Omap3530SdmaBase::RunSwTransfer(int ch) {
    Channel& c = channels_[ch];
    const uint32_t cen = c.cen & 0x00FFFFFFu;
    const uint32_t cfn = c.cfn & 0x0000FFFFu;
    if (cen == 0u || cfn == 0u) {
        c.csr |= kCsrBlock | kCsrFrame | kCsrLast;
        OnChannelComplete(ch);
        return;
    }
    c.csac = c.cssa;
    c.cdac = c.cdsa;
    c.ccen = 0;
    c.ccfn = 0;
    c.active = true;
    while ((c.csr & kCsrBlock) == 0u) {
        if (!TransferOneElement(ch)) return;
    }
}

void Omap3530SdmaBase::ExecuteSyncUnit(int ch) {
    Channel& c = channels_[ch];
    if (!c.active) {
        c.csac = c.cssa;
        c.cdac = c.cdsa;
        c.ccen = 0;
        c.ccfn = 0;
        c.active = true;
    }
    const bool fs = (c.ccr & kCcrFs) != 0u;
    const bool bs = (c.ccr & kCcrBs) != 0u;

    if (!fs && !bs) {
        TransferOneElement(ch);
        return;
    }
    if (fs && !bs) {
        const uint32_t cen = c.cen & 0x00FFFFFFu;
        for (uint32_t i = 0; i < cen; ++i) {
            if (!TransferOneElement(ch)) return;
            if ((c.csr & kCsrBlock) != 0u) return;
        }
        return;
    }
    if (!fs && bs) {
        while ((c.csr & kCsrBlock) == 0u) {
            if (!TransferOneElement(ch)) return;
        }
        return;
    }
    const bool src_sync = (c.ccr & kCcrSelSrcDstSync) != 0u;
    const uint32_t pkt_elnt = src_sync ? (c.csfi & 0xFFFFu) : (c.cdfi & 0xFFFFu);
    for (uint32_t i = 0; i < pkt_elnt; ++i) {
        if (!TransferOneElement(ch)) return;
        if ((c.csr & kCsrBlock) != 0u) return;
    }
    c.csr |= kCsrPkt;
}

bool Omap3530SdmaBase::TransferOneElement(int ch) {
    Channel& c = channels_[ch];
    const uint32_t es = ElementSize(c.csdp);
    if (es == 8u) {
        RaiseChannelFault(ch, kCsrMisAlign);
        return false;
    }
    const uint32_t src_amode = (c.ccr >> 12) & 0x3u;
    const uint32_t dst_amode = (c.ccr >> 14) & 0x3u;
    const bool const_fill   = (c.ccr & kCcrConstFillEnable)   != 0u;
    const bool transp_copy  = (c.ccr & kCcrTransparentCopyEn) != 0u;
    const bool src_endian   = (c.csdp & kCsdpSrcEndianBig)    != 0u;
    const bool dst_endian   = (c.csdp & kCsdpDstEndianBig)    != 0u;

    auto& mem  = emu_.Get<EmulatedMemory>();
    auto& disp = emu_.Get<PeripheralDispatcher>();

    uint32_t src_val = 0;
    if (const_fill) {
        src_val = c.color;
    } else {
        const uint32_t spa = (src_amode == 0u) ? c.cssa : c.csac;
        if (!IsAligned(spa, es)) {
            RaiseChannelFault(ch, kCsrMisAlign);
            return false;
        }
        uint8_t* sh = mem.TryTranslate(spa);
        if (sh) {
            std::memcpy(&src_val, sh, es);
        } else {
            switch (es) {
            case 1: src_val = disp.ReadByte(spa); break;
            case 2: src_val = disp.ReadHalf(spa); break;
            case 4: src_val = disp.ReadWord(spa); break;
            }
        }
        if (src_endian) src_val = ByteSwap(src_val, es);
    }

    bool write_dst = true;
    if (transp_copy) {
        const uint32_t mask = (es == 4u) ? 0xFFFFFFFFu : ((1u << (es * 8u)) - 1u);
        if ((src_val & mask) == (c.color & mask)) write_dst = false;
    }

    if (write_dst) {
        uint32_t dval = dst_endian ? ByteSwap(src_val, es) : src_val;
        const uint32_t dpa = c.cdac;
        if (!IsAligned(dpa, es)) {
            RaiseChannelFault(ch, kCsrMisAlign);
            return false;
        }
        uint8_t* dh = mem.TryTranslateWrite(dpa);
        if (dh) {
            std::memcpy(dh, &dval, es);
        } else {
            switch (es) {
            case 1: disp.WriteByte(dpa, static_cast<uint8_t> (dval)); break;
            case 2: disp.WriteHalf(dpa, static_cast<uint16_t>(dval)); break;
            case 4: disp.WriteWord(dpa, dval);                        break;
            }
        }
    }

    const uint32_t cen = c.cen & 0x00FFFFFFu;
    const uint32_t cfn = c.cfn & 0x0000FFFFu;
    c.ccen += 1u;
    const int32_t csei = static_cast<int32_t>(static_cast<int16_t>(
                            static_cast<uint16_t>(c.csei & 0xFFFFu)));
    const int32_t cdei = static_cast<int32_t>(static_cast<int16_t>(
                            static_cast<uint16_t>(c.cdei & 0xFFFFu)));
    const int32_t csfi = static_cast<int32_t>(c.csfi);
    const int32_t cdfi = static_cast<int32_t>(c.cdfi);

    const bool end_of_frame = (c.ccen == cen);
    if (!const_fill) c.csac = StepAddress(c.csac, src_amode, csei, csfi, es, end_of_frame);
    c.cdac = StepAddress(c.cdac, dst_amode, cdei, cdfi, es, end_of_frame);

    if (end_of_frame) {
        c.ccen = 0;
        c.ccfn += 1u;
        c.csr |= kCsrFrame;
        if (c.ccfn == cfn) {
            c.csr |= kCsrBlock | kCsrLast;
            OnChannelComplete(ch);
        }
    }
    return true;
}

uint32_t Omap3530SdmaBase::StepAddress(uint32_t cur, uint32_t amode,
                                       int32_t ei, int32_t fi,
                                       uint32_t es, bool end_of_frame) const {
    switch (amode) {
    case 0u: return cur;
    case 1u: return cur + es;
    case 2u: return cur + es + static_cast<uint32_t>(ei - 1);
    case 3u: return cur + es + static_cast<uint32_t>(
                              (end_of_frame ? fi : ei) - 1);
    default: return cur;
    }
}

void Omap3530SdmaBase::RaiseChannelFault(int ch, uint32_t csr_fault_bits) {
    Channel& c = channels_[ch];
    c.csr |= csr_fault_bits | kCsrBlock;
    c.active = false;
    LOG(Caution,
        "[SDMA] ch%u fault csr=0x%08X cssa=0x%08X cdsa=0x%08X csac=0x%08X "
        "cdac=0x%08X ccr=0x%08X csdp=0x%08X\n",
        static_cast<uint32_t>(ch), c.csr, c.cssa, c.cdsa, c.csac, c.cdac,
        c.ccr, c.csdp);
}

void Omap3530SdmaBase::OnChannelComplete(int ch) {
    Channel& c = channels_[ch];
    c.active = false;
    if ((c.clnk_ctrl & kClnkEnable) != 0u) {
        StartChain(static_cast<int>(c.clnk_ctrl & 0x1Fu));
    }
}

void Omap3530SdmaBase::StartChain(int ch) {
    if (ch < 0 || ch >= static_cast<int>(channels_.size())) return;
    Channel& c = channels_[ch];
    c.csr &= ~(kCsrBlock | kCsrFrame | kCsrLast | kCsrPkt);
    c.active = false;
    c.ccen = 0;
    c.ccfn = 0;
    if (ExtractSyncSource(c.ccr) == 0u) {
        RunSwTransfer(ch);
    }
}

void Omap3530SdmaBase::UpdateIrqLines() {
    const uint32_t count = static_cast<uint32_t>(channels_.size());
    for (uint32_t ch = 0; ch < count; ++ch) {
        const Channel& c = channels_[ch];
        const uint32_t fired = c.csr & c.cicr;
        if (fired == 0u) continue;
        const uint32_t bit = (1u << ch);
        for (int j = 0; j < 4; ++j) {
            if (irqenable_l_[j] & bit) irqstatus_l_[j] |= bit;
        }
    }
    auto& intc = emu_.Get<IrqController>();
    for (int j = 0; j < 4; ++j) {
        const int irq = IrqForLine(j);
        if (irq < 0) continue;
        const bool want_high =
            (irqstatus_l_[j] & irqenable_l_[j]) != 0u;
        if (want_high == irq_line_high_[j]) continue;
        irq_line_high_[j] = want_high;
        if (want_high) intc.AssertIrq  (irq);
        else           intc.DeAssertIrq(irq);
    }
}
