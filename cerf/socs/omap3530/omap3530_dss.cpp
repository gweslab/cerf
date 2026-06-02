#include "omap3530_dss.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/host_window.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../irq_controller.h"

bool Omap3530Dss::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetSoc() == SocFamily::OMAP3530;
}

void Omap3530Dss::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
    dss_top_[kDssSysstatus / 4u]   = kSysstatusResetDone;
    dispc_  [kDispcSysstatus / 4u] = kSysstatusResetDone;
}

bool Omap3530Dss::ShouldAssertIrqLocked() const {
    return (dispc_[kDispcIrqstatus / 4u] &
            dispc_[kDispcIrqenable / 4u] &
            kIrqMask) != 0u;
}

void Omap3530Dss::RecomputeIrqLineLocked() {
    const bool want_high = ShouldAssertIrqLocked();
    if (want_high == irq_line_high_) return;
    irq_line_high_ = want_high;
    auto& intc = emu_.Get<IrqController>();
    if (want_high) intc.AssertIrq  (kIrqDss);
    else           intc.DeAssertIrq(kIrqDss);
}

void Omap3530Dss::HandleDssSysconfigWriteLocked(uint32_t value) {
    dss_top_[kDssSysconfig / 4u] = value & ~kSysconfigSoftReset;
    if (value & kSysconfigSoftReset) {
        /* dssai.cpp:3943-3957 SETs SOFTRESET in DSS_SYSCONFIG then
           polls DSS_SYSSTATUS RESETDONE up to DISPLAY_TIMEOUT ms.
           Model instantaneous reset: re-assert RESETDONE so the
           first poll returns ready. */
        dss_top_[kDssSysstatus / 4u] = kSysstatusResetDone;
    }
}

void Omap3530Dss::HandleDispcSysconfigWriteLocked(uint32_t value) {
    dispc_[kDispcSysconfig / 4u] = value & ~kSysconfigSoftReset;
    if (value & kSysconfigSoftReset) {
        /* dssai.cpp:3996+ — DISPC_SYSCONFIG SOFTRESET / DISPC_SYSSTATUS
           RESETDONE poll. Same instantaneous-reset model. */
        for (auto& w : dispc_) w = 0u;
        dispc_[kDispcSysstatus / 4u] = kSysstatusResetDone;
        irq_line_high_ = false;
        emu_.Get<IrqController>().DeAssertIrq(kIrqDss);
    }
}

void Omap3530Dss::HandleDispcIrqstatusWriteLocked(uint32_t value) {
    /* Write-1-to-clear. dssai.cpp:791,2317,4224,4239 use
       SETREG32(IRQSTATUS, X) = read|X then write back — implementing
       this as plain assignment would clear every bit the reader
       just saw, silently masking the next IRQ assertion. */
    dispc_[kDispcIrqstatus / 4u] &= ~(value & kIrqMask);
    RecomputeIrqLineLocked();
}

void Omap3530Dss::HandleDispcIrqenableWriteLocked(uint32_t value) {
    dispc_[kDispcIrqenable / 4u] = value & kIrqMask;
    RecomputeIrqLineLocked();
}

void Omap3530Dss::HandleDispcControlWrite(uint32_t old_value,
                                          uint32_t new_value) {
    /* dssai.cpp:3931-3938 (ResetDSS) clears LCDENABLE then
       WaitForFrameDone (dssai.cpp:4202-4207) polls IRQSTATUS for
       FRAMEDONE. Real silicon pulses FRAMEDONE on disable; without
       this the driver spins to DISPLAY_TIMEOUT before every reset. */
    const bool lcd_off_edge =
        (old_value & kCtrlLcdEnable) && !(new_value & kCtrlLcdEnable);
    const bool dig_off_edge =
        (old_value & kCtrlDigitalEnable) && !(new_value & kCtrlDigitalEnable);
    if (lcd_off_edge || dig_off_edge) {
        std::lock_guard<std::mutex> lk(state_mutex_);
        dispc_[kDispcIrqstatus / 4u] |= kIrqFrameDone;
        RecomputeIrqLineLocked();
    }

    /* LCDENABLE 0→1: BSP has fully programmed SIZE_LCD / GFX_BA0 /
       GFX_ATTRIBUTES (lcd_vga.c:LcdPdd_LCD_Initialize → SetPowerLevel
       order: SIZE_LCD at line 498, GO at 668, LCDENABLE at 671). */
    const bool lcd_on_edge =
        !(old_value & kCtrlLcdEnable) && (new_value & kCtrlLcdEnable);
    if (lcd_on_edge) {
        emu_.Get<HostWindow>().OnLcdEnabled(GetGuestW(), GetGuestH());
    }
}

uint32_t Omap3530Dss::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off & 3u) HaltUnsupportedAccess("ReadWord (misaligned)", addr, 0);

    std::lock_guard<std::mutex> lk(state_mutex_);

    if (off < kDispcBase) {
        const uint32_t v = dss_top_[off / 4u];
        LOG(Periph, "[DSS] R off=0x%03X -> 0x%08X\n", off, v);
        return v;
    }
    if (off < kRfbiBase) {
        const uint32_t doff = off - kDispcBase;
        const uint32_t v = dispc_[doff / 4u];
        LOG(Periph, "[DISPC] R off=0x%03X -> 0x%08X\n", doff, v);
        return v;
    }
    if (off < kVencBase) {
        const uint32_t v = rfbi_[(off - kRfbiBase) / 4u];
        LOG(Periph, "[RFBI] R off=0x%03X -> 0x%08X (stub)\n",
            off - kRfbiBase, v);
        return v;
    }
    const uint32_t v = venc_[(off - kVencBase) / 4u];
    LOG(Periph, "[VENC] R off=0x%03X -> 0x%08X (stub)\n",
        off - kVencBase, v);
    return v;
}

uint16_t Omap3530Dss::ReadHalf(uint32_t addr) {
    const uint32_t aligned = addr & ~3u;
    const uint32_t word = ReadWord(aligned);
    return static_cast<uint16_t>((word >> ((addr & 2u) * 8u)) & 0xFFFFu);
}

void Omap3530Dss::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off & 3u) HaltUnsupportedAccess("WriteWord (misaligned)", addr, value);

    /* DISPC_CONTROL needs an edge check outside the lock for the
       OnLcdEnabled cross-service call (HostWindow may take its own
       locks). Capture old value under our lock, release, dispatch. */
    if (off >= kDispcBase && off < kRfbiBase
        && (off - kDispcBase) == kDispcControl) {
        uint32_t old_value;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            old_value = dispc_[kDispcControl / 4u];
            dispc_[kDispcControl / 4u] = value;
        }
        LOG(Periph, "[DISPC] W off=0x%03X <- 0x%08X\n", kDispcControl, value);
        HandleDispcControlWrite(old_value, value);
        return;
    }

    std::lock_guard<std::mutex> lk(state_mutex_);

    if (off < kDispcBase) {
        LOG(Periph, "[DSS] W off=0x%03X <- 0x%08X\n", off, value);
        switch (off) {
        case kDssSysconfig: HandleDssSysconfigWriteLocked(value); return;
        case kDssRev:
        case kDssSysstatus:
        case kDssSdiStatus:
            return;  /* read-only */
        default:
            dss_top_[off / 4u] = value;
            return;
        }
    }
    if (off < kRfbiBase) {
        const uint32_t doff = off - kDispcBase;
        LOG(Periph, "[DISPC] W off=0x%03X <- 0x%08X\n", doff, value);
        switch (doff) {
        case kDispcSysconfig: HandleDispcSysconfigWriteLocked(value); return;
        case kDispcIrqstatus: HandleDispcIrqstatusWriteLocked(value); return;
        case kDispcIrqenable: HandleDispcIrqenableWriteLocked(value); return;
        case kDispcRev:
        case kDispcSysstatus:
        case kDispcLineStatus:
            return;  /* read-only */
        default:
            dispc_[doff / 4u] = value;
            return;
        }
    }
    if (off < kVencBase) {
        rfbi_[(off - kRfbiBase) / 4u] = value;
        LOG(Periph, "[RFBI] W off=0x%03X <- 0x%08X (stub)\n",
            off - kRfbiBase, value);
        return;
    }
    venc_[(off - kVencBase) / 4u] = value;
    LOG(Periph, "[VENC] W off=0x%03X <- 0x%08X (stub)\n",
        off - kVencBase, value);
}

void Omap3530Dss::AdvanceScanTick() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    const uint32_t ctrl = dispc_[kDispcControl / 4u];

    if (ctrl & kCtrlLcdEnable) {
        dispc_[kDispcIrqstatus / 4u] |= kIrqVsync;
        /* GO bit auto-clears at next VFP — dssai.cpp:4114 FlushRegs
           polls until clear, dssai.cpp:4144 WaitForFlushDone same.
           Without this the BSP spins forever on shadow-reg commit. */
        dispc_[kDispcControl / 4u] = ctrl & ~kCtrlGoLcd;
    }
    if (ctrl & kCtrlDigitalEnable) {
        dispc_[kDispcIrqstatus / 4u] |= kIrqEvsyncEven | kIrqEvsyncOdd;
        dispc_[kDispcControl / 4u] &= ~kCtrlGoDigital;
    }

    RecomputeIrqLineLocked();
}

bool Omap3530Dss::IsScanning() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return (dispc_[kDispcControl    / 4u] & kCtrlLcdEnable)  != 0u
        && (dispc_[kDispcGfxAttribs / 4u] & kGfxAttrEnable) != 0u;
}

uint32_t Omap3530Dss::GetFbPa() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return dispc_[kDispcGfxBa0 / 4u];
}

uint32_t Omap3530Dss::GetGuestW() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return (dispc_[kDispcSizeLcd / 4u] & 0x7FFu) + 1u;
}

uint32_t Omap3530Dss::GetGuestH() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return ((dispc_[kDispcSizeLcd / 4u] >> 16) & 0x7FFu) + 1u;
}

uint32_t Omap3530Dss::GetGfxFormat() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return (dispc_[kDispcGfxAttribs / 4u] >> 1) & 0xFu;
}

REGISTER_SERVICE(Omap3530Dss);
