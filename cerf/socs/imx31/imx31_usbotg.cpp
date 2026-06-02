#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

/* MCIMX31RM Ch 32 (Tables 32-23/24/32) USB-OTG, no USB device wired. PORTSC
   config bits (31:12) are R/W; status bits (11:0 — CCS/PE/etc.) must read 0 so
   the kernel's connect/enable checks see no device. Unreached registers halt. */
constexpr uint32_t kBase        = 0x43F88000u;
constexpr uint32_t kSize        = 0x00004000u;
constexpr uint32_t kPortscFirst = 0x184u;
constexpr uint32_t kPortscLast  = 0x1A0u;  /* PORTSC1..PORTSC8, 4-byte stride */
constexpr uint32_t kPortscCfg   = 0xFFFFF000u; /* bits 31:12 R/W config; 11:0 status */
constexpr uint32_t kUsbcmd      = 0x140u;
constexpr uint32_t kUsbsts      = 0x144u;
constexpr uint32_t kUsbintr     = 0x148u;
constexpr uint32_t kCmdRs       = 1u << 0;     /* USBCMD Run/Stop */
constexpr uint32_t kCmdRst      = 1u << 1;     /* USBCMD Controller Reset (self-clears) */
constexpr uint32_t kCmdPse      = 1u << 4;     /* USBCMD Periodic Schedule Enable (Table 32-23) */
constexpr uint32_t kCmdAse      = 1u << 5;     /* USBCMD Async Schedule Enable (Table 32-23) */
constexpr uint32_t kStsHcHalted = 1u << 12;    /* USBSTS HCHalted */
constexpr uint32_t kStsPs       = 1u << 14;    /* USBSTS Periodic Schedule Status (Table 32-24) */
constexpr uint32_t kStsAs       = 1u << 15;    /* USBSTS Async Schedule Status (Table 32-24) */
constexpr uint32_t kUsbcmdReset = 0x00080000u; /* ITC=0x08 (Table 32-23) */
constexpr uint32_t kUsbCtrl     = 0x600u;      /* USB_CTRL (Table 32-3) */
constexpr uint32_t kOtgMirror   = 0x604u;      /* OTG_MIRROR */
constexpr uint32_t kUsbmode     = 0x1A8u;      /* USBMODE CM/ES (Table 32-34) */
constexpr uint32_t kConfigFlag  = 0x180u;      /* CONFIGFLAG CF bit0, reset 1 (Table 32-13) */
constexpr uint32_t kOtgsc       = 0x1A4u;      /* OTGSC On-The-Go status/ctrl (Table 32-33) */
/* OTGSC: bits30:24 interrupt-enable + bits5:0 control are R/W; bits19:16 are
   W1C interrupt-status; bits14:8 are R/O OTG line status. No USB cable on the
   Zune (a B-device): ID(8)=1 (B-device), BSE(12)=1 (VBus below B-session-end),
   BSV/ASV/AVV=0 (Table 32-33). */
constexpr uint32_t kOtgscRwMask = 0x7F00003Bu;
constexpr uint32_t kOtgscNoCable = 0x00001100u;  /* ID(8) | BSE(12) */
/* Device-mode endpoint controller (Table 32-2) — used by the USB-function /
   MTP driver. All 32-bit, reset 0. */
constexpr uint32_t kEndptSetupStat = 0x1ACu;   /* ENDPTSETUPSTAT W1C (Table 32-35) */
constexpr uint32_t kEndptPrime     = 0x1B0u;   /* ENDPTPRIME, HW-clears (Table 32-36) */
constexpr uint32_t kEndptFlush     = 0x1B4u;   /* ENDPTFLUSH, HW-clears (Table 32-37) */
constexpr uint32_t kEndptStat      = 0x1B8u;   /* ENDPTSTAT R/O ready bitmap (Fig 32-41) */
constexpr uint32_t kEndptComplete  = 0x1BCu;   /* ENDPTCOMPLETE W1C */
constexpr uint32_t kEndptCtrl0     = 0x1C0u;   /* ENDPTCTRL0..15 (§32.9.5.18) */
constexpr uint32_t kEndptCtrl15    = 0x1FCu;
/* EHCI operational list/index regs (§32.9.5, Figs 32-27/28/30) — R/W,
   reset 0; no schedule runs with no device, so plain storage. */
constexpr uint32_t kFrIndex     = 0x14Cu;      /* FRINDEX */
constexpr uint32_t kCtrlDsSeg   = 0x150u;      /* CTRLDSSEGMENT 4G segment, unused (ADC=0) */
constexpr uint32_t kPeriodicBase = 0x154u;     /* PERIODICLISTBASE / DEVICEADDR */
constexpr uint32_t kAsyncAddr   = 0x158u;      /* ASYNCLISTADDR / ENDPOINTLISTADDR */
constexpr uint32_t kTxFillTune  = 0x164u;      /* TXFILLTUNING perf tuning, reset 0 (Fig 32-33) */
constexpr uint32_t kUlpiView    = 0x170u;      /* ULPIVIEW (Fig 32-34) */
constexpr uint32_t kUlpiWu      = 1u << 31;    /* ULPIVIEW Wakeup, self-clears */
constexpr uint32_t kUlpiRun     = 1u << 30;    /* ULPIVIEW Run, self-clears on xfer done */

/* EHCI capability registers (read-only) — MCIMX31RM §32.9.4 Fig 32-18..32-21.
   0x100 word packs CAPLENGTH(0x40)|HCIVERSION(0x0100<<16); HCSPARAMS N_PORTS=1
   (a 0 there is "undefined" so the host driver needs ≥1); HCCPARAMS=0x0006. */
constexpr uint32_t kCapLength   = 0x100u;
constexpr uint32_t kHciVersion  = 0x102u;
constexpr uint32_t kHcsParams   = 0x104u;
constexpr uint32_t kHccParams   = 0x108u;
constexpr uint32_t kCapWord     = 0x01000040u;
constexpr uint32_t kHcsParamsVal = 0x00000001u;
constexpr uint32_t kHccParamsVal = 0x00000006u;

class Imx31Usbotg : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    /* CAPLENGTH (8-bit) and HCIVERSION (16-bit) are read at their native
       widths by the host driver; the cap word is also word-readable above. */
    uint8_t ReadByte(uint32_t addr) override {
        if (addr - kBase == kCapLength) return 0x40u;     /* CAPLENGTH (Fig 32-18) */
        HaltUnsupportedAccess("ReadByte", addr, 0);
    }
    uint16_t ReadHalf(uint32_t addr) override {
        if (addr - kBase == kHciVersion) return 0x0100u;  /* HCIVERSION (Fig 32-19) */
        HaltUnsupportedAccess("ReadHalf", addr, 0);
    }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        if (IsPortsc(off)) return portsc_[(off - kPortscFirst) / 4];  /* config only; status=0 */
        if (off >= kEndptCtrl0 && off <= kEndptCtrl15)
            return endptctrl_[(off - kEndptCtrl0) / 4];
        switch (off) {
            case kCapLength: return kCapWord;
            case kHcsParams: return kHcsParamsVal;
            case kHccParams: return kHccParamsVal;
            case kUsbcmd:  return usbcmd_;
            /* AS(15)/PS(14) must mirror USBCMD ASE(5)/PSE(4) — the host driver
               spins until AS==ASE / PS==PSE (hcd_hsotg sub_306B560); returning
               only HCHalted wedges USB bring-up. Tables 32-23/32-24. */
            case kUsbsts: {
                uint32_t sts = (usbcmd_ & kCmdRs) ? 0u : kStsHcHalted;
                if (usbcmd_ & kCmdAse) sts |= kStsAs;
                if (usbcmd_ & kCmdPse) sts |= kStsPs;
                return sts;
            }
            case kUsbintr: return usbintr_;
            /* USB_CTRL/OTG_MIRROR: PHY/control RMW config; no device/no wake so
               the wake-request status bits stay 0 (store-with-reset). */
            case kUsbCtrl:   return usb_ctrl_;
            case kOtgMirror: return otg_mirror_;
            case kUsbmode:   return usbmode_;  /* kernel sets CM=device */
            case kConfigFlag: return configflag_;  /* CF: ports routed to this HC */
            case kOtgsc:     return (otgsc_ & kOtgscRwMask) | kOtgscNoCable;
            case kUlpiView:  return ulpiview_; /* ULPIRUN already cleared */
            case kFrIndex:      return frindex_;
            case kCtrlDsSeg:    return ctrl_ds_seg_;
            case kPeriodicBase: return periodic_base_;
            case kAsyncAddr:    return async_addr_;
            case kTxFillTune:   return tx_fill_tune_;
            /* Device-mode endpoint controller, no USB host attached. PRIME/FLUSH
               are HW-cleared, so they read 0; SETUPSTAT/COMPLETE need host
               traffic so they stay 0; STAT reports the endpoints SW primed. */
            case kEndptSetupStat: return 0;
            case kEndptPrime:     return 0;
            case kEndptFlush:     return 0;
            case kEndptStat:      return endpt_stat_;
            case kEndptComplete:  return 0;
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;
        if (IsPortsc(off)) { portsc_[(off - kPortscFirst) / 4] = value & kPortscCfg; return; }
        if (off >= kEndptCtrl0 && off <= kEndptCtrl15) {
            endptctrl_[(off - kEndptCtrl0) / 4] = value; return;
        }
        switch (off) {
            /* RST self-clears on reset-complete (Table 32-23); reset is instant
               here, so store with RST already cleared. */
            case kUsbcmd:  usbcmd_  = value & ~kCmdRst; return;
            case kUsbsts:  return;  /* W1C status bits; none set (no events) */
            case kUsbintr: usbintr_   = value; return;
            case kUsbCtrl:   usb_ctrl_   = value; return;
            case kOtgMirror: otg_mirror_ = value; return;
            case kUsbmode:   usbmode_    = value; return;
            case kConfigFlag: configflag_ = value & 1u; return;  /* CF bit0; [31:1] SBZ (Table 32-13) */
            case kOtgsc:     otgsc_ = value & kOtgscRwMask; return;  /* R/O status, W1C ints unset */
            /* No emulated ULPI PHY: complete instantly by clearing WU/RUN
               so the driver's "poll until ULPIRUN==0" sees completion. */
            case kUlpiView:  ulpiview_   = value & ~(kUlpiWu | kUlpiRun); return;
            case kFrIndex:      frindex_       = value; return;
            case kCtrlDsSeg:    ctrl_ds_seg_   = value; return;
            case kPeriodicBase: periodic_base_ = value; return;
            case kAsyncAddr:    async_addr_    = value; return;
            case kTxFillTune:   tx_fill_tune_  = value; return;
            /* PRIME makes the named endpoints ready (HW would clear PRIME after
               priming, Table 32-36); FLUSH clears them (Table 32-37). SETUPSTAT/
               COMPLETE are W1C — nothing is set with no host. STAT is read-only. */
            case kEndptPrime:     endpt_stat_ |=  value; return;
            case kEndptFlush:     endpt_stat_ &= ~value; return;
            case kEndptSetupStat: return;
            case kEndptComplete:  return;
            case kEndptStat:      return;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

private:
    static bool IsPortsc(uint32_t off) {
        return off >= kPortscFirst && off <= kPortscLast && (off & 3u) == 0u;
    }
    uint32_t portsc_[8] = {};
    uint32_t usbcmd_     = kUsbcmdReset;
    uint32_t usbintr_    = 0;
    uint32_t usb_ctrl_   = 0;
    uint32_t otg_mirror_ = 0;
    uint32_t usbmode_    = 0;
    uint32_t configflag_ = 1;  /* reset value 1 (Table 32-13) */
    uint32_t otgsc_      = 0;  /* R/W interrupt-enable + control bits */
    uint32_t ulpiview_   = 0;
    uint32_t frindex_       = 0;
    uint32_t ctrl_ds_seg_   = 0;
    uint32_t periodic_base_ = 0;
    uint32_t async_addr_    = 0;
    uint32_t tx_fill_tune_  = 0;
    uint32_t endpt_stat_    = 0;   /* endpoints SW has primed (no host clears them) */
    uint32_t endptctrl_[16] = {};  /* ENDPTCTRL0..15 (§32.9.5.18) */
};

}  /* namespace */

REGISTER_SERVICE(Imx31Usbotg);
