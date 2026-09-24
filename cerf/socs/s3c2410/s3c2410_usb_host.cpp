#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

/* S3C2410 USB host: standard OpenHCI Rev 1.0a at PA 0x49000000 (S3C2410A manual
   Table 12-1; two port-status regs => NDP=2). No USB devices are emulated: a
   passive register file, ports disconnected, no interrupt raised - the OHCD's
   IST (ohci2.dll sub_33CB560) waits on the IRQ event forever (correct empty host). */

namespace {

constexpr uint32_t kBase = 0x49000000u;
constexpr uint32_t kSize = 0x0000005Cu;   /* HcRevision..HcRhPortStatus2 (0x00..0x5B) */

constexpr uint32_t kRegCount = kSize / 4u; /* 23 OHCI core registers */

/* Register offsets (S3C2410A Table 12-1). */
constexpr uint32_t kHcRevision      = 0x00u;
constexpr uint32_t kHcCommandStatus = 0x08u;
constexpr uint32_t kHcFmInterval    = 0x34u;
constexpr uint32_t kHcLSThreshold   = 0x44u;
constexpr uint32_t kHcRhDescriptorA = 0x48u;
constexpr uint32_t kHcRhPortStatus1 = 0x54u;
constexpr uint32_t kHcRhPortStatus2 = 0x58u;

constexpr uint32_t kRevision1_0a = 0x10u;        /* OHCI 1.0a                       */
constexpr uint32_t kRhdaNdpMask  = 0xFFu;        /* HcRhDescriptorA.NDP (bits[7:0]) */
constexpr uint32_t kNdp          = 2u;           /* two downstream ports            */
constexpr uint32_t kPortCcs      = 1u << 0;      /* HcRhPortStatus.CCS              */
constexpr uint32_t kPortCsc      = 1u << 16;     /* HcRhPortStatus.CSC              */

/* OpenHCI 1.0a reset values (spec sections 7.3.1 / 7.3.5). */
constexpr uint32_t kFmIntervalReset  = 0x2EDFu;  /* FI = 11999                      */
constexpr uint32_t kLSThresholdReset = 0x0628u;

class S3C2410UsbHost : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::S3c2410;
    }

    void OnReady() override {
        ResetRegs();
        emu_.Get<PeripheralDispatcher>().Register(this);
        LOG(Boot, "S3C2410UsbHost: OpenHCI 1.0a at PA 0x%08X (NDP=2, no devices)\n",
            kBase);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        if (off & 3u) HaltUnsupportedAccess("ReadWord(unaligned)", addr, 0);
        const uint32_t idx = off / 4u;
        switch (off) {
        case kHcRevision:
            return kRevision1_0a;                          /* RO: OHCI 1.0a */
        case kHcCommandStatus:
            /* HCR/CLF/BLF/OCR are self-completing requests with no lists or
               devices behind them, and SOC (bits[17:16]) reads 0. The OHCD's
               post-reset poll `while((base+0x08)&1);` therefore sees HCR=0. */
            return 0u;
        case kHcRhDescriptorA:
            /* NDP (bits[7:0]) is controller-fixed at 2; the rest is writable
               (the OHCD sets NPS here). */
            return (regs_[idx] & ~kRhdaNdpMask) | kNdp;
        case kHcRhPortStatus1:
        case kHcRhPortStatus2:
            /* No device is ever attached: CurrentConnectStatus and
               ConnectStatusChange always read 0 (port permanently empty). */
            return regs_[idx] & ~(kPortCcs | kPortCsc);
        default:
            return regs_[idx];
        }
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;
        if (off & 3u) HaltUnsupportedAccess("WriteWord(unaligned)", addr, value);
        if (off == kHcRevision) return;                    /* RO */
        /* HcCommandStatus.HCR self-clears on read; storing the raw write is
           harmless because the read path masks it. */
        regs_[off / 4u] = value;
    }

    void SaveState(StateWriter& w) override {
        for (uint32_t i = 0; i < kRegCount; ++i) w.Write("regs", regs_[i]);
    }
    void RestoreState(StateReader& r) override {
        for (uint32_t i = 0; i < kRegCount; ++i) r.Read("regs", regs_[i]);
    }

private:
    void ResetRegs() {
        for (uint32_t i = 0; i < kRegCount; ++i) regs_[i] = 0u;
        regs_[kHcFmInterval    / 4u] = kFmIntervalReset;
        regs_[kHcLSThreshold   / 4u] = kLSThresholdReset;
        regs_[kHcRhDescriptorA / 4u] = kNdp;
    }

    uint32_t regs_[kRegCount] = {};
};

}  /* namespace */

REGISTER_SERVICE(S3C2410UsbHost);
