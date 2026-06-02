#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>
#include <mutex>

namespace {

constexpr uint32_t kBasePa     = 0x4804FC00u;
constexpr uint32_t kApertureSz = 0x00000400u;

constexpr uint32_t kDsiBase    = 0x000u;
constexpr uint32_t kDsiPhyBase = 0x200u;
constexpr uint32_t kDsiPllBase = 0x300u;
constexpr uint32_t kSubSize    = 0x100u;
constexpr uint32_t kSubWords   = kSubSize / 4u;

constexpr uint32_t kDsiRev        = 0x00u;
constexpr uint32_t kDsiSysconfig  = 0x10u;
constexpr uint32_t kDsiSysstatus  = 0x14u;
constexpr uint32_t kDsiIrqstatus  = 0x18u;
constexpr uint32_t kDsiClkCtrl    = 0x54u;

constexpr uint32_t kPllControl   = 0x00u;
constexpr uint32_t kPllStatus    = 0x04u;
constexpr uint32_t kPllGo        = 0x08u;

constexpr uint32_t kSysconfigSoftReset = 1u << 1;
constexpr uint32_t kSysstatusResetDone = 1u << 0;

constexpr uint32_t kPllPwrCmdMask    = 3u << 30;
constexpr uint32_t kPllPwrStatusMask = 3u << 28;
constexpr uint32_t kPllPwrShift      = 2;  /* CMD bits[31:30] → STATUS bits[29:28] */

constexpr uint32_t kPllResetDone = 1u << 0;
constexpr uint32_t kPllLockStatus = 1u << 1;
constexpr uint32_t kPllGoCmd      = 1u << 0;

class Omap3530Dsi : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::OMAP3530;
    }
    void OnReady() override {
        dsi_   [kDsiSysstatus / 4u] = kSysstatusResetDone;
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBasePa; }
    uint32_t MmioSize() const override { return kApertureSz; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (off & 3u) HaltUnsupportedAccess("ReadWord (misaligned)", addr, 0);
        std::lock_guard<std::mutex> lk(state_mutex_);

        if (off < kDsiPhyBase) {
            uint32_t v = dsi_[off / 4u];
            LOG(Periph, "[DSI] R off=0x%03X -> 0x%08X\n", off, v);
            return v;
        }
        if (off < kDsiPllBase) {
            const uint32_t v = dsi_phy_[(off - kDsiPhyBase) / 4u];
            LOG(Periph, "[DSIPHY] R off=0x%03X -> 0x%08X\n",
                off - kDsiPhyBase, v);
            return v;
        }
        const uint32_t poff = off - kDsiPllBase;
        uint32_t v;
        if (poff == kPllStatus) {
            /* MUST derive, not store — dssai.cpp:4882 polls RESET_DONE
               after CLK_CTRL handshake, :5076 polls LOCK_STATUS after
               PLL_GO. Plain storage = both stay 0 = InitDsiPll fails. */
            v = 0u;
            if (((dsi_[kDsiClkCtrl / 4u] & kPllPwrStatusMask) != 0u))
                v |= kPllResetDone;
            if (pll_locked_) v |= kPllLockStatus;
        } else if (poff == kPllGo) {
            /* Reads always return 0 — dssai.cpp:5061 waits for the
               written GO_CMD bit to clear, modelled as "never stored
               in the first place". */
            v = 0u;
        } else {
            v = dsi_pll_[poff / 4u];
        }
        LOG(Periph, "[DSI_PLL] R off=0x%03X -> 0x%08X\n", poff, v);
        return v;
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off & 3u) HaltUnsupportedAccess("WriteWord (misaligned)", addr, value);
        std::lock_guard<std::mutex> lk(state_mutex_);

        if (off < kDsiPhyBase) {
            LOG(Periph, "[DSI] W off=0x%03X <- 0x%08X\n", off, value);
            switch (off) {
            case kDsiSysconfig:
                dsi_[kDsiSysconfig / 4u] = value & ~kSysconfigSoftReset;
                return;
            case kDsiSysstatus:
                return;  /* read-only */
            case kDsiIrqstatus:
                /* W1C — dssai.cpp:4848-4849 reads value then writes
                   it back to clear all pending. */
                dsi_[kDsiIrqstatus / 4u] &= ~value;
                return;
            case kDsiClkCtrl: {
                /* MUST mirror PWR_CMD bits[31:30] → PWR_STATUS bits[29:28]
                   on write — dssai.cpp:4862 polls STATUS == CMD; plain
                   storage = poll never succeeds = InitDsiPll fails. */
                const uint32_t pwr_cmd = value & kPllPwrCmdMask;
                const uint32_t new_status = pwr_cmd >> kPllPwrShift;
                dsi_[kDsiClkCtrl / 4u] =
                    (value & ~kPllPwrStatusMask) | new_status;
                return;
            }
            case kDsiRev:
                return;  /* read-only */
            default:
                dsi_[off / 4u] = value;
                return;
            }
        }
        if (off < kDsiPllBase) {
            dsi_phy_[(off - kDsiPhyBase) / 4u] = value;
            LOG(Periph, "[DSIPHY] W off=0x%03X <- 0x%08X\n",
                off - kDsiPhyBase, value);
            return;
        }
        const uint32_t poff = off - kDsiPllBase;
        LOG(Periph, "[DSI_PLL] W off=0x%03X <- 0x%08X\n", poff, value);
        switch (poff) {
        case kPllStatus:
            return;  /* read-only */
        case kPllGo:
            /* dssai.cpp:5057 writes GO_CMD bit; HW auto-clears once
               lock request issued (dssai.cpp:5061 polls until 0).
               Don't store the bit; latch lock so PLL_STATUS reads
               LOCK_STATUS thereafter. */
            if (value & kPllGoCmd) pll_locked_ = true;
            return;
        default:
            dsi_pll_[poff / 4u] = value;
            return;
        }
    }

private:
    mutable std::mutex state_mutex_;
    uint32_t dsi_     [kSubWords]{};
    uint32_t dsi_phy_ [kSubWords]{};
    uint32_t dsi_pll_ [kSubWords]{};
    bool     pll_locked_ = false;
};

}  /* namespace */

REGISTER_SERVICE(Omap3530Dsi);
