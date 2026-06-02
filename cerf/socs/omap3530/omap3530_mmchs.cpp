#include "omap3530_prcm_stub_block.h"
#include "omap3530_sdma.h"

namespace {

constexpr uint32_t kOffSysstatus = 0x014u;
constexpr uint32_t kOffCon       = 0x02Cu;
constexpr uint32_t kOffCmd       = 0x10Cu;
constexpr uint32_t kOffData      = 0x120u;
constexpr uint32_t kOffPstate    = 0x124u;
constexpr uint32_t kOffStat      = 0x130u;
constexpr uint32_t kOffCapa      = 0x140u;

constexpr uint32_t kCmdDmaEnable = 1u << 0;
constexpr uint32_t kCmdDataPres  = 1u << 5;
constexpr uint32_t kCmdReadDir   = 1u << 4;

class Omap3530MmchsBase : public Omap3530PrcmStubBlock {
public:
    using Omap3530PrcmStubBlock::Omap3530PrcmStubBlock;
    uint32_t MmioSize() const override { return 0x00001000u; }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        bool fire_tx = false;
        bool fire_rx = false;

        if (off == kOffCmd) {
            /* CMD write kicks off a transfer: if DMA enabled + data
               present, fire the appropriate direction. */
            if ((value & kCmdDmaEnable) && (value & kCmdDataPres)) {
                if (value & kCmdReadDir) fire_rx = true;
                else                     fire_tx = true;
            }
        } else if (off == kOffData) {
            /* Each DATA write while a TX command is active drives
               the next DMA-REQ for the next word. */
            const uint32_t last_cmd = PeekReg(kOffCmd);
            if ((last_cmd & kCmdDmaEnable) && (last_cmd & kCmdDataPres) &&
                !(last_cmd & kCmdReadDir)) {
                fire_tx = true;
            }
        }

        Omap3530PrcmStubBlock::WriteWord(addr, value);

        if ((fire_tx || fire_rx) && TxSyncSource() != 0) {
            auto& sdma = emu_.Get<Omap3530Sdma>();
            if (fire_rx) sdma.RaiseSyncEvent(RxSyncSource());
            if (fire_tx) sdma.RaiseSyncEvent(TxSyncSource());
        }
    }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (off == kOffSysstatus) return 1u;        /* RESETDONE */
        if (off == kOffCapa)      return 0x00000000u; /* no slot present */
        if (off == kOffPstate)    return 0u;        /* CMD/DATA idle */
        if (off == kOffStat)      return 0u;        /* no interrupts pending */

        const uint32_t value = Omap3530PrcmStubBlock::ReadWord(addr);
        if (off == kOffData) {
            const uint32_t last_cmd = PeekReg(kOffCmd);
            if ((last_cmd & kCmdDmaEnable) && (last_cmd & kCmdDataPres) &&
                (last_cmd & kCmdReadDir) && RxSyncSource() != 0) {
                emu_.Get<Omap3530Sdma>().RaiseSyncEvent(RxSyncSource());
            }
        }
        return value;
    }

protected:
    const char* RegisterName(uint32_t off) const override {
        switch (off) {
        case 0x010: return "MMCHS_SYSCONFIG";
        case 0x014: return "MMCHS_SYSSTATUS";
        case 0x024: return "MMCHS_CSRE";
        case 0x028: return "MMCHS_SYSTEST";
        case 0x02C: return "MMCHS_CON";
        case 0x030: return "MMCHS_PWCNT";
        case 0x104: return "MMCHS_BLK";
        case 0x108: return "MMCHS_ARG";
        case 0x10C: return "MMCHS_CMD";
        case 0x110: return "MMCHS_RSP10";
        case 0x114: return "MMCHS_RSP32";
        case 0x118: return "MMCHS_RSP54";
        case 0x11C: return "MMCHS_RSP76";
        case 0x120: return "MMCHS_DATA";
        case 0x124: return "MMCHS_PSTATE";
        case 0x128: return "MMCHS_HCTL";
        case 0x12C: return "MMCHS_SYSCTL";
        case 0x130: return "MMCHS_STAT";
        case 0x134: return "MMCHS_IE";
        case 0x138: return "MMCHS_ISE";
        case 0x13C: return "MMCHS_AC12";
        case 0x140: return "MMCHS_CAPA";
        case 0x148: return "MMCHS_CUR_CAPA";
        case 0x1FC: return "MMCHS_REV";
        }
        return nullptr;
    }
    virtual uint32_t TxSyncSource() const = 0;
    virtual uint32_t RxSyncSource() const = 0;
};

class Omap3530Mmchs1 : public Omap3530MmchsBase {
public:
    using Omap3530MmchsBase::Omap3530MmchsBase;
    uint32_t MmioBase() const override { return 0x4809C000u; }
protected:
    const char* Label() const override { return "MMCHS1"; }
    uint32_t TxSyncSource() const override { return Omap3530Sdma::kSyncMmc1Tx; }
    uint32_t RxSyncSource() const override { return Omap3530Sdma::kSyncMmc1Rx; }
};

class Omap3530Mmchs2 : public Omap3530MmchsBase {
public:
    using Omap3530MmchsBase::Omap3530MmchsBase;
    uint32_t MmioBase() const override { return 0x480B4000u; }
protected:
    const char* Label() const override { return "MMCHS2"; }
    uint32_t TxSyncSource() const override { return Omap3530Sdma::kSyncMmc2Tx; }
    uint32_t RxSyncSource() const override { return Omap3530Sdma::kSyncMmc2Rx; }
};

class Omap3530Mmchs3 : public Omap3530MmchsBase {
public:
    using Omap3530MmchsBase::Omap3530MmchsBase;
    uint32_t MmioBase() const override { return 0x480AD000u; }
protected:
    const char* Label() const override { return "MMCHS3"; }
    uint32_t TxSyncSource() const override { return Omap3530Sdma::kSyncMmc3Tx; }
    uint32_t RxSyncSource() const override { return Omap3530Sdma::kSyncMmc3Rx; }
};

}  /* namespace */

REGISTER_SERVICE(Omap3530Mmchs1);
REGISTER_SERVICE(Omap3530Mmchs2);
REGISTER_SERVICE(Omap3530Mmchs3);
