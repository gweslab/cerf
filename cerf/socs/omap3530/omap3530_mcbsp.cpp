#include "omap3530_prcm_stub_block.h"
#include "omap3530_sdma.h"

namespace {

constexpr uint32_t kOffDxrBig    = 0x0Cu;
constexpr uint32_t kOffDxrLp     = 0x08u;
constexpr uint32_t kOffSpcr2     = 0x10u;
constexpr uint32_t kOffSysconfig = 0x8Cu;

constexpr uint32_t kSpcr2Xrst    = 1u << 0;
constexpr uint32_t kSysconfigSoftReset = 1u << 1;

class Omap3530McBspBase : public Omap3530PrcmStubBlock {
public:
    using Omap3530PrcmStubBlock::Omap3530PrcmStubBlock;
    uint32_t MmioSize() const override { return 0x00001000u; }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        bool fire_tx = false;

        if (off == kOffSysconfig) {
            /* SYSCONFIG.SOFTRESET auto-clears once reset completes;
               mcbsp.dll polls for the bit going back to 0. */
            value &= ~kSysconfigSoftReset;
        } else if (off == kOffSpcr2) {
            const uint32_t old_spcr2 = PeekReg(kOffSpcr2);
            const bool was_xrst = (old_spcr2 & kSpcr2Xrst) != 0u;
            const bool now_xrst = (value & kSpcr2Xrst) != 0u;
            if (!was_xrst && now_xrst) fire_tx = true;
        } else if (off == kOffDxrBig || off == kOffDxrLp) {
            const uint32_t spcr2 = PeekReg(kOffSpcr2);
            if (spcr2 & kSpcr2Xrst) fire_tx = true;
        }

        Omap3530PrcmStubBlock::WriteWord(addr, value);

        if (fire_tx && TxSyncSource() != 0) {
            emu_.Get<Omap3530Sdma>().RaiseSyncEvent(TxSyncSource());
        }
    }

protected:
    const char* RegisterName(uint32_t) const override { return nullptr; }
    virtual uint32_t TxSyncSource() const { return 0; }
    virtual uint32_t RxSyncSource() const { return 0; }
};

class Omap3530McBsp1 : public Omap3530McBspBase {
public:
    using Omap3530McBspBase::Omap3530McBspBase;
    uint32_t MmioBase() const override { return 0x48074000u; }
protected:
    const char* Label() const override { return "MCBSP1"; }
    uint32_t TxSyncSource() const override { return Omap3530Sdma::kSyncMcbsp1Tx; }
    uint32_t RxSyncSource() const override { return Omap3530Sdma::kSyncMcbsp1Rx; }
};

class Omap3530McBsp2 : public Omap3530McBspBase {
public:
    using Omap3530McBspBase::Omap3530McBspBase;
    uint32_t MmioBase() const override { return 0x49022000u; }
protected:
    const char* Label() const override { return "MCBSP2"; }
    uint32_t TxSyncSource() const override { return Omap3530Sdma::kSyncMcbsp2Tx; }
    uint32_t RxSyncSource() const override { return Omap3530Sdma::kSyncMcbsp2Rx; }
};

class Omap3530McBsp3 : public Omap3530McBspBase {
public:
    using Omap3530McBspBase::Omap3530McBspBase;
    uint32_t MmioBase() const override { return 0x49024000u; }
protected:
    const char* Label() const override { return "MCBSP3"; }
    uint32_t TxSyncSource() const override { return Omap3530Sdma::kSyncMcbsp3Tx; }
    uint32_t RxSyncSource() const override { return Omap3530Sdma::kSyncMcbsp3Rx; }
};

class Omap3530McBsp4 : public Omap3530McBspBase {
public:
    using Omap3530McBspBase::Omap3530McBspBase;
    uint32_t MmioBase() const override { return 0x49026000u; }
protected:
    const char* Label() const override { return "MCBSP4"; }
    uint32_t TxSyncSource() const override { return Omap3530Sdma::kSyncMcbsp4Tx; }
    uint32_t RxSyncSource() const override { return Omap3530Sdma::kSyncMcbsp4Rx; }
};

class Omap3530McBsp5 : public Omap3530McBspBase {
public:
    using Omap3530McBspBase::Omap3530McBspBase;
    uint32_t MmioBase() const override { return 0x48096000u; }
protected:
    const char* Label() const override { return "MCBSP5"; }
    uint32_t TxSyncSource() const override { return Omap3530Sdma::kSyncMcbsp5Tx; }
    uint32_t RxSyncSource() const override { return Omap3530Sdma::kSyncMcbsp5Rx; }
};

}  /* namespace */

REGISTER_SERVICE(Omap3530McBsp1);
REGISTER_SERVICE(Omap3530McBsp2);
REGISTER_SERVICE(Omap3530McBsp3);
REGISTER_SERVICE(Omap3530McBsp4);
REGISTER_SERVICE(Omap3530McBsp5);
