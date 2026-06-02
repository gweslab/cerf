#include "omap3530_prcm_stub_block.h"
#include "omap3530_sdma.h"

namespace {

constexpr uint32_t kOffFifoBase  = 0x20u;
constexpr uint32_t kOffFifoEnd   = 0x40u;  /* 8 endpoints * 4 bytes */
constexpr uint32_t kOffCsrBase   = 0x100u;
constexpr uint32_t kOffCsrEnd    = 0x200u;
constexpr uint32_t kOffSysconfig = 0x404u;
constexpr uint32_t kOffSysstatus = 0x408u;

constexpr uint32_t kSysconfigSoftReset = 1u << 1;

class Omap3530Musb : public Omap3530PrcmStubBlock {
public:
    using Omap3530PrcmStubBlock::Omap3530PrcmStubBlock;
    uint32_t MmioBase() const override { return 0x480AB000u; }
    uint32_t MmioSize() const override { return 0x00000500u; }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        bool fire_tx_ep = false;
        uint32_t fired_ep = 0;

        if (off == kOffSysconfig) {
            value &= ~kSysconfigSoftReset;
        } else if (off >= kOffFifoBase && off < kOffFifoEnd) {
            fired_ep = (off - kOffFifoBase) / 4u;
            fire_tx_ep = true;
        }
        Omap3530PrcmStubBlock::WriteWord(addr, value);
        if (fire_tx_ep) FireTxFifo(fired_ep);
    }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (off == kOffSysstatus) return 0x1u;  /* RESETDONE */
        const uint32_t value = Omap3530PrcmStubBlock::ReadWord(addr);
        if (off >= kOffFifoBase && off < kOffFifoEnd) {
            FireRxFifo((off - kOffFifoBase) / 4u);
        }
        return value;
    }

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        /* Per-EP TxCSR (ep[N]+2) / RxCSR (ep[N]+6): return 0; stored
           value leaves H_SetupPkt etc. set, which musbhcd polls
           forever waiting for the matching USB device reply. */
        if (off >= kOffCsrBase && off < kOffCsrEnd) {
            const uint32_t low = off & 0xFu;
            if (low == 0x2u || low == 0x6u) return 0u;
        }
        return Omap3530PrcmStubBlock::ReadHalf(addr);
    }

    uint8_t ReadByte(uint32_t addr) override {
        const uint32_t off  = addr - MmioBase();
        uint8_t result;
        {
            std::lock_guard<std::mutex> lk(mu_);
            const uint32_t word = regs_[off / 4u];
            result = static_cast<uint8_t>(word >> ((off & 3u) * 8u));
        }
        if (off >= kOffFifoBase && off < kOffFifoEnd) {
            FireRxFifo((off - kOffFifoBase) / 4u);
        }
        return result;
    }

    void WriteByte(uint32_t addr, uint8_t value) override {
        const uint32_t off   = addr - MmioBase();
        const uint32_t shift = (off & 3u) * 8u;
        const uint32_t mask  = 0xFFu << shift;
        {
            std::lock_guard<std::mutex> lk(mu_);
            regs_[off / 4u] = (regs_[off / 4u] & ~mask) |
                              (static_cast<uint32_t>(value) << shift);
        }
        if (off >= kOffFifoBase && off < kOffFifoEnd) {
            FireTxFifo((off - kOffFifoBase) / 4u);
        }
    }

protected:
    const char* Label() const override { return "MUSB"; }
    const char* RegisterName(uint32_t) const override { return nullptr; }

private:
    static constexpr uint32_t kSyncTx[3] = {
        Omap3530Sdma::kSyncUsb0Tx0,
        Omap3530Sdma::kSyncUsb0Tx1,
        Omap3530Sdma::kSyncUsb0Tx2,
    };
    static constexpr uint32_t kSyncRx[3] = {
        Omap3530Sdma::kSyncUsb0Rx0,
        Omap3530Sdma::kSyncUsb0Rx1,
        Omap3530Sdma::kSyncUsb0Rx2,
    };

    void FireTxFifo(uint32_t ep) {
        /* Only EP1..EP3 have dedicated SDMA sync sources; EP0 control
           transfers use PIO. */
        if (ep < 1u || ep > 3u) return;
        emu_.Get<Omap3530Sdma>().RaiseSyncEvent(kSyncTx[ep - 1u]);
    }
    void FireRxFifo(uint32_t ep) {
        if (ep < 1u || ep > 3u) return;
        emu_.Get<Omap3530Sdma>().RaiseSyncEvent(kSyncRx[ep - 1u]);
    }
};

}  /* namespace */

REGISTER_SERVICE(Omap3530Musb);
