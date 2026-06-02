#include "omap3530_prcm_stub_block.h"

namespace {

class Omap3530UhhTllBase : public Omap3530PrcmStubBlock {
public:
    using Omap3530PrcmStubBlock::Omap3530PrcmStubBlock;

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off == 0x10u) {
            value &= ~0x2u;  /* SYSCONFIG.SOFTRESET self-clears. */
        }
        Omap3530PrcmStubBlock::WriteWord(addr, value);
    }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (off == 0x14u) return 0x1u;  /* SYSSTATUS.RESETDONE */
        return Omap3530PrcmStubBlock::ReadWord(addr);
    }

protected:
    const char* RegisterName(uint32_t) const override { return nullptr; }
};

class Omap3530Usbtll : public Omap3530UhhTllBase {
public:
    using Omap3530UhhTllBase::Omap3530UhhTllBase;
    uint32_t MmioBase() const override { return 0x48062000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }
protected:
    const char* Label() const override { return "USBTLL"; }
};

class Omap3530Uhh : public Omap3530UhhTllBase {
public:
    using Omap3530UhhTllBase::Omap3530UhhTllBase;
    uint32_t MmioBase() const override { return 0x48064000u; }
    uint32_t MmioSize() const override { return 0x00000400u; }
protected:
    const char* Label() const override { return "UHH"; }
};

class Omap3530Ohci : public Omap3530PrcmStubBlock {
public:
    using Omap3530PrcmStubBlock::Omap3530PrcmStubBlock;
    uint32_t MmioBase() const override { return 0x48064400u; }
    uint32_t MmioSize() const override { return 0x00000400u; }
protected:
    const char* Label() const override { return "OHCI"; }
    const char* RegisterName(uint32_t) const override { return nullptr; }
};

class Omap3530Ehci : public Omap3530PrcmStubBlock {
public:
    using Omap3530PrcmStubBlock::Omap3530PrcmStubBlock;
    uint32_t MmioBase() const override { return 0x48064800u; }
    uint32_t MmioSize() const override { return 0x00000400u; }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off == 0x10u) {
            value &= ~0x2u;  /* USBCMD.HCRESET self-clears — ehcihcd polls 1s then fails Init. */
        }
        Omap3530PrcmStubBlock::WriteWord(addr, value);
    }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        switch (off) {
        case 0x00u: return 0x01000010u;  /* HCIVERSION=0x0100 | CAPLENGTH=0x10; 0 collapses op regs onto cap regs. */
        case 0x04u: return 0x00000003u;  /* HCSPARAMS.N_PORTS=3 — OMAP3530 UHH P1/P2/P3. */
        case 0x08u: return 0x00000000u;  /* HCCPARAMS */
        }
        return Omap3530PrcmStubBlock::ReadWord(addr);
    }

protected:
    const char* Label() const override { return "EHCI"; }
    const char* RegisterName(uint32_t) const override { return nullptr; }
};

}  /* namespace */

REGISTER_SERVICE(Omap3530Usbtll);
REGISTER_SERVICE(Omap3530Uhh);
REGISTER_SERVICE(Omap3530Ohci);
REGISTER_SERVICE(Omap3530Ehci);
