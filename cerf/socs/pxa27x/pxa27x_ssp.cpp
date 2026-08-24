#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../irq_controller.h"

#include <cstdint>

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Section 8.1 (page 8-1): "All three
   SSP ports are mostly identical in operation, but differ as follows: External
   port connections, Memory-map base location". */
class Pxa27xSsp : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    /* Table 28-8 (page 28-36): "0x4190_003C SSACD_3", "0x4190_0040-
       0x419f_FFFC reserved". */
    uint32_t MmioSize() const override { return 0x40u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

protected:
    /* Table 25-2 (page 25-5) "Bit Positions for Primary Interrupt Sources". */
    virtual int IntcSource() const = 0;

private:
    /* Table 28-8 (pages 28-35, 28-36): "0x4190_0000 SSCR0_3" .. "0x4190_003C
       SSACD_3", "0x4190_0014-0x4190_0024 -- reserved". */
    static constexpr uint32_t kSscr0 = 0x00u;
    static constexpr uint32_t kSscr1 = 0x04u;
    static constexpr uint32_t kSssr  = 0x08u;
    static constexpr uint32_t kSsitr = 0x0Cu;
    static constexpr uint32_t kSsdr  = 0x10u;
    static constexpr uint32_t kSsto  = 0x28u;
    static constexpr uint32_t kSspsp = 0x2Cu;
    static constexpr uint32_t kSstsa = 0x30u;
    static constexpr uint32_t kSsrsa = 0x34u;
    static constexpr uint32_t kSstss = 0x38u;
    static constexpr uint32_t kSsacd = 0x3Cu;

    /* Table 8-6 (page 8-25) SSCR0_1/2/3, bit 31 down to bit 0: "MOD ACS FRDC
       TIM RIM NCS EDSS SCR SSE ECS FRF DSS", Reset "0 0 ? ? ? 0 0 ..." */
    static constexpr uint32_t kSscr0Mask = 0xC7FFFFFFu;
    static constexpr uint32_t kSscr0Sse  = 1u << 7;
    static constexpr uint32_t kSscr0Rim  = 1u << 22;
    static constexpr uint32_t kSscr0Tim  = 1u << 23;

    /* Table 8-7 (page 8-29) SSCR1_1/2/3, bit 31 down to bit 0: "TTELP TTE
       EBCEI SCFR ECRA ECRB SCLKDIR SFRMDIR RWOT TRAIL TSRE RSRE TINTE PINTE
       Reserved IFS STRF EFWR RFT TFT MWDS SPH SPO LBM TIE RIE", Reset bit 17
       "?". */
    static constexpr uint32_t kSscr1Mask  = 0xFFFDFFFFu;
    static constexpr uint32_t kSscr1Tie   = 1u << 1;
    static constexpr uint32_t kSscr1Rie   = 1u << 0;

    /* Table 8-11 (page 8-43) SSSR_1/2/3, bit 31 down to bit 0: "BCE CSS TUR EOC
       TINT PINT reserved RFL TFL ROR RFS TFS BSY RNE TNF reserved". */
    static constexpr uint32_t kSssrBce  = 1u << 23;
    static constexpr uint32_t kSssrTur  = 1u << 21;
    static constexpr uint32_t kSssrEoc  = 1u << 20;
    static constexpr uint32_t kSssrTint = 1u << 19;
    static constexpr uint32_t kSssrPint = 1u << 18;
    static constexpr uint32_t kSssrRor  = 1u << 7;
    static constexpr uint32_t kSssrRfs  = 1u << 6;
    static constexpr uint32_t kSssrTfs  = 1u << 5;
    static constexpr uint32_t kSssrTnf  = 1u << 2;

    /* Table 8-11 (pages 8-43 through 8-47): bits 23, 21, 20, 19, 18 and 7 have
       access "R/W" with " Write 0b1 to clear this bit."; bits 22, 15:12, 11:8,
       6, 5, 4, 3 and 2 have access "R". */
    static constexpr uint32_t kSssrSticky =
        kSssrBce | kSssrTur | kSssrEoc | kSssrTint | kSssrPint | kSssrRor;

    /* Table 8-11 (page 8-45): "RFL is the number of valid entries (minus 1)
       currently in the RX FIFO. NOTE: When the value of 0xF is read, the RX FIFO
       is either empty or full and programmers must refer to the RNE bit." */
    static constexpr uint32_t kSssrRflEmpty = 0xFu << 12;

    /* Table 8-10 (page 8-42) SSITR_1/2/3: "7 R/W TROR", "6 R/W TRFS", "5 R/W
       TTFS", "31:8 --", "4:0 --". */
    static constexpr uint32_t kSsitrMask = 0x000000E0u;

    /* Table 8-9 (page 8-41) SSTO_1/2/3: "31:24 --", "23:0 R/W TIMEOUT". */
    static constexpr uint32_t kSstoMask = 0x00FFFFFFu;

    /* Table 8-8 (page 8-39) SSPSP_1/2/3, bit 31 down to bit 0: "reserved FSRT
       DMYSTOP reserved SFRMWDTH SFRMDLY DMYSTRT STRTDLY ETDS SFRMP SCMODE",
       Reset "? ? ? ? ? ? 0 0 0 ? 0 ..." */
    static constexpr uint32_t kSspspMask = 0x03BFFFFFu;

    /* Table 8-13 (page 8-48) SSTSA_1/2/3 and Table 8-14 (page 8-49) SSRSA_1/2/3:
       "31:8 -- reserved", 7:0 "TTSA" / "RTSA". */
    static constexpr uint32_t kSstsaMask = 0x000000FFu;

    /* Table 8-16 (page 8-51) SSACD_1/2/3: "31:7 -- Reserved", 6:4 ACPS, 3 SCDB,
       2:0 ACDS. */
    static constexpr uint32_t kSsacdMask = 0x0000007Fu;

    bool     Enabled() const { return (sscr0_ & kSscr0Sse) != 0u; }
    uint32_t Status() const;
    void     UpdateIrq();

    uint32_t sscr0_ = 0u;
    uint32_t sscr1_ = 0u;
    uint32_t ssitr_ = 0u;
    uint32_t ssto_  = 0u;
    uint32_t sspsp_ = 0u;
    uint32_t sstsa_ = 0u;
    uint32_t ssrsa_ = 0u;
    uint32_t ssacd_ = 0u;
    uint32_t sticky_ = 0u;
    bool     irq_ = false;
};

/* Table 8-11 (page 8-47): "TNF ... 0 = TX FIFO is full 1 = TX FIFO is not full";
   (page 8-46) "TFS ... 1 = TX FIFO level is at or below its trigger threshold
   (TFT + 1)"; (page 8-45) "RFS ... 0 = RX FIFO level is less than its trigger
   threshold or the SSP port is disabled". */
uint32_t Pxa27xSsp::Status() const {
    uint32_t s = kSssrRflEmpty | kSssrTnf | (ssitr_ & kSsitrMask);
    if (!Enabled()) return s;
    return s | kSssrTfs | sticky_;
}

/* Table 8-15 (page 8-50) SSTSS_1/2/3: bit 31 "NMBSY" and bits 2:0 "TSS" both
   have access "R"; Table 8-12 (page 8-48) SSDR_1/2/3: "31:0 R/W DATA". */
uint32_t Pxa27xSsp::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
    case kSscr0: return sscr0_;
    case kSscr1: return sscr1_;
    case kSssr:  return Status();
    case kSsitr: return ssitr_;
    case kSsdr:  return 0u;
    case kSsto:  return ssto_;
    case kSspsp: return sspsp_;
    case kSstsa: return sstsa_;
    case kSsrsa: return ssrsa_;
    case kSstss: return 0u;
    case kSsacd: return ssacd_;
    default: break;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

/* Section 8.5.7 (page 8-47): "Both the TX and RX FIFOs are cleared when the SSP
   port is reset, or by clearing SSCR0_x[SSE]." */
void Pxa27xSsp::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
    case kSscr0:
        sscr0_ = value & kSscr0Mask;
        if (!Enabled()) sticky_ = 0u;
        UpdateIrq();
        return;
    case kSscr1: sscr1_ = value & kSscr1Mask;  UpdateIrq(); return;
    case kSsitr: ssitr_ = value & kSsitrMask;  UpdateIrq(); return;
    case kSssr:  sticky_ &= ~(value & kSssrSticky); UpdateIrq(); return;
    case kSsdr:  return;
    case kSsto:  ssto_  = value & kSstoMask;  return;
    case kSspsp: sspsp_ = value & kSspspMask; return;
    case kSstsa: sstsa_ = value & kSstsaMask; return;
    case kSsrsa: ssrsa_ = value & kSstsaMask; return;
    case kSstss: return;
    case kSsacd: ssacd_ = value & kSsacdMask; return;
    default: break;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

/* Table 8-6 (page 8-25) SSCR0[TIM] "0 = TUR events generate an SSP port
   interrupt", SSCR0[RIM] "0 = ROR events generate an SSP port interrupt";
   Table 8-11 (page 8-46) "When TFS is set, an interrupt is generated if
   SSCR1_x[TIE] is set", (page 8-45) the same for RFS and SSCR1_x[RIE]. */
void Pxa27xSsp::UpdateIrq() {
    const uint32_t s = Status();
    bool active = false;
    if (Enabled()) {
        if ((s & kSssrTfs) && (sscr1_ & kSscr1Tie)) active = true;
        if ((s & kSssrRfs) && (sscr1_ & kSscr1Rie)) active = true;
        if ((s & kSssrRor) && !(sscr0_ & kSscr0Rim)) active = true;
        if ((s & kSssrTur) && !(sscr0_ & kSscr0Tim)) active = true;
    }
    if (active == irq_) return;
    irq_ = active;
    if (active) emu_.Get<IrqController>().AssertIrq(IntcSource());
    else        emu_.Get<IrqController>().DeAssertIrq(IntcSource());
}

void Pxa27xSsp::SaveState(StateWriter& w) {
    w.Write(sscr0_);
    w.Write(sscr1_);
    w.Write(ssitr_);
    w.Write(ssto_);
    w.Write(sspsp_);
    w.Write(sstsa_);
    w.Write(ssrsa_);
    w.Write(ssacd_);
    w.Write(sticky_);
    w.Write(irq_);
}

void Pxa27xSsp::RestoreState(StateReader& r) {
    r.Read(sscr0_);
    r.Read(sscr1_);
    r.Read(ssitr_);
    r.Read(ssto_);
    r.Read(sspsp_);
    r.Read(sstsa_);
    r.Read(ssrsa_);
    r.Read(ssacd_);
    r.Read(sticky_);
    r.Read(irq_);
}

/* Table 8-11 (page 8-46) SSSR_1/2/3: "Physical Address 0x4100_0008 0x4170_0008
   0x4190_0008"; Table 25-3 ICPR: "SSP 1: 24" (page 25-7), "SSP2: 16" (page
   25-8), "SSP 3: 0" (page 25-9). */
class Pxa27xSsp1 final : public Pxa27xSsp {
public:
    using Pxa27xSsp::Pxa27xSsp;
    uint32_t MmioBase() const override { return 0x41000000u; }

protected:
    int IntcSource() const override { return 24; }
};

class Pxa27xSsp2 final : public Pxa27xSsp {
public:
    using Pxa27xSsp::Pxa27xSsp;
    uint32_t MmioBase() const override { return 0x41700000u; }

protected:
    int IntcSource() const override { return 16; }
};

class Pxa27xSsp3 final : public Pxa27xSsp {
public:
    using Pxa27xSsp::Pxa27xSsp;
    uint32_t MmioBase() const override { return 0x41900000u; }

protected:
    int IntcSource() const override { return 0; }
};

REGISTER_SERVICE(Pxa27xSsp1);
REGISTER_SERVICE(Pxa27xSsp2);
REGISTER_SERVICE(Pxa27xSsp3);

}  /* namespace */
