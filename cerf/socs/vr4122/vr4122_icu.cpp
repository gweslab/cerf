#include "../vr41xx/vr41xx_icu_impl.h"

#include <cstdint>
#include "vr4122_id.h"

namespace {

using cerf_vr41xx_icu_detail::Vr41xxIcuBase;
using cerf_vr41xx_icu_detail::Vr41xxIcuModel;

/* VR4122 ICU (VR4131 UM U15350EJ2V0UM Table 11-1): SYSINT1REG..SOFTINTREG at
   0x0F000080-0x0F00009A, SYSINT2REG..MBCUINTREG at 0x0F0000A0-0x0F0000BA; the PMU
   block follows at 0x0F0000C0. */
constexpr Vr41xxIcuModel kModel = {
    /*base1=*/0x0F000080u,
    /*size1=*/0x20u,
    /*base2=*/0x0F0000A0u,
    /*size2=*/0x20u,
    /* SYSINT1REG direct bits (VR4131 UM 11.2.4 MSYSINT1REG, p.194): D12 CLKRUN,
       D9 SIU, D3 ETIMER, D2 RTCL1, D1 POWER, D0 BAT. D8 GIU / D11 SOFT are computed
       from their Level-2 registers; D10/D13 are RFU (no WRBERR/DOZEPIU on the VR4122). */
    /*s1_direct=*/0x120Fu,
    /* SYSINT2REG direct bits (VR4131 UM 11.2.12 MSYSINT2REG, p.202): D3 TCLK, D1 LED,
       D0 RTCL2. D4 FIR / D5 DSIU are computed from their Level-2 registers. */
    /*s2_direct=*/0x000Bu,
    /* DSIUINTREG D11 INTDSIU, D10:0 RFU read 0 (VR4131 UM 11.2.3, p.193). */
    /*dsiu_fixed_read=*/0x0000u,
    /* MSYSINT1REG D[15..13], D10 and D[7..4] RFU (VR4131 UM 11.2.4 p194). */
    /*msysint1_writable=*/0x1B0Fu,
    /* VR4131 UM Table 11-1 p190: SYSINT1REG 0x80 is followed by GIUINTLREG 0x88, and the
       mask block runs MSYSINT1REG 0x8C -> MGIUINTLREG 0x94 with no MPIU/MAIU/MKIU. */
    /*mpiu_writable=*/0x0000u,
    /*maiu_writable=*/0x0000u,
    /*mkiu_writable=*/0x0000u,
    /* MGIUINTLREG D14 RFU, INTS15 and INT[13..0] R/W (VR4131 UM 11.2.5 p195). */
    /*mgiul_writable=*/0xBFFFu,
    /* MDSIUINTREG D11 INTDSIU R/W, D[15..12] and D[10..0] RFU (VR4131 UM 11.2.6 p196). */
    /*mdsiu_writable=*/0x0800u,
    /* MSYSINT2REG D[15..10] and D2 RFU (VR4131 UM 11.2.12 p202). */
    /*msysint2_writable=*/0x03FBu,
    /* MGIUINTHREG INTS[31..16] all R/W (VR4131 UM 11.2.13 p203). */
    /*mgiuh_writable=*/0xFFFFu,
    /* MFIRINTREG D[15..5] RFU (VR4131 UM 11.2.14 p204). */
    /*mfir_writable=*/0x001Fu,
};

/* Level-2 offsets from SYSINT2REG 0xA0 (VR4131 UM Table 11-1, p190):
   PCIINTREG 0xAC / SCUINTREG 0xAE / CSIINTREG 0xB0 / BCUINTREG 0xB8 are R
   (PCIINT0 / SCUINT0 D0, CSI D6:0, BCUINTR D0; reset 0, 11.2.15-11.2.17 p205-207,
   11.2.21 p211); MPCIINTREG 0xB2 / MSCUINTREG 0xB4 / MBCUINTREG 0xBA are R/W D0,
   MCSIINTREG 0xB6 R/W D6:0 (reset 0, 11.2.18-11.2.20 p208-210, 11.2.22 p212). */
constexpr uint32_t kOffPciint  = 0x0Cu;
constexpr uint32_t kOffScuint  = 0x0Eu;
constexpr uint32_t kOffCsiint  = 0x10u;
constexpr uint32_t kOffMpci    = 0x12u;
constexpr uint32_t kOffMscu    = 0x14u;
constexpr uint32_t kOffMcsi    = 0x16u;
constexpr uint32_t kOffBcuint  = 0x18u;
constexpr uint32_t kOffMbcu    = 0x1Au;
constexpr uint16_t kMpciWritable = 0x0001u;
constexpr uint16_t kMscuWritable = 0x0001u;
constexpr uint16_t kMcsiWritable = 0x007Fu;
constexpr uint16_t kMbcuWritable = 0x0001u;

/* Table 11-1: the VR4122 has no PIU/AIU/KIU - indication regs 0x82/0x84/0x86 and mask
   regs 0x8E/0x90/0x92 are absent (map goes SYSINT1REG 0x80 -> GIUINTL 0x88; NetBSD
   icureg.h VR4122_{AIU,KIU}INT_REG_W = ICU_NO_REG_W). */
class Vr4122Icu : public Vr41xxIcuBase<SocId::Vr4122, kModel> {
public:
    using Vr41xxIcuBase::Vr41xxIcuBase;

    uint16_t ReadHalf(uint32_t addr) override {
        if (IsAbsent(addr - MmioBase())) HaltUnsupportedAccess("VR4122 ICU absent register", addr, 0);
        return Vr41xxIcuBase::ReadHalf(addr);
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        if (IsAbsent(addr - MmioBase())) HaltUnsupportedAccess("VR4122 ICU absent register", addr, value);
        Vr41xxIcuBase::WriteHalf(addr, value);
    }

protected:
    /* No PCI/SCU/CSI unit is registered with PeripheralDispatcher and the BCU
       interrupt source (DCU TCINT, VR4131 UM 9.3.13 p183) is FATAL-guarded, so the
       indication registers hold their reset column 0 (11.2.15-11.2.17, 11.2.21). */
    uint16_t ReadHalf2Ext(uint32_t off) override {
        switch (off) {
            case kOffPciint: case kOffScuint: case kOffCsiint: case kOffBcuint: return 0;
            case kOffMpci: return mpci_;
            case kOffMscu: return mscu_;
            case kOffMcsi: return mcsi_;
            case kOffMbcu: return mbcu_;
            default: return Vr41xxIcuBase::ReadHalf2Ext(off);
        }
    }
    void WriteHalf2Ext(uint32_t off, uint16_t value) override {
        switch (off) {
            /* "R" rows (11.2.15-11.2.17, 11.2.21): the write is inert. */
            case kOffPciint: case kOffScuint: case kOffCsiint: case kOffBcuint: return;
            case kOffMpci: mpci_ = static_cast<uint16_t>(value & kMpciWritable); return;
            case kOffMscu: mscu_ = static_cast<uint16_t>(value & kMscuWritable); return;
            case kOffMcsi: mcsi_ = static_cast<uint16_t>(value & kMcsiWritable); return;
            case kOffMbcu: mbcu_ = static_cast<uint16_t>(value & kMbcuWritable); return;
            default: Vr41xxIcuBase::WriteHalf2Ext(off, value); return;
        }
    }
    void ApplyResetExtLocked() override { mpci_ = mscu_ = mcsi_ = mbcu_ = 0; }
    void SaveStateExtLocked(StateWriter& w) override {
        w.Write("mpci", mpci_); w.Write("mscu", mscu_); w.Write("mcsi", mcsi_); w.Write("mbcu", mbcu_);
    }
    void RestoreStateExtLocked(StateReader& r) override {
        r.Read("mpci", mpci_); r.Read("mscu", mscu_); r.Read("mcsi", mcsi_); r.Read("mbcu", mbcu_);
    }

private:
    static bool IsAbsent(uint32_t off) {
        return off == 0x02u || off == 0x04u || off == 0x06u ||
               off == 0x0Eu || off == 0x10u || off == 0x12u;
    }

    uint16_t mpci_ = 0, mscu_ = 0, mcsi_ = 0, mbcu_ = 0;
};

}  /* namespace */

REGISTER_SERVICE_AS(Vr4122Icu, Vr41xxIcu);
