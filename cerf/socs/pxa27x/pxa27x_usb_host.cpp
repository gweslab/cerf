#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

/* PXA27x Developer's Manual 280000-001 Table 20-29 (page 20-47): UHC registers
   0x4C00_0000 UHCREV .. 0x4C00_006C UHCHIT. Table 20-3 (page 20-10): OHCI 1.0a. */

namespace {

constexpr uint32_t kBase     = 0x4C000000u;
constexpr uint32_t kRegCount = 28u;
constexpr uint32_t kSize     = kRegCount * 4u;

/* Table 20-29 (page 20-47). */
constexpr uint32_t kUHCREV   = 0x00u, kUHCHCON  = 0x04u, kUHCCOMS = 0x08u;
constexpr uint32_t kUHCINTS  = 0x0Cu, kUHCINTE  = 0x10u, kUHCINTD = 0x14u;
constexpr uint32_t kUHCHCCA  = 0x18u, kUHCPCED  = 0x1Cu, kUHCCHED = 0x20u;
constexpr uint32_t kUHCCCED  = 0x24u, kUHCBHED  = 0x28u, kUHCBCED = 0x2Cu;
constexpr uint32_t kUHCDHEAD = 0x30u, kUHCFMI   = 0x34u, kUHCFMR  = 0x38u;
constexpr uint32_t kUHCFMN   = 0x3Cu, kUHCPERS  = 0x40u, kUHCLST  = 0x44u;
constexpr uint32_t kUHCRHDA  = 0x48u, kUHCRHDB  = 0x4Cu, kUHCRHS  = 0x50u;
constexpr uint32_t kUHCRHPS1 = 0x54u, kUHCRHPS2 = 0x58u, kUHCRHPS3 = 0x5Cu;
constexpr uint32_t kUHCSTAT  = 0x60u, kUHCHR    = 0x64u, kUHCHIE  = 0x68u;
constexpr uint32_t kUHCHIT   = 0x6Cu;

/* Table 20-21 (page 20-31) UHCRHDA[NDP] 7:0 R: "supports three (3) downstream
   ports, this field always contains a value of 0x2". */
constexpr uint32_t kPorts   = 3u;
constexpr uint32_t kRhdaNdp = 0x2u;

/* Table 20-3 (page 20-10) UHCREV: "this register reads 0x0000_0010". */
constexpr uint32_t kRevision1_0a = 0x00000010u;

/* Table 20-4 (page 20-11) UHCHCON: R/W 10:0; 31:11 reserved. */
constexpr uint32_t kHconRw = 0x000007FFu;

/* Table 20-7 (page 20-18) UHCINTE / Table 20-8 (page 20-20) UHCINTD:
   31 MIE R/W, 30 and 6:0 "Read/Write 1 to set"; reset 0. */
constexpr uint32_t kIntEnableRw = 0xC000007Fu;

/* Table 20-9 (page 20-21) UHCHCCA: 31:8 R/W, 7:0 R "Fixed at 0". */
constexpr uint32_t kHccaRw = 0xFFFFFF00u;

/* Tables 20-11..20-14 (pages 20-22..20-24) UHCCHED/UHCCCED/UHCBHED/UHCBCED:
   31:4 R/W, 3:0 R "Fixed at 0". */
constexpr uint32_t kEdPointerRw = 0xFFFFFFF0u;

/* Table 20-16 (page 20-26) UHCFMI: 31 FIT, 30:16 FSMPS, 13:0 FI all R/W;
   reset FI = 11,999. */
constexpr uint32_t kFmiRw    = 0xFFFF3FFFu;
constexpr uint32_t kFmiReset = 0x00002EDFu;

/* Table 20-19 (page 20-29) UHCPERS: 13:0 PS R/W; reset 0. */
constexpr uint32_t kPersRw = 0x00003FFFu;

/* Table 20-20 (page 20-30) UHCLST: 11:0 LST R/W; reset 0x628. */
constexpr uint32_t kLstRw    = 0x00000FFFu;
constexpr uint32_t kLstReset = 0x00000628u;

/* Table 20-21 (pages 20-31, 20-32) UHCRHDA: 31:24 POTPGT, 12 NOCP, 11 OCPM,
   9 NPS, 8 PSM R/W; 10 DT "always reads 0"; 7:0 NDP R. Reset 0x0400_0902. */
constexpr uint32_t kRhdaRw    = 0xFF001B00u;
constexpr uint32_t kRhdaPsm   = 1u << 8;
constexpr uint32_t kRhdaReset = 0x04000902u;

/* Table 20-22 (page 20-33) UHCRHDB: PPCM 19:17 (port 1..3), DR 3:1 (port 1..3)
   R/W, all other bits "always reads as 0"; reset 0. */
constexpr uint32_t kRhdbRw       = 0x000E000Eu;
constexpr uint32_t kRhdbPpcmPort = 17u;

/* Table 20-23 (pages 20-34, 20-35) UHCRHS: 31 CRWE, 16 LPSC, 0 LPS all
   "always read as 0"; 15 DRWE "Read/Write 1 to set"; reset 0. */
constexpr uint32_t kRhsLps  = 1u << 0;
constexpr uint32_t kRhsDrwe = 1u << 15;
constexpr uint32_t kRhsLpsc = 1u << 16;
constexpr uint32_t kRhsCrwe = 1u << 31;

/* Table 20-24 (pages 20-36..20-39) UHCRHPS1/2/3: 0 CCS, 1 PES, 2 PSS, 4 PRS,
   8 PPS, 16 CSC R/W; 9 LSDA R/WC. Reset 20:16, 9:8 and 4:0 = 0. */
constexpr uint32_t kPortPes  = 1u << 1;
constexpr uint32_t kPortPss  = 1u << 2;
constexpr uint32_t kPortPrs  = 1u << 4;
constexpr uint32_t kPortPps  = 1u << 8;
constexpr uint32_t kPortLsda = 1u << 9;
constexpr uint32_t kPortCsc  = 1u << 16;

/* Table 20-26 (pages 20-42, 20-43) UHCHR: R/W 11:9 and 7:0, bit 8 reserved;
   reset 0b0110_0010_0110; 0 FSBIR "always reads as 0b0". */
constexpr uint32_t kHrRw    = 0x00000EFFu;
constexpr uint32_t kHrFsbir = 1u << 0;
constexpr uint32_t kHrReset = 0x00000626u;

/* Table 20-27 (page 20-44) UHCHIE: R/W 14:10, 8, 7; reset 0. */
constexpr uint32_t kHieRw = 0x00007D80u;

/* Table 20-28 (page 20-46) UHCHIT: R/W 16:7; reset 0. */
constexpr uint32_t kHitRw = 0x0001FF80u;

class Pxa27xUsbHost : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }

    void OnReady() override {
        ResetRegs();
        emu_.Get<PeripheralDispatcher>().Register(this);
        LOG(Boot, "Pxa27xUsbHost: OpenHCI 1.0a at PA 0x%08X (NDP=%u, no devices)\n",
            kBase, kPorts);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        if (off & 3u) HaltUnsupportedAccess("ReadWord(unaligned)", addr, 0);
        return ReadReg(off);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;
        if (off & 3u) HaltUnsupportedAccess("WriteWord(unaligned)", addr, value);
        WriteReg(off, value);
    }

    void SaveState(StateWriter& w) override {
        for (uint32_t i = 0; i < kRegCount; ++i) w.Write(regs_[i]);
    }
    void RestoreState(StateReader& r) override {
        for (uint32_t i = 0; i < kRegCount; ++i) r.Read(regs_[i]);
    }

private:
    uint32_t& Reg(uint32_t off) { return regs_[off / 4u]; }

    uint32_t ReadReg(uint32_t off) {
        switch (off) {
        case kUHCREV:   return kRevision1_0a;
        case kUHCHCON:  return Reg(off);

        /* Table 20-5 (page 20-14) UHCCOMS: 17:16 SOC R; 3 OCR "When read, this
           bit always returns 0"; 0 HCR "cleared by the UHC ... within 10 us". */
        case kUHCCOMS:  return 0u;

        /* Table 20-6 (page 20-16) UHCINTS: 30 OC "tied to 0 because the SMI pin
           is not implemented"; 6:0 R/WC "The host controller driver cannot set
           any of these bits". */
        case kUHCINTS:  return 0u;

        case kUHCINTE:
        case kUHCINTD:  return Reg(kUHCINTE);
        case kUHCHCCA:  return Reg(off);

        /* Table 20-10 (page 20-21) UHCPCED: 31:4 PCED R, 3:0 "Fixed at 0". */
        case kUHCPCED:  return 0u;

        case kUHCCHED:
        case kUHCCCED:
        case kUHCBHED:
        case kUHCBCED:  return Reg(off);

        /* Table 20-15 (page 20-25) UHCDHEAD: 31:4 DHED R, 3:0 "Fixed at 0". */
        case kUHCDHEAD: return 0u;

        case kUHCFMI:   return Reg(off);

        /* Table 20-17 (page 20-27) UHCFMR: 31 FRT, 13:0 FR read-only. */
        case kUHCFMR:   return 0u;

        /* Table 20-18 (page 20-28) UHCFMN: 15:0 FN read-only. */
        case kUHCFMN:   return 0u;

        case kUHCPERS:
        case kUHCLST:
        case kUHCRHDA:
        case kUHCRHDB:  return Reg(off);
        case kUHCRHS:   return Reg(off) & kRhsDrwe;

        case kUHCRHPS1:
        case kUHCRHPS2:
        case kUHCRHPS3: return Reg(off) & (kPortPps | kPortCsc);

        /* Table 20-25 (page 20-39) UHCSTAT: bits are set only "if the interrupt
           enable bit (in UHCHIE register) for that event is set". */
        case kUHCSTAT:  return 0u;

        case kUHCHR:    return Reg(off) & ~kHrFsbir;
        case kUHCHIE:
        case kUHCHIT:   return Reg(off);
        default:        HaltUnsupportedAccess("ReadWord", kBase + off, 0);
        }
    }

    void WriteReg(uint32_t off, uint32_t value) {
        switch (off) {
        case kUHCHCON:  Reg(off) = value & kHconRw; return;

        /* Table 20-5 (page 20-14) UHCCOMS: "write-to-set register"; HCR self-
           clears within 10 us, CLF/BLF/OCR read back 0. */
        case kUHCCOMS:  return;

        /* Table 20-6 (page 20-16) UHCINTS: "To clear this bit, write 0b1 to
           it." */
        case kUHCINTS:  return;

        /* Table 20-7 (page 20-18) UHCINTE: "Writing a 1 ... sets the
           corresponding bit"; Table 20-8 (page 20-20) UHCINTD: "writing a 1 ...
           clears the corresponding bit in the UHC Interrupt Enable register". */
        case kUHCINTE:  Reg(kUHCINTE) |=  (value & kIntEnableRw); return;
        case kUHCINTD:  Reg(kUHCINTE) &= ~(value & kIntEnableRw); return;

        case kUHCHCCA:  Reg(off) = value & kHccaRw;      return;
        case kUHCCHED:
        case kUHCCCED:
        case kUHCBHED:
        case kUHCBCED:  Reg(off) = value & kEdPointerRw; return;
        case kUHCFMI:   Reg(off) = value & kFmiRw;       return;
        case kUHCPERS:  Reg(off) = value & kPersRw;      return;
        case kUHCLST:   Reg(off) = value & kLstRw;       return;
        case kUHCRHDA:  Reg(off) = (value & kRhdaRw) | kRhdaNdp; return;
        case kUHCRHDB:  Reg(off) = value & kRhdbRw;      return;
        case kUHCRHS:   WriteRootHubStatus(value);       return;

        case kUHCRHPS1: WritePort(kUHCRHPS1, value); return;
        case kUHCRHPS2: WritePort(kUHCRHPS2, value); return;
        case kUHCRHPS3: WritePort(kUHCRHPS3, value); return;

        /* Table 20-25 (page 20-39) UHCSTAT: "bits are cleared only by writing a
           1 to the bit." */
        case kUHCSTAT:  return;

        case kUHCHR:    Reg(off) = value & kHrRw;  return;
        case kUHCHIE:   Reg(off) = value & kHieRw; return;
        case kUHCHIT:   Reg(off) = value & kHitRw; return;

        /* Tables 20-3, 20-10, 20-15, 20-17, 20-18: UHCREV, UHCPCED, UHCDHEAD,
           UHCFMR and UHCFMN are read-only. */
        case kUHCREV:
        case kUHCPCED:
        case kUHCDHEAD:
        case kUHCFMR:
        case kUHCFMN:   return;
        default:        HaltUnsupportedAccess("WriteWord", kBase + off, value);
        }
    }

    /* Table 20-24 (page 20-37) PPS: "HCD clears this bit by writing Clear Port
       Power (writing a 1 to UHCRHPS1/2/3[LSDA])"; (pages 20-38, 20-39) a
       set-port-reset, set-port-enable or set-port-suspend write while
       CurrentConnectStatus is cleared "sets connect-status-change" instead. */
    void WritePort(uint32_t off, uint32_t value) {
        uint32_t& r = Reg(off);
        if (value & kPortCsc)  r &= ~kPortCsc;
        if (value & kPortLsda) r &= ~kPortPps;
        if (value & kPortPps)  r |=  kPortPps;
        if (value & (kPortPrs | kPortPss | kPortPes)) r |= kPortCsc;
    }

    /* Table 20-23 (page 20-34) LPSC: in global power mode "turn on power to all
       ports", in per-port mode only "on ports whose port power control mask bit
       (UHCRHDB[PPCM]) is not set"; (page 20-35) LPS clears the same selection. */
    void SetGlobalPower(bool on) {
        const bool per_port = (Reg(kUHCRHDA) & kRhdaPsm) != 0u;
        for (uint32_t i = 0; i < kPorts; ++i) {
            if (per_port && (Reg(kUHCRHDB) & (1u << (kRhdbPpcmPort + i)))) continue;
            uint32_t& r = regs_[(kUHCRHPS1 / 4u) + i];
            if (on) r |= kPortPps; else r &= ~kPortPps;
        }
    }

    /* Table 20-23 (page 20-34) CRWE: "Writing a 1 clears the device remote
       wake-up enable (UHCRHS[DRWE]) bit"; DRWE: "Writing a 1 sets" it. */
    void WriteRootHubStatus(uint32_t value) {
        uint32_t& r = Reg(kUHCRHS);
        if (value & kRhsCrwe) r &= ~kRhsDrwe;
        if (value & kRhsDrwe) r |=  kRhsDrwe;
        if (value & kRhsLpsc) SetGlobalPower(true);
        if (value & kRhsLps)  SetGlobalPower(false);
    }

    void ResetRegs() {
        for (uint32_t i = 0; i < kRegCount; ++i) regs_[i] = 0u;
        Reg(kUHCFMI)  = kFmiReset;
        Reg(kUHCLST)  = kLstReset;
        Reg(kUHCRHDA) = kRhdaReset;
        Reg(kUHCHR)   = kHrReset;
    }

    uint32_t regs_[kRegCount] = {};
};

}  /* namespace */

REGISTER_SERVICE(Pxa27xUsbHost);
