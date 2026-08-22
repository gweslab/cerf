#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../irq_controller.h"

#include <cstdint>

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Table 15-28 (page 15-44) "MMC
   Controller Register Summary": "0x4110_0000 MMC_STRPCL" .. "0x4110_004C
   MMC_BLKS_REM". */
class Pxa27xMmc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x41100000u; }
    uint32_t MmioSize() const override { return 0x00000050u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override { UpdateIrq(); }

private:
    /* Table 15-8 (page 15-29): "13 R END_CMD_RES", "12 R PRG_DONE", "11 R
       DATA_TRAN_DONE", "8 R CLK_EN", "5 R RES_CRC_ERR", "1 R TIME_OUT_RES". */
    static constexpr uint32_t kStatClkEn        = 0x00000100u;
    static constexpr uint32_t kStatEndCmdRes    = 0x00002000u;
    static constexpr uint32_t kStatPrgDone      = 0x00001000u;
    static constexpr uint32_t kStatDataTranDone = 0x00000800u;
    static constexpr uint32_t kStatResCrcErr    = 0x00000020u;
    static constexpr uint32_t kStatTimeOutRes   = 0x00000002u;

    /* Table 15-19 (pages 15-37..15-39): "31:13 reserved", "9 R RES_ERR", "4 R
       CLK_IS_OFF", "2 R END_CMD_RES", "1 R PRG_DONE", "0 R DATA_TRAN_DONE". */
    static constexpr uint32_t kIRegEndCmdRes    = 0x00000004u;
    static constexpr uint32_t kIRegPrgDone      = 0x00000002u;
    static constexpr uint32_t kIRegDataTranDone = 0x00000001u;
    static constexpr uint32_t kIRegClkIsOff     = 0x00000010u;
    static constexpr uint32_t kIRegResErr       = 0x00000200u;
    static constexpr uint32_t kIRegMask         = 0x00001FFFu;

    /* Table 15-7 (page 15-28): "1 R/W STRT_CLK", "0 R/W STOP_CLK". */
    static constexpr uint32_t kStrpclStrtClk = 0x00000002u;
    static constexpr uint32_t kStrpclStopClk = 0x00000001u;

    /* Table 15-11 (page 15-32): "31:14 reserved", "9 reserved", "10 R/W
       STOP_TRAN". */
    static constexpr uint32_t kCmdatRw       = 0x00003DFFu;
    static constexpr uint32_t kCmdatStopTran = 0x00000400u;

    static constexpr uint32_t kClkrtRw   = 0x00000007u; /* Table 15-9  (page 15-30): "2:0 R/W CLK_RATE". */
    static constexpr uint32_t kSpiRw     = 0x0000000Fu; /* Table 15-10 (page 15-31): "31:4 reserved". */
    static constexpr uint32_t kRestoRw   = 0x0000007Fu; /* Table 15-13 (page 15-33): "6:0 R/W RES_TO". */
    static constexpr uint32_t kRdtoRw    = 0x0000FFFFu; /* Table 15-14 (page 15-33): "15:0 R/W READ_TO". */
    static constexpr uint32_t kBlklenRw  = 0x00000FFFu; /* Table 15-15 (page 15-34): "11:0 R/W BLK_LEN". */
    static constexpr uint32_t kNumblkRw  = 0x0000FFFFu; /* Table 15-16 (page 15-34): "15:0 R/W NUM_BLK". */
    static constexpr uint32_t kCmdRw     = 0x0000003Fu; /* Table 15-20 (page 15-40): "5:0 R/W CMD_INDX". */
    static constexpr uint32_t kArgRw     = 0x0000FFFFu; /* Tables 15-21, 15-22 (pages 15-40, 15-41): "15:0 R/W". */
    static constexpr uint32_t kRdwaitEn  = 0x00000001u; /* Table 15-26 (page 15-43): "0 R/W RD_WAIT_EN". */
    static constexpr uint32_t kBlksRemRw = 0x0000FFFFu; /* Table 15-27 (page 15-43): "15:0 R/W BLKS_REM". */

    /* Table 15-20 (page 15-40): "6 R reserved, read-only, always 1.
       Transmission bit in command sequence and cannot be changed." */
    static constexpr uint32_t kCmdTransmissionBit = 0x00000040u;

    /* Section 15.9.5 (page 15-31): "Writing the MMC_CMDAT register clears the
       MMC_STAT register and clears the FIFOs unless the STOP_TRAN bit is being
       written to a 1 or the command is SDIO CMD52." */
    static constexpr uint32_t kCmdIndexSdio52 = 52u;

    /* Table 25-3 (page 25-7) "ICPR Bit Definitions": "23 R MMC". */
    static constexpr int kIntcMmc = 23;

    uint32_t Stat() const;
    uint32_t IReg() const;
    void     ArmCommandSequence(uint32_t cmdat);
    void     RunCommandSequence();
    void     UpdateIrq();

    /* Section 15.9.2 (page 15-28): "The register is cleared at the beginning of
       every command sequence." */
    uint32_t stat_events_ = 0u;
    bool     clk_on_      = false;
    /* sdhc_pxa27x_b2.dll FUN_022736a4 reaches MMC_CMDAT at 0x0227396C while
       MMCLK is stopped, MMC_STRPCL at 0x022739C0, MMC_STAT at 0x022739D0. The
       CMDAT pointer at 0x01DD9350 is set in FUN_02273b54 and dereferenced
       nowhere else in the module. */
    bool     cmd_armed_   = false;
    /* Table 15-19 (page 15-38): "1 = MMCLK has been turned off, due to stop bit
       in STRP_CLK register. Cleared by the MMC_STAT[CLK_EN] bit when the clock
       is started." */
    bool     clk_is_off_  = false;

    uint32_t clkrt_    = 0u;         /* Table 15-9  (page 15-30): Reset 2:0 = 0. */
    uint32_t spi_      = 0u;         /* Table 15-10 (page 15-31): Reset 3:0 = 0. */
    uint32_t cmdat_    = 0x00000080u;/* Table 15-11 (page 15-32): Reset 13:0, 1 at "7 R/W DMA_EN". */
    uint32_t resto_    = 0x00000040u;/* Section 15.9.6 (page 15-33): "The default value of this register is 64." */
    uint32_t rdto_     = 0x0000FFFFu;/* Table 15-14 (page 15-33): Reset 15:0 all 1. */
    uint32_t blklen_   = 0u;         /* Table 15-15 (page 15-34): Reset 11:0 = 0. */
    uint32_t numblk_   = 0u;         /* Table 15-16 (page 15-34): Reset 15:0 = 0. */
    uint32_t i_mask_   = 0x00001FFFu;/* Table 15-18 (page 15-35): Reset 12:0 all 1. */
    uint32_t cmd_      = 0u;         /* Table 15-20 (page 15-40): Reset 5:0 = 0. */
    uint32_t argh_     = 0u;         /* Table 15-21 (page 15-40): Reset 15:0 = 0. */
    uint32_t argl_     = 0u;         /* Table 15-22 (page 15-41): Reset 15:0 = 0. */
    uint32_t rdwait_   = 0u;         /* Table 15-26 (page 15-43): Reset 1:0 = 0. */
    uint32_t blks_rem_ = 0u;         /* Table 15-27 (page 15-43): Reset 15:0 = 0. */
};

/* Table 15-28 (page 15-44). */
enum : uint32_t {
    kOffStrpcl  = 0x00, kOffStat   = 0x04, kOffClkrt  = 0x08, kOffSpi     = 0x0C,
    kOffCmdat   = 0x10, kOffResto  = 0x14, kOffRdto   = 0x18, kOffBlklen  = 0x1C,
    kOffNumblk  = 0x20, kOffPrtbuf = 0x24, kOffIMask  = 0x28, kOffIReg    = 0x2C,
    kOffCmd     = 0x30, kOffArgh   = 0x34, kOffArgl   = 0x38, kOffRes     = 0x3C,
    kOffRxfifo  = 0x40, kOffTxfifo = 0x44, kOffRdwait = 0x48, kOffBlksRem = 0x4C,
    kOffEnd     = 0x50,
};

uint32_t Pxa27xMmc::Stat() const {
    return stat_events_ | (clk_on_ ? kStatClkEn : 0u);
}

/* Table 15-19 (page 15-39): "Cleared by the MMC_STAT[END_CMD_RES] bit",
   "Cleared by the MMC_STAT[PRG_DONE] bit", "Cleared by the
   MMC_STAT[DATA_TRAN_DONE] bit". Section 15.9.12 (page 15-37): "If RES_ERR or
   DAT_ERR occurs, the type of error is in the MMC_STAT register." */
uint32_t Pxa27xMmc::IReg() const {
    uint32_t v = 0u;
    if (stat_events_ & kStatEndCmdRes)                     v |= kIRegEndCmdRes;
    if (stat_events_ & kStatPrgDone)                       v |= kIRegPrgDone;
    if (stat_events_ & kStatDataTranDone)                  v |= kIRegDataTranDone;
    if (stat_events_ & (kStatResCrcErr | kStatTimeOutRes)) v |= kIRegResErr;
    if (clk_is_off_)                                       v |= kIRegClkIsOff;
    return v;
}

/* Section 15.9.5 (page 15-31): "Writing to this register starts the command
   sequence on the MMC/SD/SDIO bus when MMCLK is turned on." */
void Pxa27xMmc::ArmCommandSequence(uint32_t cmdat) {
    if (cmdat & kCmdatStopTran)
        return;
    if (cmd_ != kCmdIndexSdio52)
        stat_events_ = 0u;
    cmd_armed_ = true;
    if (clk_on_)
        RunCommandSequence();
}

/* Table 15-19 (page 15-39): "1 = MMC has received the response or a response
   time-out has occurred." Table 15-8 (page 15-29): "1 R TIME_OUT_RES".
   sdhc_pxa27x_b2.dll FUN_02272538 turns MMC_STAT bit 1 into a response-timeout
   error return. */
void Pxa27xMmc::RunCommandSequence() {
    cmd_armed_ = false;
    stat_events_ |= kStatEndCmdRes | kStatTimeOutRes;
}

/* Section 15.9.11 (page 15-35): "The MMC_I_MASK register masks off the various
   interrupts. To mask an interrupt, set its bit." */
void Pxa27xMmc::UpdateIrq() {
    const bool active = (IReg() & ~i_mask_ & kIRegMask) != 0u;
    auto& intc = emu_.Get<IrqController>();
    if (active) intc.AssertIrq  (kIntcMmc);
    else        intc.DeAssertIrq(kIntcMmc);
}

uint32_t Pxa27xMmc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off >= kOffEnd || (off & 0x3u) != 0u)
        HaltUnsupportedAccess("ReadWord", addr, 0);
    switch (off) {
        /* Section 15.9.1 (page 15-28): "The register is cleared after the clock
           is started or stopped." */
        case kOffStrpcl:  return 0u;
        case kOffStat:    return Stat();
        case kOffClkrt:   return clkrt_;
        case kOffSpi:     return spi_;
        case kOffCmdat:   return cmdat_;
        case kOffResto:   return resto_;
        case kOffRdto:    return rdto_;
        case kOffBlklen:  return blklen_;
        case kOffNumblk:  return numblk_;
        /* Section 15.9.10 (page 15-35): "This register is cleared by the MMC/
           SD/SDIO controller after the FIFOs have swapped." */
        case kOffPrtbuf:  return 0u;
        case kOffIMask:   return i_mask_;
        case kOffIReg:    return IReg();
        case kOffCmd:     return cmd_ | kCmdTransmissionBit;
        case kOffArgh:    return argh_;
        case kOffArgl:    return argl_;
        /* Table 15-23 (page 15-41): Reset 15:0 = 0. Table 15-24 (page 15-42):
           Reset 7:0 = 0. */
        case kOffRes:     return 0u;
        case kOffRxfifo:  return 0u;
        /* Section 15.9.18 (page 15-42): "This is a write-only register." */
        case kOffTxfifo:  return 0u;
        /* Section 15.9.19 (page 15-42): "The RD_WAIT_STRT bit is cleared by the
           controller after the read data transfer has restarted." */
        case kOffRdwait:  return rdwait_;
        case kOffBlksRem: return blks_rem_;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa27xMmc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off >= kOffEnd || (off & 0x3u) != 0u)
        HaltUnsupportedAccess("WriteWord", addr, value);
    switch (off) {
        /* Table 15-7 (page 15-28): "1 = Starts the MMCLK and then the bit is
           automatically cleared", "1 = Stops the MMCLK and then the bit is
           automatically cleared". */
        case kOffStrpcl:
            if (value & kStrpclStopClk) { clk_on_ = false; clk_is_off_ = true;  }
            if (value & kStrpclStrtClk) { clk_on_ = true;  clk_is_off_ = false; }
            if (clk_on_ && cmd_armed_)
                RunCommandSequence();
            UpdateIrq();
            return;
        /* Section 15.9.2 (page 15-28): "This is a read-only register." */
        case kOffStat:    return;
        case kOffClkrt:   clkrt_  = value & kClkrtRw;  return;
        case kOffSpi:     spi_    = value & kSpiRw;    return;
        case kOffCmdat:
            cmdat_ = value & kCmdatRw;
            ArmCommandSequence(cmdat_);
            UpdateIrq();
            return;
        case kOffResto:   resto_  = value & kRestoRw;  return;
        case kOffRdto:    rdto_   = value & kRdtoRw;   return;
        case kOffBlklen:  blklen_ = value & kBlklenRw; return;
        case kOffNumblk:  numblk_ = value & kNumblkRw; return;
        /* Section 15.9.10 (page 15-35): "The FIFOs swap when either FIFO is full
           (32 bytes) or the MMC_PRTBUF register is set to a 1." */
        case kOffPrtbuf:  return;
        case kOffIMask:   i_mask_ = value & kIRegMask; UpdateIrq(); return;
        /* Section 15.9.12 (page 15-37): "This is a read-only register." */
        case kOffIReg:    return;
        case kOffCmd:     cmd_    = value & kCmdRw;    return;
        case kOffArgh:    argh_   = value & kArgRw;    return;
        case kOffArgl:    argl_   = value & kArgRw;    return;
        /* Sections 15.9.16 (page 15-41) and 15.9.17 (page 15-42): "This is a
           read-only register." */
        case kOffRes:     return;
        case kOffRxfifo:  return;
        /* Table 15-25 (page 15-42): "7:0 W Data". */
        case kOffTxfifo:  return;
        /* Section 15.9.19 (page 15-42): "The RD_WAIT_STRT bit is cleared by the
           controller after the read data transfer has restarted." */
        case kOffRdwait:  rdwait_   = value & kRdwaitEn;  return;
        case kOffBlksRem: blks_rem_ = value & kBlksRemRw; return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa27xMmc::SaveState(StateWriter& w) {
    w.Write(stat_events_); w.Write(clk_on_); w.Write(cmd_armed_); w.Write(clk_is_off_);
    w.Write(clkrt_);  w.Write(spi_);     w.Write(cmdat_);  w.Write(resto_);
    w.Write(rdto_);   w.Write(blklen_);  w.Write(numblk_); w.Write(i_mask_);
    w.Write(cmd_);    w.Write(argh_);    w.Write(argl_);   w.Write(rdwait_);
    w.Write(blks_rem_);
}

void Pxa27xMmc::RestoreState(StateReader& r) {
    r.Read(stat_events_); r.Read(clk_on_); r.Read(cmd_armed_); r.Read(clk_is_off_);
    r.Read(clkrt_);  r.Read(spi_);     r.Read(cmdat_);  r.Read(resto_);
    r.Read(rdto_);   r.Read(blklen_);  r.Read(numblk_); r.Read(i_mask_);
    r.Read(cmd_);    r.Read(argh_);    r.Read(argl_);   r.Read(rdwait_);
    r.Read(blks_rem_);
}

}

REGISTER_SERVICE(Pxa27xMmc);
