#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <mutex>

/* Intel PXA27x Developer's Manual 280000-001 Table 5-22 (pages 5-51 through
   5-58) "DMA Controller Register Summary". */
class Pxa27xDma : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    /* Table 5-22 (page 5-51) first entry "0x4000_0000 DCSR0"; (page 5-58) last
       entry "0x4000_112C-0x400F_FFFC reserved". */
    uint32_t MmioBase() const override { return 0x40000000u; }
    uint32_t MmioSize() const override { return 0x00100000u; }

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

protected:
    /* Table 5-18 (pages 5-41 through 5-46) DCSR0-31 bit definitions. */
    static constexpr uint32_t RUN        = 1u << 31, NODESCFETCH = 1u << 30,
                              STOPIRQEN  = 1u << 29, EORIRQEN    = 1u << 28,
                              EORJMPEN   = 1u << 27, EORSTOPEN   = 1u << 26,
                              SETCMPST   = 1u << 25, CLRCMPST    = 1u << 24,
                              RASIRQEN   = 1u << 23, MASKRUN     = 1u << 22,
                              CMPST      = 1u << 10, EORINT      = 1u <<  9,
                              REQPEND    = 1u <<  8, RASINTR     = 1u <<  4,
                              STOPINTR   = 1u <<  3, ENDINTR     = 1u <<  2,
                              STARTINTR  = 1u <<  1, BUSERRINTR  = 1u <<  0;
    /* Table 5-18 Access column reads R/W for bits 31:26, 23, 10 and 4. */
    static constexpr uint32_t kDcsrRw = RUN | NODESCFETCH | STOPIRQEN | EORIRQEN
                                      | EORJMPEN | EORSTOPEN | RASIRQEN | CMPST
                                      | RASINTR;
    /* Table 5-18 (page 5-44) "To clear EORINT, write 0b1 to the bit"; (page
       5-45) "Set ENDINTR to reset the corresponding interrupt", "Set STARTINTR
       to reset the corresponding interrupt"; (page 5-46) "Set BUSERRINTR to
       reset the corresponding interrupt". */
    static constexpr uint32_t kDcsrW1c = EORINT | ENDINTR | STARTINTR | BUSERRINTR;
    /* Table 5-18 Access column reads W for bits 25, 24 and 22, and R for bits 8
       and 3. */
    static constexpr uint32_t kDcsrWriteOnly = SETCMPST | CLRCMPST | MASKRUN;
    static constexpr uint32_t kDcsrReadOnly  = REQPEND | STOPINTR;

    /* Table 5-15 (pages 5-35 through 5-38) DCMD0-31 bit definitions. */
    static constexpr uint32_t INCSRCADDR = 1u << 31, INCTRGADDR = 1u << 30,
                              FLOWSRC    = 1u << 29, FLOWTRG    = 1u << 28,
                              CMPEN      = 1u << 25, ADDRMODE   = 1u << 23,
                              STARTIRQEN = 1u << 22, ENDIRQEN   = 1u << 21;
    static constexpr uint32_t kDcmdMask = 0xF2FBDFFFu;
    /* Table 5-15 (page 5-38) "15:14 R/W WIDTH ... 0b01 = 1 byte / 0b10 =
       Half-word (2 bytes) / 0b11 = Word (4 Bytes)". */
    static constexpr uint32_t kDcmdWidthShift = 14, kDcmdWidthMask = 0x3u;
    /* Table 5-15 (page 5-38) "12:0 R/W LEN ... The maximum transfer length is
       (8K - 1) bytes." */
    static constexpr uint32_t kDcmdLengthMask = 0x1FFFu;

    /* Table 5-12 (page 5-32) DDADR0-31 "31:4 R/W Descriptor Address", "1 R/W
       BREN", "0 R/W STOP". */
    static constexpr uint32_t DDADR_BREN = 1u << 1, DDADR_STOP = 1u << 0;
    static constexpr uint32_t kDdadrMask = 0xFFFFFFF3u;
    static constexpr uint32_t kDescAddrMask = 0xFFFFFFF0u;
    /* Table 5-12 (page 5-32) BREN: "If both DDADRx[BREN] and DCSRx[CMPST] are
       set, the DMA controller fetches the next descriptor from (DDADRx + 32
       bytes)." */
    static constexpr uint32_t kBranchOffset = 32u;

    /* Table 5-11 (page 5-31) DRCMR0-74 "7 R/W MAPVLD", "4:0 R/W CHLNUM". */
    static constexpr uint32_t kDrcmrMask = 0x9Fu;

    /* Table 5-20 (page 5-49): "the DMA controller forces the least-significant
       three bits for all external addresses to zeros and the least significant
       two bits of all peripheral addresses to zeros." */
    static constexpr uint32_t kAlignExternal   = 0xFFFFFFF8u;
    static constexpr uint32_t kAlignPeripheral = 0xFFFFFFFCu;

    /* Table 5-21 (page 5-51) DPCSR "31 R/W BRGSPLT", "0 R BRGBUSY"; reset row
       prints bit 31 = 0b1. */
    static constexpr uint32_t kDpcsrRw = 0x80000000u, kDpcsrReset = 0x80000000u;

    /* Table 25-2 (page 25-5) "IP[25] DMA controller DMA Channel service request
       25"; Table 25-9 (page 25-20) ICMR "25 R/W DMAC". */
    static constexpr uint32_t kIntcDmaBit = 25u;

    /* Table 5-22 (pages 5-51, 5-52) "0x4000_0000 DCSR0" through
       "0x4000_007C DCSR31". */
    static constexpr uint32_t kNumChannels = 32;
    static constexpr uint32_t kMaxDescriptors = 4096;

    std::mutex state_mutex_;
    /* Table 5-18 (page 5-41) reset row is 0b0 in every stored field. Bit 3
       STOPINTR is Access R: "0 = The channel is running / 1 = The channel is in
       uninitialized or stopped state" (page 5-45). */
    uint32_t dcsr_[kNumChannels]  = {};
    uint32_t ddadr_[kNumChannels] = {}, dsadr_[kNumChannels] = {};
    uint32_t dtadr_[kNumChannels] = {}, dcmd_[kNumChannels]  = {};
    /* Table 5-22 (pages 5-52 through 5-58): DRCMR0-63 at 0x4000_0100-0x4000_01FC,
       DRCMR64-70 at 0x4000_1100-0x4000_1118, DRCMR74 at 0x4000_1128. */
    uint8_t  drcmr_lo_[64] = {}, drcmr_hi_[7] = {}, drcmr74_ = 0;
    uint32_t dalgn_ = 0;
    uint32_t dpcsr_ = kDpcsrReset;

    uint32_t DcsrValue(uint32_t ch) const;
    void WriteDcsrLocked(uint32_t ch, uint32_t value);
    void StartChannelLocked(uint32_t ch);
    void RunChannelSyncLocked(uint32_t ch);
    bool RunTransfer(uint32_t ch);
    bool RunCompareLocked(uint32_t ch);
    uint32_t DescriptorAddressLocked(uint32_t ch) const;
    uint32_t AlignBaseLocked(uint32_t ch, uint32_t pa);
    static uint32_t UnitWidth(uint32_t dcmd);
    uint32_t Dint() const;
    bool ChannelIrq(uint32_t ch) const;
    void UpdateIrqLocked();
    bool ReadPhys32(uint32_t pa, uint32_t* out);
    bool ReadPhys(uint32_t pa, uint32_t width, uint32_t* out);
    bool WritePhys(uint32_t pa, uint32_t width, uint32_t value);

private:
    uint32_t ReadRegLocked(uint32_t addr);
    void     WriteRegLocked(uint32_t addr, uint32_t value);
    uint8_t* DrcmrSlot(uint32_t off);
};
