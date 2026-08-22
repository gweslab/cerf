#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* PXA270 Developer's Manual chapter 12, USB Client Controller. */
class Pxa27xUdc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    /* Table 12-33 (pages 12-67..12-70): 0x4060_0000 UDCCR through
       "0x4060_0460-0x406F_FFFC reserved". */
    uint32_t MmioBase() const override { return 0x40600000u; }
    uint32_t MmioSize() const override { return 0x00100000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    /* Table 12-33 (pages 12-67..12-69): UDCCSRA..UDCCSRX, letter O skipped. */
    static constexpr uint32_t kNumEps = 23u;

    /* Table 12-12 (pages 12-33..12-35): "31 R/W OEN", "0 R/W UDE"; "4
       Read/Write 1 to Set SMAC", "3 Read/Write 1 to Clear EMCE", "2 Read/Write
       1 to Set UDR"; "30 R AALTHNP", "1 R UDA". Page 12-16: "The UDCCR[SMAC] is
       cleared by the UDC after the endpoint memory reallocation has completed." */
    static constexpr uint32_t kUdccrRw  = 0x80000001u;
    static constexpr uint32_t kUdccrUde = 0x00000001u;

    /* Table 12-15 (page 12-38): all 32 bits "R/W". */
    static constexpr uint32_t kUdcicr0Rw = 0xFFFFFFFFu;
    /* Table 12-16 (page 12-39): "31 R/W IECC".."27 R/W IERS", "26:16 reserved",
       "15:14 R/W IEX".."1:0 R/W IEQ". */
    static constexpr uint32_t kUdcicr1Rw = 0xF800FFFFu;
    /* Table 12-17 (page 12-40): "31:25 reserved", "24 R/W IESF", "23:18
       reserved", "17 R/W IEXR", "16 R/W IEXF", "15:10 reserved", "9 R/W
       IEVV40R".."0 R/W IEIDF". */
    static constexpr uint32_t kUdcotgicrRw = 0x010303FFu;

    /* Table 12-20 (pages 12-46..12-47): "26:24 R/W SEOS", "23:18 reserved",
       "17 R/W HXOE", "16 R/W HXS", "15:11 reserved", "10 R/W IDON".."0 R/W
       CPVEN", "31:27 reserved"; Reset row prints 1 at HXOE and HXS. */
    static constexpr uint32_t kUp2ocrRw    = 0x070307FFu;
    static constexpr uint32_t kUp2ocrReset = 0x00030000u;
    /* Table 12-22 (page 12-48): "31:2 reserved", "1:0 R/W CFG". */
    static constexpr uint32_t kUp3ocrRw    = 0x00000003u;

    /* Table 12-27 (pages 12-53..12-55): "9 R/W ACM", "3 R/W DME". */
    static constexpr uint32_t kUdccsr0Rw  = 0x00000208u;
    /* Table 12-27: "8 Read/Write 1 to Set AREN", "5 Read/Write 1 to Set FST",
       "1 Read/Write 1 to Set IPR"; "7 Read/Write 1 to Clear SA", "4 Read/Write
       1 to Clear SST", "0 Read/Write 1 to Clear OPC"; "6 R RNE". */
    static constexpr uint32_t kUdccsr0Set = 0x00000122u;
    /* Table 12-27 (page 12-55): "2 Read 0/Write 1 to Set FTF"; "The UDC
       automatically clears IPR when the packet has been successfully
       transmitted or FTF has been set." */
    static constexpr uint32_t kUdccsr0Ftf = 0x00000004u;
    static constexpr uint32_t kUdccsr0Ipr = 0x00000002u;

    /* Table 12-29 (pages 12-60..12-61): "5 R/W FST", "3 R/W DME"; "8
       Read/Write 1 to Set FEF", "4 Read/Write 1 to Clear SST", "2 Read/Write 1
       to Clear TRN", "1 Read/Write 1 to Clear PC"; "9 R DPE". */
    static constexpr uint32_t kEpCsrRw = 0x00000028u;
    /* Table 12-29 (page 12-60): "7 IN Endpoints: Read/Write 1 to Set, OUT
       Endpoints: R    SP". */
    static constexpr uint32_t kEpCsrSp = 0x00000080u;
    /* Table 12-29 "6 R BNE/BNF", "0 R FS"; page 12-56: "If the endpoint is
       configured as an IN endpoint, BNE/BNF clears when the endpoint buffer
       space has been filled with packet data."; page 12-59: "FS is active if
       there is less than one complete data packet in the transmit FIFO." */
    static constexpr uint32_t kEpCsrInIdle = 0x00000041u;

    /* Table 12-32 (pages 12-65..12-66): "31:27 reserved"; bits 26:0 "If UDE =
       0: R/W  If UDE = 1: R". Page 12-64: "Once the UDC has been enabled, the
       endpoint Configuration registers become read-only and cannot be changed
       until the UDC is disabled." */
    static constexpr uint32_t kEpCrRw = 0x07FFFFFFu;
    /* Table 12-32 (page 12-66): "12 ... ED USB Endpoint Direction ... 1 = IN",
       "0 ... EE Endpoint Enable". */
    static constexpr uint32_t kEpCrEd = 0x00001000u;
    static constexpr uint32_t kEpCrEe = 0x00000001u;

    uint32_t EpCsr(uint32_t n) const;
    void     WriteEpCsr(uint32_t n, uint32_t value);

    uint32_t udccr_     = 0u;  /* Table 12-12 (page 12-35): Reset 31:0 = 0. */
    uint32_t udcicr0_   = 0u;  /* Table 12-15 (page 12-38): Reset 31:0 = 0. */
    uint32_t udcicr1_   = 0u;  /* Table 12-16 (page 12-39): Reset 31:0 = 0. */
    uint32_t udcotgicr_ = 0u;  /* Table 12-17 (page 12-40): Reset 31:0 = 0. */
    uint32_t up2ocr_    = kUp2ocrReset;
    uint32_t up3ocr_    = 0u;  /* Table 12-22 (page 12-48): Reset 31:0 = 0. */
    uint32_t udccsr0_   = 0u;  /* Table 12-27 (page 12-53): Reset 9:0 = 0. */
    uint32_t epcsr_[kNumEps] = {};  /* Table 12-29 (page 12-60): Reset 9:0 = 0. */
    uint32_t epcr_ [kNumEps] = {};  /* Table 12-32 (page 12-65): Reset 26:0 = 0. */
};

/* Table 12-33 (pages 12-67..12-70). */
enum : uint32_t {
    kOffUdccr     = 0x000, kOffUdcicr0    = 0x004, kOffUdcicr1   = 0x008,
    kOffUdcisr0   = 0x00C, kOffUdcisr1    = 0x010, kOffUdcfnr    = 0x014,
    kOffUdcotgicr = 0x018, kOffUdcotgisr  = 0x01C,
    kOffUp2ocr    = 0x020, kOffUp3ocr     = 0x024,
    kOffUdccsr0   = 0x100, kOffEpCsr      = 0x104, kOffEpCsrLast = 0x15C,
    kOffUdcbcr0   = 0x200, kOffUdcbcrLast = 0x25C,
    kOffUdcdr0    = 0x300, kOffUdcdrLast  = 0x35C,
    kOffEpCr      = 0x404, kOffEpCrLast   = 0x45C,
    kOffFileEnd   = 0x460,
};

uint32_t Pxa27xUdc::EpCsr(uint32_t n) const {
    uint32_t v = epcsr_[n];
    if ((epcr_[n] & (kEpCrEe | kEpCrEd)) == (kEpCrEe | kEpCrEd))
        v |= kEpCsrInIdle;
    return v;
}

void Pxa27xUdc::WriteEpCsr(uint32_t n, uint32_t value) {
    /* Table 12-29 (page 12-60) "8 Read/Write 1 to Set FEF"; page 12-56: "FEF is
       cleared by the UDC after the FIFO contents have been deleted." */
    uint32_t next = (value & kEpCsrRw) | (epcsr_[n] & kEpCsrSp);
    if (epcr_[n] & kEpCrEd)
        next |= value & kEpCsrSp;
    epcsr_[n] = next;
}

uint32_t Pxa27xUdc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off >= kOffFileEnd || (off & 0x3u) != 0u)
        HaltUnsupportedAccess("ReadWord", addr, 0);
    if (off >= kOffEpCsr && off <= kOffEpCsrLast)
        return EpCsr((off - kOffEpCsr) >> 2);
    if (off >= kOffEpCr && off <= kOffEpCrLast)
        return epcr_[(off - kOffEpCr) >> 2];
    /* Table 12-30 (page 12-62): "9:0 R BC Byte Count". */
    if (off >= kOffUdcbcr0 && off <= kOffUdcbcrLast)
        return 0u;
    /* Table 12-31 (page 12-64): UDCDR0/A-X, Reset row undefined. */
    if (off >= kOffUdcdr0 && off <= kOffUdcdrLast)
        return 0u;
    switch (off) {
        case kOffUdccr:     return udccr_;
        case kOffUdcicr0:   return udcicr0_;
        case kOffUdcicr1:   return udcicr1_;
        /* Table 12-23 (page 12-50) "31:30 R/W IRP".."1:0 R/W IR0" and Table
           12-24 (page 12-51) "31 R/W IRCC".."1:0 R/W IRQ" are set by the UDC on
           USB traffic. */
        case kOffUdcisr0:   return 0u;
        case kOffUdcisr1:   return 0u;
        /* Table 12-26 (page 12-52): "10:0 R FN Frame number associated with
           last received SOF." */
        case kOffUdcfnr:    return 0u;
        case kOffUdcotgicr: return udcotgicr_;
        /* Table 12-25 (pages 12-51..12-52): "24 R/WC IRSF".."0 R/WC IRIDF". */
        case kOffUdcotgisr: return 0u;
        case kOffUp2ocr:    return up2ocr_;
        case kOffUp3ocr:    return up3ocr_;
        case kOffUdccsr0:   return udccsr0_;
    }
    /* Table 12-33 (pages 12-67..12-70): "0x4060_0028-0x4060_00FC reserved",
       "0x4060_0160-0x4060_01FC reserved", "0x4060_0260-0x4060_02FC reserved",
       "0x4060_0360-0x4060_03FC reserved", "0x4060_0400 reserved". */
    return 0u;
}

void Pxa27xUdc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off >= kOffFileEnd || (off & 0x3u) != 0u)
        HaltUnsupportedAccess("WriteWord", addr, value);
    if (off >= kOffEpCsr && off <= kOffEpCsrLast) {
        WriteEpCsr((off - kOffEpCsr) >> 2, value);
        return;
    }
    if (off >= kOffEpCr && off <= kOffEpCrLast) {
        if (!(udccr_ & kUdccrUde))
            epcr_[(off - kOffEpCr) >> 2] = value & kEpCrRw;
        return;
    }
    /* Table 12-30 (page 12-62): "9:0 R BC". */
    if (off >= kOffUdcbcr0 && off <= kOffUdcbcrLast)
        return;
    /* Table 12-31 (page 12-64): UDCDR0/A-X transmit data. */
    if (off >= kOffUdcdr0 && off <= kOffUdcdrLast)
        return;
    switch (off) {
        case kOffUdccr:     udccr_     = value & kUdccrRw;     return;
        case kOffUdcicr0:   udcicr0_   = value & kUdcicr0Rw;   return;
        case kOffUdcicr1:   udcicr1_   = value & kUdcicr1Rw;   return;
        /* Table 12-23 (page 12-50) / Table 12-24 (page 12-51): write-1-to-clear
           over bits the UDC sets only on USB traffic. */
        case kOffUdcisr0:   return;
        case kOffUdcisr1:   return;
        /* Table 12-26 (page 12-52): "10:0 R FN". */
        case kOffUdcfnr:    return;
        case kOffUdcotgicr: udcotgicr_ = value & kUdcotgicrRw; return;
        /* Table 12-25 (pages 12-51..12-52): "R/WC". */
        case kOffUdcotgisr: return;
        case kOffUp2ocr:    up2ocr_    = value & kUp2ocrRw;    return;
        case kOffUp3ocr:    up3ocr_    = value & kUp3ocrRw;    return;
        case kOffUdccsr0: {
            const uint32_t next = (value    & kUdccsr0Rw)
                                | (udccsr0_ & kUdccsr0Set)
                                | (value    & kUdccsr0Set);
            udccsr0_ = (value & kUdccsr0Ftf) ? (next & ~kUdccsr0Ipr) : next;
            return;
        }
    }
    /* Table 12-33 (pages 12-67..12-70): reserved. */
}

void Pxa27xUdc::SaveState(StateWriter& w) {
    w.Write(udccr_);   w.Write(udcicr0_); w.Write(udcicr1_);
    w.Write(udcotgicr_);
    w.Write(up2ocr_);  w.Write(up3ocr_);  w.Write(udccsr0_);
    w.WriteBytes(epcsr_, sizeof(epcsr_));
    w.WriteBytes(epcr_,  sizeof(epcr_));
}

void Pxa27xUdc::RestoreState(StateReader& r) {
    r.Read(udccr_);   r.Read(udcicr0_); r.Read(udcicr1_);
    r.Read(udcotgicr_);
    r.Read(up2ocr_);  r.Read(up3ocr_);  r.Read(udccsr0_);
    r.ReadBytes(epcsr_, sizeof(epcsr_));
    r.ReadBytes(epcr_,  sizeof(epcr_));
}

}

REGISTER_SERVICE(Pxa27xUdc);
