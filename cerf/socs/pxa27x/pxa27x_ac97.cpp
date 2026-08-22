#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/ac97_codec.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <cstring>

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Table 13-25 (pages 13-42, 13-43)
   "AC '97 Controller Register Summary". */
enum : uint32_t {
    kPOCR   = 0x000u, kPCMICR = 0x004u, kMCCR = 0x008u, kGCR  = 0x00Cu,
    kPOSR   = 0x010u, kPCMISR = 0x014u, kMCSR = 0x018u, kGSR  = 0x01Cu,
    kCAR    = 0x020u, kPCDR   = 0x040u, kMCDR = 0x060u,
    kMOCR   = 0x100u, kMICR   = 0x108u, kMOSR = 0x110u, kMISR = 0x118u,
    kMODR   = 0x140u,
};

/* Table 13-25 (page 13-43): "(0x4050_0200-0x4050_02FC) Primary Audio Codec
   registers", 0x300 Secondary Audio, 0x400 Primary Modem, 0x500 Secondary
   Modem, "0x4050_0600-0x405F_FFFC reserved". */
enum : uint32_t {
    kCodecBase = 0x200u, kCodecEnd = 0x600u,
    kCodecWindows = 4u, kCodecRegs = 0x80u,
};

/* Table 13-10 (page 13-26) POCR, Table 13-11 (page 13-27) PCMICR, Table 13-16
   (page 13-32) MCCR, Table 13-19 (page 13-35) MOCR, Table 13-20 (page 13-36)
   MICR: "3 R/W FEIE", "1 R/W FSRIE", all other bits reserved. */
constexpr uint32_t kCtrlFields = 0x0000000Au;

/* Table 13-12 (page 13-28) POSR, Table 13-21 (page 13-37) MOSR: "4 R/W FIFOE
   ... Cleared by writing 0b1 to this bit", "2 R FSR". */
constexpr uint32_t kOutStatusW1c = 0x00000010u;
/* Table 13-13 (page 13-29) PCMISR, Table 13-17 (page 13-33) MCSR, Table 13-22
   (page 13-38) MISR: "4 R/W FIFOE", "3 R/W EOC", "2 R FSR". */
constexpr uint32_t kInStatusW1c = 0x00000018u;
constexpr uint32_t kFifoe = 1u << 4, kEoc = 1u << 3, kFsr = 1u << 2;

/* Table 13-8 (pages 13-21, 13-22) GCR: "24 R/W nDMAEN", "19 R/W CDONE_IE",
   "18 R/W SDONE_IE", "9 R/W SRDY_IE", "8 R/W PRDY_IE", "5 R/W SRES_IE",
   "4 R/W PRES_IE", "3 R/W ACOFF", "2 R/W WRST", "1 R/W nCRST", "0 R/W
   GPI_IE". */
constexpr uint32_t kGcrFields = 0x010C033Fu;
constexpr uint32_t kGcrAcoff = 1u << 3, kGcrWrst = 1u << 2, kGcrNcrst = 1u << 1;

/* Table 13-9 (pages 13-23, 13-24, 13-25) GSR: CDONE, SDONE, RCS, SRESINT,
   PRESINT and GSCI are each "cleared by software writing 0b1 to this
   location". */
constexpr uint32_t kGsrW1c = 0x000C8C01u;
constexpr uint32_t kGsrCdone  = 1u << 19, kGsrSdone = 1u << 18;
constexpr uint32_t kGsrPcrdy  = 1u << 8;
constexpr uint32_t kGsrMcint  = 1u << 7, kGsrPoint = 1u << 6, kGsrPiint = 1u << 5;
constexpr uint32_t kGsrAcoffd = 1u << 3, kGsrMoint = 1u << 2, kGsrMiint = 1u << 1;

class Pxa27xAc97 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    /* Section 13.7 (page 13-20): "The AC '97 controller and Codec registers are
       mapped in addresses 0x4050_0000-0x405F_FFFC." */
    uint32_t MmioBase() const override { return 0x40500000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    /* Section 13.8 (page 13-42): "All AC '97 controller registers are
       word-addressable (32 bits wide) and increment in units of 0x00004. The
       registers in the Codec are half-word-addressable (16 bits wide)." */
    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (off == kGCR) return gcr_;
        if (!LinkOutOfColdReset()) return IsRegister(off) ? 0u : Reject("ReadWord", addr, 0);
        if (InCodecWindow(off)) return CodecRead(off);
        switch (off) {
        case kPOCR:   return pocr_;
        case kPCMICR: return pcmicr_;
        case kMCCR:   return mccr_;
        case kPOSR:   return posr_;
        case kPCMISR: return pcmisr_;
        case kMCSR:   return mcsr_;
        case kGSR:    return ReadGsr();
        case kCAR:    return ReadCar();
        case kMOCR:   return mocr_;
        case kMICR:   return micr_;
        case kMOSR:   return mosr_;
        case kMISR:   return misr_;
        case kPCDR:   return ReadRxFifo(pcmisr_);
        case kMCDR:   return ReadRxFifo(mcsr_);
        case kMODR:   return ReadRxFifo(misr_);
        }
        return Reject("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off == kGCR) { WriteGcr(value); return; }
        if (!LinkOutOfColdReset()) {
            if (!IsRegister(off)) Reject("WriteWord", addr, value);
            return;
        }
        if (InCodecWindow(off)) {
            CodecWrite(off, static_cast<uint16_t>(value));
            return;
        }
        switch (off) {
        case kPOCR:   pocr_   = value & kCtrlFields; return;
        case kPCMICR: pcmicr_ = value & kCtrlFields; return;
        case kMCCR:   mccr_   = value & kCtrlFields; return;
        case kMOCR:   mocr_   = value & kCtrlFields; return;
        case kMICR:   micr_   = value & kCtrlFields; return;
        case kPOSR:   posr_   &= ~(value & kOutStatusW1c); return;
        case kMOSR:   mosr_   &= ~(value & kOutStatusW1c); return;
        case kPCMISR: pcmisr_ &= ~(value & kInStatusW1c);  return;
        case kMCSR:   mcsr_   &= ~(value & kInStatusW1c);  return;
        case kMISR:   misr_   &= ~(value & kInStatusW1c);  return;
        case kGSR:    gsr_    &= ~(value & kGsrW1c);       return;
        /* Table 13-14 (page 13-30) CAR: "Software can also clear this bit by
           writing 0b0 to this bit location". */
        case kCAR:    car_caip_ = (value & 1u) != 0u; return;
        /* Table 13-18 (page 13-34) MCDR: "This is a read-only register. A write
           to this register has no effect." */
        case kPCDR: case kMODR: case kMCDR: return;
        }
        Reject("WriteWord", addr, value);
    }

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (!InCodecWindow(off)) return static_cast<uint16_t>(Reject("ReadHalf", addr, 0));
        return LinkOutOfColdReset() ? CodecRead(off) : 0u;
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t off = addr - MmioBase();
        if (!InCodecWindow(off)) { Reject("WriteHalf", addr, value); return; }
        if (LinkOutOfColdReset()) CodecWrite(off, value);
    }

    void SaveState(StateWriter& w) override {
        w.Write(pocr_);   w.Write(pcmicr_); w.Write(mccr_);
        w.Write(mocr_);   w.Write(micr_);   w.Write(gcr_);
        w.Write(posr_);   w.Write(pcmisr_); w.Write(mcsr_);
        w.Write(mosr_);   w.Write(misr_);   w.Write(gsr_);
        w.Write(car_caip_);
        w.WriteBytes(codec_, sizeof(codec_));
        if (auto* c = emu_.TryGet<Ac97Codec>()) c->SaveState(w);
    }
    void RestoreState(StateReader& r) override {
        r.Read(pocr_);   r.Read(pcmicr_); r.Read(mccr_);
        r.Read(mocr_);   r.Read(micr_);   r.Read(gcr_);
        r.Read(posr_);   r.Read(pcmisr_); r.Read(mcsr_);
        r.Read(mosr_);   r.Read(misr_);   r.Read(gsr_);
        r.Read(car_caip_);
        r.ReadBytes(codec_, sizeof(codec_));
        if (auto* c = emu_.TryGet<Ac97Codec>()) c->RestoreState(r);
    }

private:
    [[noreturn]] uint32_t Reject(const char* op, uint32_t addr, uint32_t value) {
        HaltUnsupportedAccess(op, addr, value);
    }

    static bool InCodecWindow(uint32_t off) {
        return off >= kCodecBase && off < kCodecEnd;
    }

    static bool IsRegister(uint32_t off) {
        switch (off) {
        case kPOCR: case kPCMICR: case kMCCR: case kGCR:
        case kPOSR: case kPCMISR: case kMCSR: case kGSR:
        case kCAR:  case kPCDR:   case kMCDR:
        case kMOCR: case kMICR:   case kMOSR: case kMISR:
        case kMODR:
            return true;
        default:
            return InCodecWindow(off);
        }
    }

    /* Section 13.6.1 (page 13-16): "When GCR[nCRST] is 0b0, all other registers
       are in their reset state." */
    bool LinkOutOfColdReset() const { return (gcr_ & kGcrNcrst) != 0u; }

    /* Section 13.7.17 (page 13-40): "Physical address for a Primary Audio Codec
       = 0x4050_0200 + Shift_Left_Once (Internal 7-bit Codec register address)". */
    static uint32_t CodecWindow(uint32_t off) { return (off - kCodecBase) >> 8; }
    static uint32_t CodecReg(uint32_t off) { return (off & 0xFFu) >> 1; }

    /* Section 13.6.3 (pages 13-17, 13-18): "The AC '97 controller clears the
       CAR[CAIP] bit when the Codec-write or Codec-read operation completes";
       "sets the GSR[CDONE] bit after the completion of a Codec write
       operation"; "the AC '97 controller sets the GSR[SDONE] bit". */
    uint16_t CodecRead(uint32_t off) {
        car_caip_ = false;
        gsr_ |= kGsrSdone;
        const uint32_t win = CodecWindow(off), reg = CodecReg(off);
        if (win == 0) {
            if (auto* c = emu_.TryGet<Ac97Codec>()) return c->ReadReg(reg);
        }
        return codec_[win][reg];
    }

    void CodecWrite(uint32_t off, uint16_t value) {
        car_caip_ = false;
        gsr_ |= kGsrCdone;
        const uint32_t win = CodecWindow(off), reg = CodecReg(off);
        if (win == 0) {
            if (auto* c = emu_.TryGet<Ac97Codec>()) { c->WriteReg(reg, value); return; }
        }
        codec_[win][reg] = value;
    }

    /* Table 13-14 (page 13-30) CAR: "If no cycle is in progress, this bit is
       0b0, and the act of reading the register sets this bit to 0b1, which
       reserves the right for that software driver to perform the I/O cycle." */
    uint32_t ReadCar() {
        const uint32_t v = car_caip_ ? 1u : 0u;
        car_caip_ = true;
        return v;
    }

    /* Table 13-13 (page 13-29) PCMISR[FIFOE]: "Receive FIFO underrun occurs.
       Invalid data is read by the CPU. Pointers do not increment. This could
       happen only if programmed I/O tries to read the receive FIFO when it is
       empty." */
    static uint32_t ReadRxFifo(uint32_t& status) {
        status |= kFifoe;
        return 0u;
    }

    /* Table 13-9 (page 13-24) "3 R ACOFFD ... Is 0b1 if the AC-link has been
       cleanly shutdown"; (page 13-23) "8 R PCRDY Primary Codec Ready. Reflects
       the state of the Codec Ready bit in AC97_SDATA_IN_0." */
    uint32_t ReadGsr() const {
        uint32_t v = gsr_ | kGsrPcrdy;
        if (gcr_ & kGcrAcoff) v |= kGsrAcoffd;
        if (posr_   & (kFifoe | kFsr))        v |= kGsrPoint;
        if (mosr_   & (kFifoe | kFsr))        v |= kGsrMoint;
        if (pcmisr_ & (kFifoe | kEoc | kFsr)) v |= kGsrPiint;
        if (mcsr_   & (kFifoe | kEoc | kFsr)) v |= kGsrMcint;
        if (misr_   & (kFifoe | kEoc | kFsr)) v |= kGsrMiint;
        return v;
    }

    /* Table 13-8 (page 13-22) "2 R/W WRST ... This bit is self-clearing"; "1
       R/W nCRST ... 0 = Causes a cold reset to occur throughout the AC '97
       circuitry. All data in the controller and the Codec is lost." */
    void WriteGcr(uint32_t value) {
        gcr_ = value & kGcrFields & ~kGcrWrst;
        if (LinkOutOfColdReset()) return;
        pocr_ = pcmicr_ = mccr_ = mocr_ = micr_ = 0;
        posr_ = pcmisr_ = mcsr_ = mosr_ = misr_ = gsr_ = 0;
        car_caip_ = false;
        std::memset(codec_, 0, sizeof(codec_));
    }

    /* Reset rows of Table 13-9 (page 13-23) and Tables 13-10 through 13-23 are
       0b0 in every defined field; the Table 13-8 (page 13-21) row is 0b0 in
       every defined field except nDMAEN, which it prints as undefined. */
    uint32_t pocr_ = 0, pcmicr_ = 0, mccr_ = 0, mocr_ = 0, micr_ = 0, gcr_ = 0;
    uint32_t posr_ = 0, pcmisr_ = 0, mcsr_ = 0, mosr_ = 0, misr_ = 0, gsr_ = 0;
    bool     car_caip_ = false;
    uint16_t codec_[kCodecWindows][kCodecRegs] = {};
};

}  /* namespace */

REGISTER_SERVICE(Pxa27xAc97);
