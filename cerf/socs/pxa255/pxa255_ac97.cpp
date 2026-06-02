#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>

namespace {

/* PXA255 AC'97 controller (§13, base 0x40500000). Careful audio stub: no
   codec/FIFO is modeled, so GSR must report codec-ready (PCR) + commands-done
   (CDONE/SDONE) and CAR must report the link free (CAIP=0), or the audio
   driver deadlocks the boot polling for them. Control regs are storage. */
class Pxa255Ac97 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x40500000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    static constexpr uint32_t kPOCR = 0x00u;
    static constexpr uint32_t kPICR = 0x04u;
    static constexpr uint32_t kMCCR = 0x08u;
    static constexpr uint32_t kGCR  = 0x0Cu;
    static constexpr uint32_t kGSR  = 0x1Cu;
    static constexpr uint32_t kCAR  = 0x20u;
    static constexpr uint32_t kMOCR = 0x100u;
    static constexpr uint32_t kMICR = 0x108u;

    /* §13.8.3.17 / Table 13-24: CODEC register windows span 0x200..0x5FF,
       each a 16-bit reg at offset (codec_reg << 1). No codec modeled, so the
       window is storage — set-then-verify read-back must match or codec init
       hangs. */
    static constexpr uint32_t kCodecBase = 0x200u;
    static constexpr uint32_t kCodecEnd  = 0x600u;
    static bool InCodecWindow(uint32_t off) {
        return off >= kCodecBase && off < kCodecEnd;
    }

    /* §13.8.3.2 Table 13-8: codec ready (PCR) + commands done (CDONE/SDONE). */
    static constexpr uint32_t kGsrReady = (1u << 8) | (1u << 18) | (1u << 19);

    uint32_t pocr_ = 0, picr_ = 0, mccr_ = 0, gcr_ = 0, mocr_ = 0, micr_ = 0;
    uint16_t codec_[(kCodecEnd - kCodecBase) / 2] = {};
};

uint32_t Pxa255Ac97::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (InCodecWindow(off)) return codec_[(off - kCodecBase) >> 1];
    switch (off) {
        case kPOCR: return pocr_;
        case kPICR: return picr_;
        case kMCCR: return mccr_;
        case kGCR:  return gcr_;
        case kMOCR: return mocr_;
        case kMICR: return micr_;
        case kGSR:  return kGsrReady;  /* codec ready, commands done. */
        case kCAR:  return 0u;         /* §13.6.3: CAIP=0 → AC-link free. */
        default:    return 0u;         /* status/codec/FIFO idle. */
    }
}

void Pxa255Ac97::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (InCodecWindow(off)) {
        codec_[(off - kCodecBase) >> 1] = static_cast<uint16_t>(value);
        return;
    }
    switch (off) {
        case kPOCR: pocr_ = value; return;
        case kPICR: picr_ = value; return;
        case kMCCR: mccr_ = value; return;
        case kGCR:  gcr_  = value; return;
        case kMOCR: mocr_ = value; return;
        case kMICR: micr_ = value; return;
        /* §13.6.3: CAR.CAIP is HW-owned and no codec is modeled, so CAR always
           reads CAIP=0 (free). The driver's `car &= ~CAIP` must stay dropped —
           storing it would let a stale CAIP=1 read back BUSY and hang the poll
           (aclinkcontrol.c Ac97Unlock / while(TEST(car,CAIP)==BUSY)). */
        case kCAR:  return;
        default:    return;            /* GSR W1C status / FIFO writes. */
    }
}

uint16_t Pxa255Ac97::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (InCodecWindow(off)) return codec_[(off - kCodecBase) >> 1];
    const uint32_t word  = ReadWord(addr & ~0x3u);
    const uint32_t shift = (off & 0x2u) * 8u;
    return static_cast<uint16_t>((word >> shift) & 0xFFFFu);
}

void Pxa255Ac97::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - MmioBase();
    if (InCodecWindow(off)) {
        codec_[(off - kCodecBase) >> 1] = value;
        return;
    }
    const uint32_t shift = (off & 0x2u) * 8u;
    const uint32_t word  = ReadWord(addr & ~0x3u);
    WriteWord(addr & ~0x3u,
              (word & ~(0xFFFFu << shift)) | (static_cast<uint32_t>(value) << shift));
}

}  /* namespace */

REGISTER_SERVICE(Pxa255Ac97);
