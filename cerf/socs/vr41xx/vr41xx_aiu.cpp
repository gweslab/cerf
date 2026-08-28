#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <cstdint>

namespace {

/* VR41xx AIU (Audio Interface Unit), 0x0B000160-0x0B00017F (VR4111 UM Table 6-10 p170 /
   VR4121 UM ch.21 Table 21-1 p495 / VR4102 UM ch.20 Table 20-1). */
constexpr uint32_t kBase = 0x0B000160u;
constexpr uint32_t kSize = 0x20u;

constexpr uint32_t kOffScnt  = 0x08u;   /* SCNTREG  0x168 (VR4111 21.2.4 p448 / VR4121 p499 / VR4102 p413) */
constexpr uint32_t kOffScnvr = 0x0Au;   /* SCNVRREG 0x16A (VR4111 Table 21-1 p445 / VR4102 20.2.5 p414) */
constexpr uint32_t kOffMcnt  = 0x12u;   /* MCNTREG  0x172 (VR4111 21.2.7 p451 / VR4121 p502 / VR4102 p416) */
constexpr uint32_t kOffSeq   = 0x1Au;   /* SEQREG   0x17A (VR4111 21.2.10 p454 / VR4121 p505 / VR4102 p419) */
constexpr uint32_t kOffInt   = 0x1Cu;   /* INTREG   0x17C (VR4111 21.2.11 p455 / VR4121 p506 / VR4102 p420) */

/* SEQREG: D15 AIURST, D4 AIUMEN, D0 AIUSEN R/W; D14:5 / D3:1 reserved. AIUMEN and AIUSEN are
   "MIC/Speaker block operation enable, DMA enable" (VR4111 p454 / VR4121 p505 / VR4102 p419). */
constexpr uint16_t kSeqWritable = 0x8011u;
constexpr uint16_t kSeqAiumen   = 0x0010u;

/* SCNTREG: D15 DAENAIU + D1 SSTOPEN R/W; D14:4 / D2 / D0 reserved, "0 is returned after a
   read"; D3 SSTATE (R) "Indicates speaker operation state / 1: In operation / 0: Stopped"
   (VR4111 21.2.4 p448 / VR4121 21.2.4 p499 / VR4102 20.2.4 p413). */
constexpr uint16_t kScntWritable = 0x8002u;

/* MCNTREG: D15 ADENAIU + D1 MSTOPEN R/W; D0 ADREQAIU (R, "1: Request / 0: Normal");
   D14:4 / D2 reserved (VR4111 21.2.7 p451 / VR4121 21.2.7 p502 / VR4102 20.2.7 p416).
   D3 MSTATE (R) "Indicates MIC operation state (= AIUMEN)" - VR4111 p451 and VR4102 p416;
   VR4121 p502 states the bit with no such equality. */
constexpr uint16_t kMcntWritable = 0x8002u;
constexpr uint16_t kMcntMstate   = 0x0008u;

/* INTREG: MIC {MENDINTR D11, MINTR D10, MIDLEINTR D9, MSTINTR D8} + SPEAKER
   {SENDINTR D3, SINTR D2, SIDLEINTR D1}, each W1C ("cleared to 0 when 1 is
   written", VR4111 p455 / VR4121 p506 / VR4102 p420). */
constexpr uint16_t kIntCauseMask = 0x0F0Eu;

class Vr41xxAiu : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd) return false;
        const SocFamily soc = bd->GetSoc();
        return soc == SocFamily::VR4102 || soc == SocFamily::VR4111 ||
               soc == SocFamily::VR4121;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        /* SCNTREG, MCNTREG, SEQREG and INTREG carry 0 in both reset rows on every bit
           (VR4111 UM 21.2.4 p448 / 21.2.7 p451 / 21.2.10 p454 / 21.2.11 p455;
           VR4121 UM 21.2.4/21.2.7/21.2.10/21.2.11; VR4102 UM 20.2.4/20.2.7/20.2.10/20.2.11). */
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            seq_  = 0;
            scnt_ = 0;
            mcnt_ = 0;
            int_  = 0;
        });
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint16_t ReadHalf(uint32_t addr) override {
        switch (addr - kBase) {
            case kOffScnt: return scnt_;
            case kOffMcnt: return mcnt_ | ((seq_ & kSeqAiumen) ? kMcntMstate : 0u);
            case kOffSeq:  return seq_;
            case kOffInt:  return int_;
            default: HaltUnsupportedAccess("AIU ReadHalf", addr, 0);
        }
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        switch (addr - kBase) {
            case kOffScnt: scnt_ = value & kScntWritable; return;
            case kOffScnvr: return;
            case kOffMcnt: mcnt_ = value & kMcntWritable; return;
            case kOffSeq:  seq_  = value & kSeqWritable;  return;
            case kOffInt:  int_ &= ~(value & kIntCauseMask); return;
            default: HaltUnsupportedAccess("AIU WriteHalf", addr, value);
        }
    }

    uint8_t  ReadByte (uint32_t addr) override { HaltUnsupportedAccess("AIU ReadByte", addr, 0); }
    uint32_t ReadWord (uint32_t addr) override { HaltUnsupportedAccess("AIU ReadWord", addr, 0); }
    void WriteByte(uint32_t addr, uint8_t  v) override { HaltUnsupportedAccess("AIU WriteByte", addr, v); }
    void WriteWord(uint32_t addr, uint32_t v) override { HaltUnsupportedAccess("AIU WriteWord", addr, v); }

    void SaveState(StateWriter& w) override { w.Write(seq_); w.Write(scnt_); w.Write(mcnt_); w.Write(int_); }
    void RestoreState(StateReader& r) override { r.Read(seq_); r.Read(scnt_); r.Read(mcnt_); r.Read(int_); }

private:
    uint16_t seq_  = 0;   /* SEQREG  (AIURST/AIUMEN/AIUSEN) */
    uint16_t scnt_ = 0;   /* SCNTREG (DAENAIU/SSTOPEN)      */
    uint16_t mcnt_ = 0;   /* MCNTREG (ADENAIU/MSTOPEN)      */
    uint16_t int_  = 0;   /* INTREG  (W1C interrupt status) */
};

}  /* namespace */

REGISTER_SERVICE(Vr41xxAiu);
