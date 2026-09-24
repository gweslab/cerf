#pragma once

#include "vr41xx_icu.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/mips/mips_jit.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <cstdint>
#include <mutex>

namespace cerf_vr41xx_icu_detail {

/* VR4121 UM Table 15-1 == VR4102 UM Table 14-1. */
constexpr uint32_t kOffSysint1  = 0x00u;   /* SYSINT1REG   (R)   */
constexpr uint32_t kOffPiuint   = 0x02u;   /* PIUINTREG    (R)   */
constexpr uint32_t kOffAiuint   = 0x04u;   /* AIUINTREG    (R)   */
constexpr uint32_t kOffKiuint   = 0x06u;   /* KIUINTREG    (R)   */
constexpr uint32_t kOffGiuintl  = 0x08u;   /* GIUINTLREG   (R)   */
constexpr uint32_t kOffDsiuint  = 0x0Au;   /* DSIUINTREG   (R)   */
constexpr uint32_t kOffMsysint1 = 0x0Cu;   /* MSYSINT1REG  (R/W) */
constexpr uint32_t kOffMpiu     = 0x0Eu;
constexpr uint32_t kOffMaiu     = 0x10u;
constexpr uint32_t kOffMkiu     = 0x12u;
constexpr uint32_t kOffMgiul    = 0x14u;
constexpr uint32_t kOffMdsiu    = 0x16u;
constexpr uint32_t kOffNmireg   = 0x18u;   /* NMIREG       (R/W) */
constexpr uint32_t kOffSoftint  = 0x1Au;   /* SOFTINTREG   (R/W) */

constexpr uint32_t kOffSysint2  = 0x00u;   /* SYSINT2REG   (R)   */
constexpr uint32_t kOffGiuinth  = 0x02u;   /* GIUINTHREG   (R)   */
constexpr uint32_t kOffFirint   = 0x04u;   /* FIRINTREG    (R)   */
constexpr uint32_t kOffMsysint2 = 0x06u;   /* MSYSINT2REG  (R/W) */
constexpr uint32_t kOffMgiuh    = 0x08u;
constexpr uint32_t kOffMfir     = 0x0Au;

/* SYSINT1REG bits whose source is a Level-2 register, so the ICU computes them from
   that register AND its mask (VR4121 UM 15.2.1 == VR4102 UM 14.2.1). */
constexpr uint16_t kS1Piu  = 1u << 5;    /* PIUINTR  <- PIUINTREG  & MPIUINTREG  */
constexpr uint16_t kS1Aiu  = 1u << 6;    /* AIUINTR  <- AIUINTREG  & MAIUINTREG  */
constexpr uint16_t kS1Kiu  = 1u << 7;    /* KIUINTR  <- KIUINTREG  & MKIUINTREG  */
constexpr uint16_t kS1Giu  = 1u << 8;    /* GIUINTR  <- GIUINTLREG & MGIUINTLREG
                                            | GIUINTHREG & MGIUINTHREG            */
constexpr uint16_t kS1Soft = 1u << 11;   /* SOFTINTR "occurs by setting the SOFTINTREG" */
constexpr uint16_t kS2Fir  = 1u << 4;    /* FIRINTR  <- FIRINTREG  & MFIRINTREG  */
constexpr uint16_t kS2Dsiu = 1u << 5;    /* DSIUINTR <- DSIUINTREG & MDSIUINTREG */

/* The SYSINT bits the CPU core takes on a dedicated line: "NMI: battint_intr only /
   Int3: hsp_intr only / Int2: rtc_long2_intr only / Int1: rtc_long1_intr only / Int0:
   All other interrupts" (VR4121 UM 15.1, VR4102 UM 14.1). */
constexpr uint16_t kS1Bat   = 1u << 0;   /* SYSINT1REG D0 BATINTR   */
constexpr uint16_t kS1RtcL1 = 1u << 2;   /* SYSINT1REG D2 RTCL1INTR */
constexpr uint16_t kS2RtcL2 = 1u << 0;   /* SYSINT2REG D0 RTCL2INTR */
constexpr uint16_t kS2Hsp   = 1u << 2;   /* SYSINT2REG D2 HSPINTR   */

/* NMIREG D0 NMIORINT, "Low battery detect interrupt type setting. 1: Int0, 0: NMI"
   (VR4121 UM 15.2.13 == VR4102 UM 14.2.13); D15:1 RFU read 0. */
constexpr uint16_t kNmiOrInt = 1u << 0;

/* SOFTINTREG D3:0 SOFTINTR(3:0) R/W, "1: Set, 0: Clear" (VR4121 UM 15.2.14 ==
   VR4102 UM 14.2.14); D15:4 RFU read 0. */
constexpr uint16_t kSoftWritable = 0x000Fu;

/* Int0..Int3 -> Cause.IP2..IP5 = Cause bits 10..13 (VR4121 UM Fig 10-2). */
constexpr uint32_t kIp2 = 1u << 10;
constexpr uint32_t kIp3 = 1u << 11;
constexpr uint32_t kIp4 = 1u << 12;
constexpr uint32_t kIp5 = 1u << 13;

struct Vr41xxIcuModel {
    uint32_t base1;
    uint32_t size1;
    uint32_t base2;
    uint32_t size2;
    uint16_t s1_direct;        /* SYSINT1REG bits with no Level-2 register */
    uint16_t s2_direct;        /* SYSINT2REG bits with no Level-2 register */
    uint16_t dsiu_fixed_read;  /* DSIUINTREG bits reading back 1 */

    /* MxxxINTREG R/W bits; the rest are Reserved/RFU "R", "Write 0 to these bits. 0 is
       returned after a read" (VR4111 UM 15.2.7-15.2.12, 15.2.18-15.2.20; VR4102 UM
       14.2.7-14.2.12, 14.2.18-14.2.20; VR4131 UM 11.2.4-11.2.6, 11.2.12-11.2.14). */
    uint16_t msysint1_writable;
    uint16_t mpiu_writable;
    uint16_t maiu_writable;
    uint16_t mkiu_writable;
    uint16_t mgiul_writable;
    uint16_t mdsiu_writable;
    uint16_t msysint2_writable;
    uint16_t mgiuh_writable;
    uint16_t mfir_writable;
};

template <const std::string_view& Soc, Vr41xxIcuModel M>
class Vr41xxIcuBase : public Vr41xxIcu {
public:
    using Vr41xxIcu::Vr41xxIcu;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == Soc;
    }

    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            std::lock_guard<std::mutex> lk(mtx_);
            ApplyResetLocked();
        });
    }

    uint32_t MmioBase() const override { return M.base1; }
    uint32_t MmioSize() const override { return M.size1; }
    uint32_t Icu2Base() const override { return M.base2; }
    uint32_t Icu2Size() const override { return M.size2; }

    uint16_t ReadHalf(uint32_t addr) override {
        std::lock_guard<std::mutex> lk(mtx_);
        switch (addr - M.base1) {
            case kOffSysint1:  return ComputeSysint1Locked();
            case kOffPiuint:   return piuint_;
            case kOffAiuint:   return aiuint_;
            case kOffKiuint:   return kiuint_;
            case kOffGiuintl:  return giuintl_;
            case kOffDsiuint:  return static_cast<uint16_t>(dsiuint_ | M.dsiu_fixed_read);
            case kOffMsysint1: return msysint1_;
            case kOffMpiu:     return mpiu_;
            case kOffMaiu:     return maiu_;
            case kOffMkiu:     return mkiu_;
            case kOffMgiul:    return mgiul_;
            case kOffMdsiu:    return mdsiu_;
            case kOffNmireg:   return nmireg_;
            case kOffSoftint:  return softint_;
            default: return Peripheral::ReadHalf(addr);
        }
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        std::lock_guard<std::mutex> lk(mtx_);
        switch (addr - M.base1) {
            /* "R" (VR4121 UM Table 15-1, VR4102 UM Table 14-1), and SYSINT1REG's bit
               table prescribes writing 0 to its RFU bits, "0 is returned after a read"
               (VR4121 UM 15.2.1, VR4102 UM 14.2.1): the write is inert. */
            case kOffSysint1: case kOffPiuint: case kOffAiuint: case kOffKiuint:
            case kOffGiuintl: case kOffDsiuint:
                return;
            case kOffMsysint1: msysint1_ = Masked(value, M.msysint1_writable); RecomputeLocked(); return;
            case kOffMpiu:     mpiu_     = Masked(value, M.mpiu_writable);     RecomputeLocked(); return;
            case kOffMaiu:     maiu_     = Masked(value, M.maiu_writable);     RecomputeLocked(); return;
            case kOffMkiu:     mkiu_     = Masked(value, M.mkiu_writable);     RecomputeLocked(); return;
            case kOffMgiul:    mgiul_    = Masked(value, M.mgiul_writable);    RecomputeLocked(); return;
            case kOffMdsiu:    mdsiu_    = Masked(value, M.mdsiu_writable);    RecomputeLocked(); return;
            case kOffNmireg:
                nmireg_  = static_cast<uint16_t>(value & kNmiOrInt);
                RecomputeLocked();
                return;
            case kOffSoftint:
                softint_ = static_cast<uint16_t>(value & kSoftWritable);
                RecomputeLocked();
                return;
            default: Peripheral::WriteHalf(addr, value); return;
        }
    }

    uint16_t ReadHalf2(uint32_t off) override {
        std::lock_guard<std::mutex> lk(mtx_);
        switch (off) {
            case kOffSysint2:  return ComputeSysint2Locked();
            case kOffGiuinth:  return giuinth_;
            case kOffFirint:   return firint_;
            case kOffMsysint2: return msysint2_;
            case kOffMgiuh:    return mgiuh_;
            case kOffMfir:     return mfir_;
            default: return ReadHalf2Ext(off);
        }
    }

    void WriteHalf2(uint32_t off, uint16_t value) override {
        std::lock_guard<std::mutex> lk(mtx_);
        switch (off) {
            /* "R" (VR4121 UM Table 15-1, VR4102 UM Table 14-1), and SYSINT2REG's bit
               table prescribes writing 0 to D15:6, "0 is returned after a read"
               (VR4121 UM 15.2.15, VR4102 UM 14.2.15): the write is inert. */
            case kOffSysint2: case kOffGiuinth: case kOffFirint:
                return;
            case kOffMsysint2: msysint2_ = Masked(value, M.msysint2_writable); RecomputeLocked(); return;
            case kOffMgiuh:    mgiuh_    = Masked(value, M.mgiuh_writable);    RecomputeLocked(); return;
            case kOffMfir:     mfir_     = Masked(value, M.mfir_writable);     RecomputeLocked(); return;
            default: WriteHalf2Ext(off, value); return;
        }
    }

    void SetSysint1Source(uint16_t bit, bool level) override {
        std::lock_guard<std::mutex> lk(mtx_);
        if (level) sysint1_direct_ |= bit;
        else       sysint1_direct_ = static_cast<uint16_t>(sysint1_direct_ & ~bit);
        RecomputeLocked();
    }
    void SetSysint2Source(uint16_t bit, bool level) override {
        std::lock_guard<std::mutex> lk(mtx_);
        if (level) sysint2_direct_ |= bit;
        else       sysint2_direct_ = static_cast<uint16_t>(sysint2_direct_ & ~bit);
        RecomputeLocked();
    }
    void SetGiuLow(uint16_t bits) override {
        std::lock_guard<std::mutex> lk(mtx_);
        giuintl_ = bits;
        RecomputeLocked();
    }
    void SetGiuHigh(uint16_t bits) override {
        std::lock_guard<std::mutex> lk(mtx_);
        giuinth_ = bits;
        RecomputeLocked();
    }
    void SetPiuSource(uint16_t bits) override {
        std::lock_guard<std::mutex> lk(mtx_);
        piuint_ = bits;
        RecomputeLocked();
    }
    void SetKiuSource(uint16_t bits) override {
        std::lock_guard<std::mutex> lk(mtx_);
        kiuint_ = bits;
        RecomputeLocked();
    }
    void SetDsiuSource(uint16_t bits) override {
        std::lock_guard<std::mutex> lk(mtx_);
        dsiuint_ = bits;
        RecomputeLocked();
    }

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(mtx_);
        w.Write("giuintl", giuintl_); w.Write("giuinth", giuinth_); w.Write("piuint", piuint_); w.Write("aiuint", aiuint_);
        w.Write("kiuint", kiuint_);  w.Write("dsiuint", dsiuint_); w.Write("firint", firint_);
        w.Write("mgiul", mgiul_);   w.Write("mgiuh", mgiuh_);   w.Write("mpiu", mpiu_);   w.Write("maiu", maiu_);
        w.Write("mkiu", mkiu_);    w.Write("mdsiu", mdsiu_);   w.Write("mfir", mfir_);
        w.Write("sysint1_direct", sysint1_direct_); w.Write("sysint2_direct", sysint2_direct_);
        w.Write("msysint1", msysint1_); w.Write("msysint2", msysint2_); w.Write("nmireg", nmireg_); w.Write("softint", softint_);
        SaveStateExtLocked(w);
    }

    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(mtx_);
        r.Read("giuintl", giuintl_); r.Read("giuinth", giuinth_); r.Read("piuint", piuint_); r.Read("aiuint", aiuint_);
        r.Read("kiuint", kiuint_);  r.Read("dsiuint", dsiuint_); r.Read("firint", firint_);
        r.Read("mgiul", mgiul_);   r.Read("mgiuh", mgiuh_);   r.Read("mpiu", mpiu_);   r.Read("maiu", maiu_);
        r.Read("mkiu", mkiu_);    r.Read("mdsiu", mdsiu_);   r.Read("mfir", mfir_);
        r.Read("sysint1_direct", sysint1_direct_); r.Read("sysint2_direct", sysint2_direct_);
        r.Read("msysint1", msysint1_); r.Read("msysint2", msysint2_); r.Read("nmireg", nmireg_); r.Read("softint", softint_);
        RestoreStateExtLocked(r);
    }

    void PostRestore() override {
        std::lock_guard<std::mutex> lk(mtx_);
        RecomputeLocked();
    }

protected:
    /* VR4131 UM Table 11-1 adds PCIINTREG..MBCUINTREG 0xAC-0xBA over VR4121 UM Table
       15-1 == VR4102 UM Table 14-1; hooks run with mtx_ held (re-locking deadlocks). */
    virtual uint16_t ReadHalf2Ext(uint32_t off) { return Peripheral::ReadHalf(M.base2 + off); }
    virtual void WriteHalf2Ext(uint32_t off, uint16_t value) {
        Peripheral::WriteHalf(M.base2 + off, value);
    }
    virtual void ApplyResetExtLocked() {}
    virtual void SaveStateExtLocked(StateWriter&) {}
    virtual void RestoreStateExtLocked(StateReader&) {}

private:
    static uint16_t Masked(uint16_t value, uint16_t writable) {
        return static_cast<uint16_t>(value & writable);
    }

    /* The ICU's own R/W registers, whose RTCRST and After-reset rows are all 0 (VR4111 UM
       and VR4121 UM 15.2.7-15.2.14, 15.2.18-15.2.20; VR4102 UM 14.2.7-14.2.14,
       14.2.18-14.2.20). The indication registers carry the level each source unit drives
       ("Interrupt to GPIO pin. 1: Occurred", VR4121 UM 15.2.5). */
    void ApplyResetLocked() {
        mgiul_ = 0; mgiuh_ = 0; mpiu_ = 0; maiu_ = 0;
        mkiu_  = 0; mdsiu_ = 0; mfir_ = 0;
        msysint1_ = 0; msysint2_ = 0; nmireg_ = 0; softint_ = 0;
        ApplyResetExtLocked();
        RecomputeLocked();
    }

    uint16_t ComputeSysint1Locked() const {
        uint16_t s = static_cast<uint16_t>(sysint1_direct_ & M.s1_direct);
        if (piuint_ & mpiu_)  s |= kS1Piu;
        if (aiuint_ & maiu_)  s |= kS1Aiu;
        if (kiuint_ & mkiu_)  s |= kS1Kiu;
        if ((giuintl_ & mgiul_) | (giuinth_ & mgiuh_)) s |= kS1Giu;
        if (softint_ & kSoftWritable) s |= kS1Soft;
        return s;
    }

    uint16_t ComputeSysint2Locked() const {
        uint16_t s = static_cast<uint16_t>(sysint2_direct_ & M.s2_direct);
        if (firint_  & mfir_)  s |= kS2Fir;
        if (dsiuint_ & mdsiu_) s |= kS2Dsiu;
        return s;
    }

    void RecomputeLocked() {
        const uint16_t m1 = static_cast<uint16_t>(ComputeSysint1Locked() & msysint1_);
        const uint16_t m2 = static_cast<uint16_t>(ComputeSysint2Locked() & msysint2_);

        uint32_t ip = 0;
        if (m1 & kS1RtcL1) ip |= kIp3;
        if (m2 & kS2RtcL2) ip |= kIp4;
        if (m2 & kS2Hsp)   ip |= kIp5;

        /* NMIREG D0 = 0 routes battint_intr to NMI (VR4121 UM 15.2.13, VR4102 UM
           14.2.13); the MIPS engine implements no NMI delivery. */
        const bool bat = (m1 & kS1Bat) != 0;
        if (bat && !(nmireg_ & kNmiOrInt)) {
            LOG(Caution, "Vr41xxIcu: battint routed to NMI (NMIREG=0x%04X); MIPS NMI "
                         "delivery is not modeled\n", nmireg_);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }

        const uint16_t int0_1 = static_cast<uint16_t>(m1 & ~(kS1Bat | kS1RtcL1));
        const uint16_t int0_2 = static_cast<uint16_t>(m2 & ~(kS2RtcL2 | kS2Hsp));
        if (int0_1 || int0_2 || (bat && (nmireg_ & kNmiOrInt))) ip |= kIp2;

        /* SetExternalInterruptLevel takes the live LEVEL, not a latch, so the full
           recomputed value including 0 is pushed every time (agent_docs/jit.md
           § In-core timer + interrupts). */
        emu_.Get<MipsJit>().SetExternalInterruptLevel(ip);
    }

    mutable std::mutex mtx_;

    /* Level-2 indication registers (R), driven by their source unit, + their masks. */
    uint16_t giuintl_ = 0, giuinth_ = 0, piuint_ = 0, aiuint_ = 0,
             kiuint_  = 0, dsiuint_ = 0, firint_ = 0;
    /* "The initial value is '0', which specifies masking. No interrupt signal is
       supplied to CPU core unless the CPU writes '1' to this register" - the REGICU
       bullet of VR4121 UM 15.1 / VR4102 UM 14.1, for every M* register. */
    uint16_t mgiul_ = 0, mgiuh_ = 0, mpiu_ = 0, maiu_ = 0,
             mkiu_  = 0, mdsiu_ = 0, mfir_ = 0;

    uint16_t sysint1_direct_ = 0, sysint2_direct_ = 0;
    uint16_t msysint1_ = 0, msysint2_ = 0, nmireg_ = 0, softint_ = 0;
};

}  /* namespace cerf_vr41xx_icu_detail */
