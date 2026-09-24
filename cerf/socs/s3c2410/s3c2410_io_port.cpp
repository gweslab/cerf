#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../host/guest_deep_sleep.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../irq_controller.h"
#include "s3c2410_eint_source.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <atomic>

namespace {

/* S3C2410A User's Manual Table 1-4 (p. 1-34) places the I/O port block at
   0x56000000 with an access unit of W (word). */
constexpr uint32_t kBase = 0x56000000u;

enum class Kind : uint8_t {
    Rw,
    W1c,
    Absent,
};

struct RegDesc {
    uint32_t writable;
    uint32_t reset;
    Kind     kind;
};

/* S3C2410A UM ch. 9 "Reset Value" and bit-table columns: ports A/B/C/D/E/F/G/H
   pp. 9-8/9-9/9-10/9-12/9-14/9-16/9-17/9-19, MISCCR p. 9-20, DCLKCON p. 9-21,
   EXTINT0/1/2 pp. 9-22/9-23/9-24, EINTFLT p. 9-25, EINTMASK p. 9-26,
   EINTPEND p. 9-27, GSTATUS p. 9-28. */
constexpr RegDesc kRegs[] = {
    /* 0x00 GPACON  */ { 0x007FFFFFu, 0x007FFFFFu, Kind::Rw },
    /* 0x04 GPADAT  */ { 0x007FFFFFu, 0x00000000u, Kind::Rw },
    /* 0x08         */ { 0u, 0u, Kind::Absent },
    /* 0x0C         */ { 0u, 0u, Kind::Absent },
    /* 0x10 GPBCON  */ { 0x003FFFFFu, 0x00000000u, Kind::Rw },
    /* 0x14 GPBDAT  */ { 0x000007FFu, 0x00000000u, Kind::Rw },
    /* 0x18 GPBUP   */ { 0x000007FFu, 0x00000000u, Kind::Rw },
    /* 0x1C         */ { 0u, 0u, Kind::Absent },
    /* 0x20 GPCCON  */ { 0xFFFFFFFFu, 0x00000000u, Kind::Rw },
    /* 0x24 GPCDAT  */ { 0x0000FFFFu, 0x00000000u, Kind::Rw },
    /* 0x28 GPCUP   */ { 0x0000FFFFu, 0x00000000u, Kind::Rw },
    /* 0x2C         */ { 0u, 0u, Kind::Absent },
    /* 0x30 GPDCON  */ { 0xFFFFFFFFu, 0x00000000u, Kind::Rw },
    /* 0x34 GPDDAT  */ { 0x0000FFFFu, 0x00000000u, Kind::Rw },
    /* 0x38 GPDUP   */ { 0x0000FFFFu, 0x0000F000u, Kind::Rw },
    /* 0x3C         */ { 0u, 0u, Kind::Absent },
    /* 0x40 GPECON  */ { 0xFFFFFFFFu, 0x00000000u, Kind::Rw },
    /* 0x44 GPEDAT  */ { 0x0000FFFFu, 0x00000000u, Kind::Rw },
    /* 0x48 GPEUP   */ { 0x0000FFFFu, 0x00000000u, Kind::Rw },
    /* 0x4C         */ { 0u, 0u, Kind::Absent },
    /* 0x50 GPFCON  */ { 0x0000FFFFu, 0x00000000u, Kind::Rw },
    /* 0x54 GPFDAT  */ { 0x000000FFu, 0x00000000u, Kind::Rw },
    /* 0x58 GPFUP   */ { 0x000000FFu, 0x00000000u, Kind::Rw },
    /* 0x5C         */ { 0u, 0u, Kind::Absent },
    /* 0x60 GPGCON  */ { 0xFFFFFFFFu, 0x00000000u, Kind::Rw },
    /* 0x64 GPGDAT  */ { 0x0000FFFFu, 0x00000000u, Kind::Rw },
    /* 0x68 GPGUP   */ { 0x0000FFFFu, 0x0000F800u, Kind::Rw },
    /* 0x6C         */ { 0u, 0u, Kind::Absent },
    /* 0x70 GPHCON  */ { 0x003FFFFFu, 0x00000000u, Kind::Rw },
    /* 0x74 GPHDAT  */ { 0x000007FFu, 0x00000000u, Kind::Rw },
    /* 0x78 GPHUP   */ { 0x000007FFu, 0x00000000u, Kind::Rw },
    /* 0x7C         */ { 0u, 0u, Kind::Absent },
    /* 0x80 MISCCR  */ { 0x000F377Bu, 0x00010330u, Kind::Rw },
    /* 0x84 DCLKCON */ { 0x0FF30FF3u, 0x00000000u, Kind::Rw },
    /* 0x88 EXTINT0 */ { 0x77777777u, 0x00000000u, Kind::Rw },
    /* 0x8C EXTINT1 */ { 0x77777777u, 0x00000000u, Kind::Rw },
    /* 0x90 EXTINT2 */ { 0xFFFFFFFFu, 0x00000000u, Kind::Rw },
    /* 0x94 EINTFLT0*/ { 0xFFFFFFFFu, 0x00000000u, Kind::Rw },
    /* 0x98 EINTFLT1*/ { 0xFFFFFFFFu, 0x00000000u, Kind::Rw },
    /* 0x9C EINTFLT2*/ { 0xFFFFFFFFu, 0x00000000u, Kind::Rw },
    /* 0xA0 EINTFLT3*/ { 0xFFFFFFFFu, 0x00000000u, Kind::Rw },
    /* 0xA4 EINTMASK*/ { 0x00FFFFF0u, 0x00FFFFF0u, Kind::Rw },
    /* 0xA8 EINTPEND*/ { 0x00FFFFF0u, 0x00000000u, Kind::W1c },
    /* 0xAC GSTATUS0*/ { 0u, 0u, Kind::Absent },
    /* 0xB0 GSTATUS1*/ { 0u, 0u, Kind::Absent },
    /* 0xB4 GSTATUS2*/ { 0x00000007u, 0x00000001u, Kind::W1c },
    /* 0xB8 GSTATUS3*/ { 0xFFFFFFFFu, 0x00000000u, Kind::Rw },
    /* 0xBC GSTATUS4*/ { 0xFFFFFFFFu, 0x00000000u, Kind::Rw },
};

constexpr size_t kSlotCount = sizeof(kRegs) / sizeof(kRegs[0]);

constexpr size_t   kGstatus2Slot = 0xB4u / 4u;
constexpr uint32_t kPwrst        = 1u << 0;
constexpr uint32_t kOffrst       = 1u << 1;
constexpr uint32_t kWdtrst       = 1u << 2;

constexpr size_t kExtInt0Slot  = 0x88u / 4u;
constexpr size_t kEintMaskSlot = 0xA4u / 4u;
constexpr size_t kEintPendSlot = 0xA8u / 4u;
constexpr size_t kExtIntSlots  = 3u;

/* S3C2410A UM p. 9-16 GPFCON and p. 9-17 GPGCON: each pin owns a 2-bit
   field at [2n+1:2n] selecting "00 = Input, 01 = Output, 10 = EINTn",
   EINT0-7 on GPF0-7 and EINT8-23 on GPG0-15, both reset 0x0. */
constexpr size_t   kGpfConSlot   = 0x50u / 4u;
constexpr size_t   kGpgConSlot   = 0x60u / 4u;
constexpr uint32_t kPinModeEint  = 0x2u;
constexpr int      kGpgFirstEint = 8;

/* S3C2410A UM p. 14-7: SRCPND EINT0 [0], EINT1 [1], EINT2 [2], EINT3 [3],
   EINT4_7 [4], EINT8_23 [5]. */
constexpr int kEintFirst      = 0;
constexpr int kSrcpndEint4_7  = 4;
constexpr int kSrcpndEint8_23 = 5;

/* S3C2410A UM pp. 9-26/9-27: EINTMASK and EINTPEND serve EINT[23:4]. */
constexpr int kEintPendFirst = 4;
constexpr int kEintLast      = 23;

class S3C2410IoPort : public Peripheral,
                      public ResetCauseLatch,
                      public DeepSleepWaker,
                      public S3C2410EintSink {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::S3c2410;
    }
    void OnReady() override {
        Reset();
        auto& reset = emu_.Get<GuestCpuReset>();
        reset.SetCauseLatch(this);
        reset.RegisterResetListener([this](ResetLineKind) { OnResetLine(); });
        emu_.Get<GuestDeepSleep>().RegisterWaker(this);
        emu_.Get<S3C2410EintSource>().SetSink(this);
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    /* S3C2410A UM p. 9-28: GSTATUS2 reset value is 0x1, the power-on column. */
    void LatchColdReset() override     { StoreSlot(kGstatus2Slot, kPwrst); }
    void LatchWatchdogReset() override { OrSlot(kGstatus2Slot, kWdtrst); }

    /* S3C2410A UM p. 9-28: GSTATUS2 causes are PWRST, OFFRST, WDTRST. p. 9-8
       GPA21: "nRSTOUT = nRESET & nWDTRST & SW_RESET(MISCCR[16])". */
    void LatchWarmReset() override { OrSlot(kGstatus2Slot, kWdtrst); }

    /* S3C2410A UM p. 9-28: GSTATUS2 OFFRST [1] "Power_OFF reset. The reset after
       the wakeup from Power_OFF mode. The setting is cleared by writing 1." */
    void LatchSleepWakeCause() override { OrSlot(kGstatus2Slot, kOffrst); }
    void ClearSleepWakeCause() override { AndSlot(kGstatus2Slot, ~kOffrst); }

    /* S3C2410A UM p. 9-26: EINTMASK 0 = Enable Interrupt, 1 = Masked. p. 9-7:
       a masked EINT[15:4] wakes from Power_OFF but leaves "the EINT4_7 bit and
       EINT8_23 bit of the SRCPND" unset. */
    void DriveEintPin(int eint, bool level) override {
        if (eint < kEintFirst || eint > kEintLast) { HaltEint("DriveEintPin", eint); }
        const uint32_t bit        = 1u << eint;
        OrDriven(bit);
        const uint32_t prev_level = level ? OrLevels(bit) : AndLevels(~bit);
        const bool was = (prev_level & bit) != 0u;
        if (was == level) { return; }
        if (!EintPinSelectsInterrupt(eint)) { return; }
        if (!EintRequests(EintMode(eint), level)) { return; }
        LatchAndPropagateEint(eint);
    }

    /* S3C2410A UM p. 9-22: EXTINTn "configures the signaling method between the
       level trigger and edge trigger", 000 = Low level, 001 = High level.
       UM p. 14-7: SRCPND EINT0 [0], EINT1 [1], EINT2 [2], EINT3 [3]. */
    void ReassertHeldLevelEints(uint32_t cleared_srcpnd) override {
        ReevaluateLevelEints(cleared_srcpnd & ((1u << kEintPendFirst) - 1u));
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return 0x00100000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override {
        w.WriteBytes("storage", storage_, sizeof(storage_));
        w.Write<uint32_t>("levels", LoadLevels());
        w.Write<uint32_t>("driven", LoadDriven());
    }
    void RestoreState(StateReader& r) override {
        r.ReadBytes("storage", storage_, sizeof(storage_));
        uint32_t levels = 0;
        uint32_t driven = 0;
        r.Read("levels", levels);
        r.Read("driven", driven);
        StoreLevels(levels);
        StoreDriven(driven);
    }

private:
    uint32_t LoadSlot(size_t slot) {
        return std::atomic_ref<uint32_t>(storage_[slot]).load(std::memory_order_acquire);
    }
    void StoreSlot(size_t slot, uint32_t value) {
        std::atomic_ref<uint32_t>(storage_[slot]).store(value, std::memory_order_release);
    }
    void OrSlot(size_t slot, uint32_t bits) {
        std::atomic_ref<uint32_t>(storage_[slot]).fetch_or(bits, std::memory_order_acq_rel);
    }
    void AndSlot(size_t slot, uint32_t bits) {
        std::atomic_ref<uint32_t>(storage_[slot]).fetch_and(bits, std::memory_order_acq_rel);
    }

    /* S3C2410A UM p. 9-22: each EXTINTn carries eight 3-bit fields at
       4*(n%8) setting the signalling method of that EINT. */
    uint32_t EintMode(int eint) {
        const uint32_t cfg =
            LoadSlot(kExtInt0Slot + static_cast<size_t>(eint) / 8u);
        return (cfg >> (4u * (static_cast<uint32_t>(eint) % 8u))) & 0x7u;
    }

    /* S3C2410A UM p. 9-7: "port control register (PnCON) determines the
       function of each pin". pp. 9-16/9-17: the pin reaches the external
       interrupt block only while its GPFCON/GPGCON field selects EINTn. */
    bool EintPinSelectsInterrupt(int eint) {
        const bool  on_port_g = eint >= kGpgFirstEint;
        const size_t slot     = on_port_g ? kGpgConSlot : kGpfConSlot;
        const uint32_t shift  =
            2u * static_cast<uint32_t>(on_port_g ? eint - kGpgFirstEint : eint);
        return ((LoadSlot(slot) >> shift) & 0x3u) == kPinModeEint;
    }

    /* S3C2410A UM p. 9-22: each EXTINTn carries the eight EINT fields of one
       eight-pin group, so a write to it re-selects those pins' methods. */
    static uint32_t EintsOfExtIntSlot(size_t slot) {
        const int base = 8 * static_cast<int>(slot - kExtInt0Slot);
        uint32_t mask = 0u;
        for (int e = base; e < base + 8; ++e) {
            if (e >= kEintFirst && e <= kEintLast) { mask |= 1u << e; }
        }
        return mask;
    }

    /* S3C2410A UM p. 9-22: "000 = Low level, 001 = High level,
       01x = Falling edge triggered, 10x = Rising edge triggered,
       11x = Both edge triggered". */
    static bool EintRequests(uint32_t mode, bool level) {
        switch (mode) {
            case 0x0u:            return !level;
            case 0x1u:            return level;
            case 0x2u: case 0x3u: return !level;
            case 0x4u: case 0x5u: return level;
            default:              return true;
        }
    }

    static bool EintIsLevelMode(uint32_t mode) { return mode <= 0x1u; }

    /* S3C2410A UM p. 9-27: EINTPEND carries EINT[23:4]. p. 14-7: EINT[3:0] each
       own an SRCPND bit of the same index. */
    void LatchAndPropagateEint(int eint) {
        if (eint < kEintPendFirst) {
            emu_.Get<IrqController>().AssertIrq(eint);
            return;
        }
        OrSlot(kEintPendSlot, 1u << eint);
        PropagateEint(eint);
    }

    /* S3C2410A UM p. 9-26: EINTMASK 0 = Enable Interrupt, 1 = Masked.
       UM p. 14-7: SRCPND EINT4_7 [4], EINT8_23 [5]. */
    void PropagateEint(int eint) {
        if (((LoadSlot(kEintMaskSlot) >> eint) & 1u) != 0u) { return; }
        emu_.Get<IrqController>().AssertIrq(
            eint <= 7 ? kSrcpndEint4_7 : kSrcpndEint8_23);
    }

    /* S3C2410A UM p. 9-22: 000 and 001 select a LEVEL signalling method, so
       the request stands while the pin holds that level. UM p. 9-7: while
       masked, "the EINT4_7 bit and EINT8_23 bit of the SRCPND" stay unset. */
    void ReevaluateLevelEints(uint32_t candidates) {
        const uint32_t levels = LoadLevels();
        const uint32_t driven = LoadDriven();
        for (int e = kEintFirst; e <= kEintLast; ++e) {
            const uint32_t bit = 1u << e;
            if ((candidates & bit) == 0u) { continue; }
            if ((driven & bit) == 0u) { continue; }
            if (!EintPinSelectsInterrupt(e)) { continue; }
            const uint32_t mode = EintMode(e);
            if (!EintIsLevelMode(mode)) { continue; }
            if (!EintRequests(mode, (levels & bit) != 0u)) { continue; }
            LatchAndPropagateEint(e);
        }
    }

    uint32_t LoadLevels() {
        return std::atomic_ref<uint32_t>(input_level_).load(std::memory_order_acquire);
    }
    void StoreLevels(uint32_t v) {
        std::atomic_ref<uint32_t>(input_level_).store(v, std::memory_order_release);
    }
    uint32_t OrLevels(uint32_t bits) {
        return std::atomic_ref<uint32_t>(input_level_)
            .fetch_or(bits, std::memory_order_acq_rel);
    }
    uint32_t AndLevels(uint32_t bits) {
        return std::atomic_ref<uint32_t>(input_level_)
            .fetch_and(bits, std::memory_order_acq_rel);
    }
    uint32_t OrDriven(uint32_t bits) {
        return std::atomic_ref<uint32_t>(input_driven_)
            .fetch_or(bits, std::memory_order_acq_rel);
    }
    uint32_t LoadDriven() {
        return std::atomic_ref<uint32_t>(input_driven_).load(std::memory_order_acquire);
    }
    void StoreDriven(uint32_t v) {
        std::atomic_ref<uint32_t>(input_driven_).store(v, std::memory_order_release);
    }

    [[noreturn]] void HaltEint(const char* op, int eint) {
        LOG(Caution, "S3C2410IoPort::%s: EINT%d outside EINT[23:0]\n", op, eint);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    void Reset() {
        for (size_t i = 0; i < kSlotCount; ++i) {
            StoreSlot(i, kRegs[i].reset);
        }
    }

    /* S3C2410A UM p. 9-28: GSTATUS3 / GSTATUS4 are "cleared by nRESET or
       watchdog timer"; GSTATUS2 reports which reset occurred. */
    /* S3C2410A UM p. 9-7: "All GPIO register values are preserved in Power_OFF
       mode." p. 7-15 wake steps 3/6/7 read back MISCCR[19:17], GSTATUS3,4 and
       EINTPEND written before entry. */
    void OnResetLine() {
        if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) {
            return;
        }
        for (size_t i = 0; i < kSlotCount; ++i) {
            if (i != kGstatus2Slot) {
                StoreSlot(i, kRegs[i].reset);
            }
        }
    }

    alignas(std::atomic_ref<uint32_t>::required_alignment)
    uint32_t storage_[kSlotCount] = {};

    alignas(std::atomic_ref<uint32_t>::required_alignment)
    uint32_t input_level_ = 0;
    alignas(std::atomic_ref<uint32_t>::required_alignment)
    uint32_t input_driven_ = 0;
};

uint32_t S3C2410IoPort::ReadWord(uint32_t addr) {
    const uint32_t off  = addr - kBase;
    const uint32_t slot = off / 4u;
    if (slot >= kSlotCount || kRegs[slot].kind == Kind::Absent) {
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }
    const uint32_t value = LoadSlot(slot);
#if CERF_DEV_MODE
    LOG(SocIoport, "read  +0x%02X -> 0x%08X\n", off, value);
#endif
    return value;
}

void S3C2410IoPort::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off  = addr - kBase;
    const uint32_t slot = off / 4u;
    if (slot >= kSlotCount) {
        HaltUnsupportedAccess("WriteWord", addr, value);
    }
    const RegDesc& d = kRegs[slot];
    if (d.kind == Kind::Absent) {
        HaltUnsupportedAccess("WriteWord", addr, value);
    }
#if CERF_DEV_MODE
    LOG(SocIoport, "write +0x%02X = 0x%08X\n", off, value);
#endif
    if (d.kind == Kind::W1c) {
        const uint32_t cleared = value & d.writable;
        AndSlot(slot, ~cleared);
        if (slot == kEintPendSlot) { ReevaluateLevelEints(cleared); }
        return;
    }
    const uint32_t before = LoadSlot(slot);
    const uint32_t after  = (before & ~d.writable) | (value & d.writable);
    StoreSlot(slot, after);
    if (slot == kEintMaskSlot) {
        ReevaluateLevelEints(before & ~after);
    } else if (slot >= kExtInt0Slot && slot < kExtInt0Slot + kExtIntSlots) {
        ReevaluateLevelEints(EintsOfExtIntSlot(slot));
    } else if (slot == kGpfConSlot || slot == kGpgConSlot) {
        ReevaluateLevelEints(EintsOfExtIntSlot(kExtInt0Slot) |
                             EintsOfExtIntSlot(kExtInt0Slot + 1u) |
                             EintsOfExtIntSlot(kExtInt0Slot + 2u));
    }
}

}  /* namespace */

REGISTER_SERVICE(S3C2410IoPort);
