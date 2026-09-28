#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../host/guest_deep_sleep.h"
#include "../../state/state_stream.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../jit/guest_cycle_clock.h"
#include "../guest_cpu_reset.h"
#include "sa11xx_core_clock_table.h"
#include "sa11xx_pre_kernel_ppcr.h"
#include "sa11xx_gpio.h"
#include "sa11xx_intc.h"
#include "sa11xx_rtc.h"

namespace {

/* SA-1110 Dev Man §8.1: a 3.6864-MHz crystal feeds the CPU PLL. §8.2
   Table 8-1, both parts: core clock = (16 + 4 x CCF) x that crystal. */
constexpr uint64_t kCrystalHz = 3686400u;

constexpr uint32_t kPwerHardReset = 0x00000003u;
constexpr uint32_t kPwerRtcAlarm  = 1u << 31;
constexpr uint32_t kPwerGpioEdges = 0x0FFFFFFFu;
constexpr uint32_t kPwerWritable  = kPwerRtcAlarm | kPwerGpioEdges;
constexpr uint32_t kIcprRtcAlarm = 1u << 31;
constexpr uint32_t kPssrDh = 1u << 3;
constexpr uint32_t kPssrPh = 1u << 4;

/* SA-1110 Dev Man §8.2.1 (printed 8-3), SA-1100 TRM §8.2.1 (printed 8-2): "an
   interruption in operation for approximately 150 microseconds after the PPCR is
   written"; the power management and RTC "do not see any interruption". */
constexpr uint64_t kPllStopNs = 150000u;

/* SA-1110 Power Manager - Dev Man §9.5.7-9.5.8. PSSR (+0x4) bits 4:0
   are W1C; POSR (+0x1C) bit 0 OOK (32-kHz oscillator stable) reads 1 -
   the emulated oscillator is stable from reset. */

class Sa11xxPowerManager : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        max_ccf_ = emu_.Get<Sa11xxCoreClockTable>().MaxCcf();
        if (auto* seed = emu_.TryGet<Sa11xxPreKernelPpcr>()) {
            seed_ppcr_ = seed->PpcrValue();
        }
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
            if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) {
                pssr_ |= kPssrDh | kPssrPh;
                return;
            }
            if (kind == ResetLineKind::Rtc) ApplyHardResetValues();
        });
        /* §9.5.3 first step a: "loading the power manager GPIO sleep state
           register (PGSR) into the GPIO output data register". */
        emu_.Get<GuestDeepSleep>().RegisterSleepEntryListener([this] {
            emu_.Get<Sa11xxGpio>().LoadSleepOutputs(pgsr_);
        });
        emu_.Get<GuestCpuReset>().RegisterResetReleaseListener([this] { ApplyRate(); });
        ApplyPpcr(seed_ppcr_);
        /* §9.5.7.4 PWER WE31: "1 - Wake-up due to RTC alarm enabled." §9.2.1.1
           Table 9-1: ICPR bit 31 is the RTC alarm. */
        emu_.Get<GuestDeepSleep>().RegisterParkWakeSource([this] {
            return (pwer_ & kPwerRtcAlarm) != 0u &&
                   (emu_.Get<Sa11xxIntc>().GetIcpr() & kIcprRtcAlarm) != 0u;
        });
        emu_.Get<GuestDeepSleep>().RegisterParkWakeDue([this] {
            if ((pwer_ & kPwerRtcAlarm) == 0u) return GuestDeepSleep::kNoParkWake;
            return emu_.Get<Sa11xxRtc>().AlarmWakeDueNs();
        });
        /* §9.5.7.4 PWER WE0..WE27: "1 - Wake-up due to GPIO n edge detect
           enabled." §9.1.1.4: a GEDR status bit can "wake up the SA-1110 from
           sleep mode". */
        emu_.Get<GuestDeepSleep>().RegisterParkWakeSource([this] {
            return (emu_.Get<Sa11xxGpio>().InputEdges() & pwer_ & kPwerGpioEdges) != 0u;
        });
    }

    uint32_t MmioBase() const override { return 0x90020000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;
    uint8_t  ReadByte (uint32_t addr) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override { ApplyRate(); }

private:
    void ApplyPpcr(uint32_t value);
    void ApplyRate();

    /* §9.5.7.1-9.5.7.7 on nRESET: PMCR, PCFR and PPCR clear, PWER = 0x00000003,
       PSSR clears; PSPR is never reset and PGSR is unknown at reset. */
    void ApplyHardResetValues() {
        pcfr_ = 0;
        ppcr_ = seed_ppcr_;
        pwer_ = kPwerHardReset;
        pssr_ = 0;
    }

    uint32_t max_ccf_   = 11;
    uint32_t seed_ppcr_ = 0;

    uint32_t pssr_ = 0;
    uint32_t pspr_ = 0;
    uint32_t pwer_ = kPwerHardReset;
    uint32_t pcfr_ = 0;
    uint32_t ppcr_ = 0;
    uint32_t pgsr_ = 0;

    uint32_t ReadReg(uint32_t off) const;
    void     WriteReg(uint32_t off, uint32_t value);

    static bool IsKnown(uint32_t off) {
        switch (off) {
            case 0x00: case 0x04: case 0x08: case 0x0C:
            case 0x10: case 0x14: case 0x18: case 0x1C:
                return true;
            default:
                return false;
        }
    }
};

uint32_t Sa11xxPowerManager::ReadReg(uint32_t off) const {
    switch (off) {
        case 0x00: return 0u;
        case 0x04: return pssr_ & 0x1Fu;     /* bits 4:0 PH|DH|VFS|BFS|SSS */
        case 0x08: return pspr_;
        case 0x0C: return pwer_;
        case 0x10: return pcfr_;
        case 0x14: return ppcr_;
        case 0x18: return pgsr_ & 0x0FFFFFFFu;  /* bits 27:0 SS27..SS0 */
        case 0x1C: return 0x1u;              /* POSR.OOK always set */
        default:
            emu_.Get<Fatal>().Die("Sa11xxPowerManager: read of unmapped offset +0x%02X", off);
    }
}

void Sa11xxPowerManager::WriteReg(uint32_t off, uint32_t value) {
    switch (off) {
        case 0x00:
            /* §9.5.7.1 PMCR: "The force bit is automatically cleared upon exiting sleep mode";
               "For reserved bits, writes are ignored and reads return zero." */
            if (value & 0x1u) {
                pssr_ |= 0x1u;   /* §9.5.7.5 SSS: sleep entered via the SF bit */
                LOG(SocReset, "[PWRMGR] sleep: pwer=0x%08X icpr=0x%08X\n", pwer_,
                    emu_.Get<Sa11xxIntc>().GetIcpr());
                emu_.Get<GuestDeepSleep>().Enter();
            }
            break;
        case 0x04: pssr_ &= ~(value & 0x1Fu); break;  /* W1C on bits 4:0 */
        case 0x08: pspr_ = value; break;
        case 0x0C: pwer_ = value & kPwerWritable; break;  /* §9.5.7.4: reserved bits ignored */
        case 0x10: pcfr_ = value; break;
        case 0x14:
            ApplyPpcr(value);
            emu_.Get<Sa11xxRtc>().CreditCoreStop(kPllStopNs);
            break;
        case 0x18: pgsr_ = value & 0x0FFFFFFFu; break;
        default:
            emu_.Get<Fatal>().Die("Sa11xxPowerManager: write 0x%08X to +0x%02X, which has no "
                                  "writable register", value, off);
    }
}

void Sa11xxPowerManager::ApplyPpcr(uint32_t value) {
    if ((value & ~0x1Fu) != 0u) {
        emu_.Get<Fatal>().Die("Sa11xxPowerManager: PPCR reserved bits set, value=0x%08X",
                              value);
    }
    if ((value & 0x1Fu) > max_ccf_) {
        emu_.Get<Fatal>().Die("Sa11xxPowerManager: PPCR CCF %u is not a supported core "
                              "clock configuration", value & 0x1Fu);
    }
    ppcr_ = value;
    ApplyRate();
}

void Sa11xxPowerManager::ApplyRate() {
    const uint32_t ccf = ppcr_ & 0x1Fu;
    const uint64_t hz  = (16ull + 4ull * ccf) * kCrystalHz;
    LOG(SocClkpwr, "Sa11xxPowerManager: CCF %u -> core clock %llu Hz\n",
        ccf, static_cast<unsigned long long>(hz));
    emu_.Get<GuestCycleClock>().SetClockHz(hz);
}

uint32_t Sa11xxPowerManager::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return ReadReg(off);
}

void Sa11xxPowerManager::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    WriteReg(off, value);
}

/* ipaq_h3100_ppc2000 nk.exe start 0x800411C4: LDRB R1, [R2,#4] reads PSSR,
   then 0x800411D8 ANDS R3, R1, #2 tests BFS. */
uint8_t Sa11xxPowerManager::ReadByte(uint32_t addr) {
    if (addr != MmioBase() + 0x04u) HaltUnsupportedAccess("ReadByte", addr, 0);
    return static_cast<uint8_t>(ReadReg(0x04u));
}

void Sa11xxPowerManager::SaveState(StateWriter& w) {
    w.Write("pssr", pssr_);
    w.Write("pspr", pspr_);
    w.Write("pwer", pwer_);
    w.Write("pcfr", pcfr_);
    w.Write("ppcr", ppcr_);
    w.Write("pgsr", pgsr_);
}

void Sa11xxPowerManager::RestoreState(StateReader& r) {
    r.Read("pssr", pssr_);
    r.Read("pspr", pspr_);
    r.Read("pwer", pwer_);
    r.Read("pcfr", pcfr_);
    r.Read("ppcr", ppcr_);
    r.Read("pgsr", pgsr_);
    if ((ppcr_ & ~0x1Fu) != 0u || (ppcr_ & 0x1Fu) > max_ccf_) {
        r.Reject("Sa11xxPowerManager: PPCR 0x%08X is not a supported core clock setting", ppcr_);
    }
    if ((pwer_ & ~kPwerWritable) != 0u || (pssr_ & ~0x1Fu) != 0u || (pgsr_ & ~0x0FFFFFFFu) != 0u) {
        r.Reject("Sa11xxPowerManager: PWER 0x%08X, PSSR 0x%08X or PGSR 0x%08X sets reserved bits",
                 pwer_, pssr_, pgsr_);
    }
}

}  /* namespace */

REGISTER_SERVICE(Sa11xxPowerManager);
