#include "../../core/service.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../board_context.h"
#include "nec_mobilepro_900_boot_args.h"
#include "nec_mobilepro_900_id.h"
#include "nec_mobilepro_900_pco_companion.h"
#include "../../cpu/arm_processor_config.h"
#include "../../cpu/emulated_memory.h"
#include "../../jit/arm/arm_cpu.h"
#include "../../peripherals/epson_sed1356/sed1356.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/pxa255/pxa255_clock_manager.h"
#include "../../socs/pxa255/pxa255_ffuart.h"
#include "../../socs/pxa255/pxa255_gpio.h"
#include "../../socs/pxa255/pxa255_power_manager.h"
#include "../../socs/pxa255/pxa255_rtc.h"

#include <cstdint>

namespace {

struct RegWrite {
    uint32_t pa;
    uint32_t value;
};

/* nec_mobilepro_900_ce4_2 SABOOT.NB0 nk.exe sub_9006191C (0x9006191C-0x90061A24):
   GAFR, GPSR, GPCR, GPDR, then GRER/GFER cleared and PSSR <- 0x30. */
constexpr RegWrite kGpioInit[] = {
    {0x40E00054u, 0x80000000u}, {0x40E00058u, 0x590A815Au}, {0x40E0005Cu, 0x609A9559u},
    {0x40E00060u, 0x0005AAAAu}, {0x40E00064u, 0xA0000000u}, {0x40E00068u, 0x00000002u},
    {0x40E00018u, 0x00000000u}, {0x40E0001Cu, 0x04000000u}, {0x40E00020u, 0x00001A06u},
    {0x40E00024u, 0x0C3B1A00u}, {0x40E00028u, 0x18000000u}, {0x40E0002Cu, 0x00000539u},
    {0x40E0000Cu, 0xD3839000u}, {0x40E00010u, 0x1CFFBB83u}, {0x40E00014u, 0x0001C73Fu},
    {0x40E00030u, 0x00000000u}, {0x40E00034u, 0x00000000u}, {0x40E00038u, 0x00000000u},
    {0x40E0003Cu, 0x00000000u}, {0x40E00040u, 0x00000000u}, {0x40E00044u, 0x00000000u},
};

/* nec_mobilepro_900_ce4_2 SABOOT.NB0 nk.exe sub_9006133C 0x90061354-0x900613A0: LCR, IER, DLL and
   DLH under DLAB, LCR, FCR, IER, MCR; then IER |= UUE (0x900613A4-0x900613AC) and the banner at
   0x900613E0, byte by byte to THR (0x900613B0-0x900613D8). */
constexpr RegWrite kFfuartInit[] = {
    {0x4010000Cu, 0x00u}, {0x40100004u, 0x00u}, {0x4010000Cu, 0x80u}, {0x40100000u, 0x08u},
    {0x40100004u, 0x00u}, {0x4010000Cu, 0x00u}, {0x4010000Cu, 0x03u}, {0x40100008u, 0x07u},
    {0x40100004u, 0x00u}, {0x40100010u, 0x00u},
};
/* nec_mobilepro_900_ce4_2 SABOOT.NB0 nk.exe sub_900618A8 0x900618B0-0x900618B4. */
constexpr uint32_t kCpar = 0x2001u;

constexpr uint32_t kFfuartThr = 0x40100000u;
constexpr uint32_t kFfuartIer = 0x40100004u;
constexpr uint32_t kIerUue    = 0x40u;
constexpr char     kBanner[]  = "\n\r\n\rMP900 BSQUARE boot loader\n\r";

constexpr uint32_t kGplr0  = 0x40E00000u;
constexpr uint32_t kGplr2  = 0x40E00008u;
constexpr uint32_t kGpdr0  = 0x40E0000Cu;
constexpr uint32_t kGpsr0  = 0x40E00018u;
constexpr uint32_t kGpcr0  = 0x40E00024u;
constexpr uint32_t kGafr0L = 0x40E00054u;
constexpr uint32_t kPssr   = 0x40F00004u;
constexpr uint32_t kPspr   = 0x40F00008u;
constexpr uint32_t kPedr   = 0x40F00018u;
constexpr uint32_t kRcsr   = 0x40F00030u;
constexpr uint32_t kRcnr   = 0x40900000u;
constexpr uint32_t kRttr   = 0x4090000Cu;
constexpr uint32_t kCccr   = 0x41300000u;

constexpr uint32_t kCauseHwrWdr = 0x3u;
constexpr uint32_t kCauseWdr    = 0x2u;
constexpr uint32_t kCauseSmr    = 0x4u;
constexpr uint32_t kCauseGpr    = 0x8u;

constexpr uint32_t kGpio0           = 1u << 0;
constexpr uint32_t kGpio1           = 1u << 1;
constexpr uint32_t kGpioBatteryDoor = 1u << 6;
constexpr uint32_t kGplr2Gpio77     = 1u << 13;
constexpr uint32_t kPedrRtc         = 0x80000000u;
constexpr uint32_t kPedrGpio10      = 0x00000400u;

constexpr uint32_t kArgsBasePa          = 0xA0004000u;
constexpr uint32_t kSaveBlockPa         = 0xA0005000u;
constexpr uint32_t kSaveBlockWords      = 0x25u;
constexpr uint32_t kBootStateLaunched   = 2u;
constexpr uint32_t kDisplayMode640x240  = 2u;
constexpr uint32_t kCoreMhz             = 400u;
constexpr uint32_t kBatteryMask         = 0x3FFu;
constexpr uint32_t kAlarmBatteryFloor   = 0x15Eu;
constexpr uint32_t kSuspendBatteryLimit = 0x240u;
constexpr uint32_t kHardBootBadChecksum = 0x40F00008u;
constexpr uint32_t kConfigBlockVa       = 0x90160004u;
constexpr uint32_t kKeyStatusByte       = 12u;
constexpr uint8_t  kKeyStatusNoFlag     = 0x40u;

/* nec_mobilepro_900_ce4_2 SABOOT.NB0 nk.exe sub_9006AF28 "Cold boot detected" block; the OS
   reads the same words in the XIP.BIN nk.exe of nec_mobilepro_900_ce4_2 (sub_9023AE20,
   OEMIoControl 0x3072 sub_9023A178) and nec_mobilepro_900_hpc2000 (sub_840BAAB0, sub_840BA1AC). */
constexpr uint32_t kBootFlagsPa      = 0xA001E7E8u;
constexpr uint32_t kBootFlagsCold    = 0xC01Du;
constexpr uint32_t kRamImageEntryPa  = 0xA001E814u;
constexpr uint32_t kOemIoctlWordPa   = 0xA001E7F4u;
constexpr uint32_t kOemIoctlWordCold = 0x00F00F00u;
constexpr uint32_t kStackTopWordPa   = 0xA0004FFCu;
constexpr uint32_t kStackTopWordCold = 0x000F0000u;

constexpr uint32_t kSedPowerSaveConfig = 0x1F0u;
constexpr uint32_t kSedGpioControl     = 0x008u;
constexpr uint32_t kSedLcdDisplayMode  = 0x040u;
constexpr uint32_t kSedDisplayMode     = 0x1FCu;

class NecMobilepro900Saboot : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NecMobilepro900;
    }

    void OnReady() override {
        layout_ = &emu_.Get<NecMobilepro900BootArgs>().Layout();
        Boot(false);
        emu_.Get<GuestCpuReset>().RegisterResetReleaseListener([this] { Boot(true); });
    }

private:
    uint32_t Ram(uint32_t pa) { return emu_.Get<EmulatedMemory>().ReadWord(pa); }
    void SetRam(uint32_t pa, uint32_t v) { emu_.Get<EmulatedMemory>().WriteWord(pa, v); }
    uint32_t Gpio(uint32_t pa) { return emu_.Get<Pxa255Gpio>().ReadWord(pa); }
    void SetGpio(uint32_t pa, uint32_t v) { emu_.Get<Pxa255Gpio>().WriteWord(pa, v); }
    uint32_t Pm(uint32_t pa) { return emu_.Get<Pxa255PowerManager>().ReadWord(pa); }
    void SetPm(uint32_t pa, uint32_t v) { emu_.Get<Pxa255PowerManager>().WriteWord(pa, v); }
    uint32_t Battery() {
        return emu_.Get<NecMobilePro900PcoCompanion>().MainBatteryRaw() & kBatteryMask;
    }

    /* StartUp 0x90061178-0x90061194, sub_900618A8 (0x90061900-0x9006190C), sub_9006191C,
       sub_90061B94 (0x90061B94-0x90061BD4), then sub_900614B8. */
    void Boot(bool board_inputs_driven) {
        board_inputs_driven_ = board_inputs_driven;
        if (layout_->sets_cpar) emu_.Get<ArmCpu>().SetResetCoprocessorAccess(kCpar);
        const uint32_t cause = Pm(kRcsr) & 0xFFu;
        if ((cause & kCauseSmr) != 0u && (Pm(kPedr) & kPedrGpio10) != 0u) {
            emu_.Get<Fatal>().Die("NEC 900 SABOOT stand-in: a GPIO 10 sleep wake, which SABOOT "
                                  "sends straight back to sleep; not modelled");
        }
        SetPm(kRcsr, 0xFu);
        for (const RegWrite& w : kGpioInit) SetGpio(w.pa, w.value);
        SetPm(kPssr, 0x30u);
        if ((cause & kCauseHwrWdr) != 0u) {
            auto& rtc = emu_.Get<Pxa255Rtc>();
            rtc.WriteWord(kRttr, 0x80008001u);
            rtc.WriteWord(kRcnr, 0u);
        }
        if ((emu_.Get<ArmProcessorConfig>().Midr() & 0x1C0Fu) != 0x802u) {
            emu_.Get<Pxa255ClockManager>().SetOscillatorStable();
        }
        if (layout_->inits_ffuart) InitFfuart();
        Decide(SaveCause(cause));
    }

    void InitFfuart() {
        auto& uart = emu_.Get<Pxa255Ffuart>();
        for (const RegWrite& w : kFfuartInit) uart.WriteWord(w.pa, w.value);
        uart.WriteWord(kFfuartIer, uart.ReadWord(kFfuartIer) | kIerUue);
        for (const char* p = kBanner; *p != '\0'; ++p) {
            uart.WriteByte(kFfuartThr, static_cast<uint8_t>(*p));
        }
    }

    /* sub_9007DC4C */
    uint32_t SaveCause(uint32_t cause) {
        const auto& l = *layout_;
        if ((cause & kCauseSmr) == 0u) {
            SetRam(l.reset_cause_pa, cause);
            return cause;
        }
        const uint32_t saved = Ram(l.reset_cause_pa);
        if (saved != 0u) return saved;
        if (Ram(l.boot_state_pa) == kBootStateLaunched) {
            SetRam(l.reset_cause_pa, cause);
            return cause;
        }
        SetRam(l.reset_cause_pa, 0u);
        return kCauseGpr;
    }

    /* sub_900614B8 0x90061518-0x90061578, 0x9006164C-0x9006168C */
    void Decide(uint32_t r10) {
        const auto& l = *layout_;
        if ((Pm(kPedr) & (kPedrRtc | kPedrGpio10)) != 0u) {
            ClockBoot();
            return;
        }
        if ((Gpio(kGplr0) & kGpioBatteryDoor) != 0u && (r10 & kCauseSmr) != 0u) {
            if (l.has_low_battery_flag && Ram(l.low_battery_pa) != 0u) {
                ClockBoot();
                return;
            }
            SetRam(l.reset_cause_pa, 0u);
            if (!ResumeFromSaveBlock()) HardBoot(r10, kHardBootBadChecksum);
            return;
        }
        const uint32_t request = Ram(l.hard_boot_request_pa);
        SetRam(l.hard_boot_request_pa, 0u);
        SetRam(l.hard_boot_code_pa, request);
        if (request != 0u) {
            HardBoot(r10, request);
            return;
        }
        if ((r10 & (kCauseGpr | kCauseSmr)) != 0u) {
            ClockBoot();
            return;
        }
        HardBoot(r10, 0u);
    }

    /* 0x900615AC-0x900615E4 */
    void HardBoot(uint32_t r10, uint32_t code) {
        const auto& l = *layout_;
        for (uint32_t off = 0; off < l.cleared_bytes; off += 4u) SetRam(kArgsBasePa + off, 0u);
        SetRam(l.hard_boot_code_pa, code);
        if (l.hard_boot_restores_watchdog_cause && (r10 & kCauseWdr) != 0u) {
            SetRam(l.reset_cause_pa, r10);
        }
        Main();
    }

    /* 0x900615E8: sub_90061C7C, then main */
    void ClockBoot() {
        ProgramCoreClock();
        Main();
    }

    /* sub_9006D050 (GPIO 0, key status, sub_9006D324), then main sub_9006AF28 */
    void Main() {
        const auto& l = *layout_;
        SetGpio(kGpsr0, kGpio0);
        SetGpio(kGpdr0, Gpio(kGpdr0) | kGpio0);
        auto& pco = emu_.Get<NecMobilePro900PcoCompanion>();
        const uint8_t k7 = pco.KeyMatrixByte(7), k8 = pco.KeyMatrixByte(8), k9 = pco.KeyMatrixByte(9);
        if (((k8 & 8u) == 0u && (k9 & 4u) == 0u) || ((k7 & 8u) == 0u && (k8 & 8u) == 0u)) {
            emu_.Get<Fatal>().Die("NEC 900 SABOOT stand-in: a boot key combination held (keys "
                                  "%02X %02X %02X) selects SABOOT's flash or CF boot; not "
                                  "modelled", k7, k8, k9);
        }
        SetRam(l.display_mode_pa, kDisplayMode640x240);
        SetRam(l.core_mhz_pa, kCoreMhz);
        bool restore_gpio1 = true;
        if (Ram(l.boot_state_pa) == 0u && (Ram(l.reset_cause_pa) & kCauseWdr) == 0u) {
            SetRam(l.boot_state_pa, 1u);
            if (board_inputs_driven_ && (Gpio(kGplr0) & kGpio1) != 0u) {
                emu_.Get<Fatal>().Die("NEC 900 SABOOT stand-in: GPIO 1 high at a hard reset "
                                      "(SABOOT's \"Power Button Down!\"); SABOOT's wait for its "
                                      "release is not modelled");
            }
            restore_gpio1 = false;
        }
        if (l.has_main_status_words) SetRam(l.config_block_pointer_pa, kConfigBlockVa);
        const uint32_t cause = Ram(l.reset_cause_pa);
        if ((cause & kCauseSmr) != 0u) {
            uint32_t key_flag = 0u;
            if ((Pm(kPedr) & kPedrRtc) != 0u) {
                if (Battery() < kAlarmBatteryFloor) {
                    emu_.Get<Fatal>().Die("NEC 900 SABOOT stand-in: battery 0x%03X below 0x15E "
                                          "on an alarm wake; SABOOT's return to sleep is not "
                                          "modelled", Battery());
                }
                key_flag = (pco.KeyMatrixByte(kKeyStatusByte) & kKeyStatusNoFlag) != 0u ? 0u : 1u;
            }
            if (l.has_main_status_words) SetRam(l.sleep_boot_key_flag_pa, key_flag);
        }
        if (board_inputs_driven_ && (Gpio(kGplr0) & kGpioBatteryDoor) == 0u) {
            emu_.Get<Fatal>().Die("NEC 900 SABOOT stand-in: battery door open; SABOOT's "
                                  "door wait and sleep are not modelled");
        }
        if (l.has_low_battery_flag && Ram(l.low_battery_pa) != 0u) {
            if ((Gpio(kGplr2) & kGplr2Gpio77) == 0u && Battery() <= kSuspendBatteryLimit) {
                emu_.Get<Fatal>().Die("NEC 900 SABOOT stand-in: battery 0x%03X off AC with the "
                                      "low-battery flag set; SABOOT's suspend is not modelled",
                                      Battery());
            }
            SetRam(l.low_battery_pa, 0u);
        }
        SetRam(l.boot_state_pa, kBootStateLaunched);
        if ((cause & kCauseSmr) != 0u) {
            SleepBoot();
            return;
        }
        SetRam(l.reset_cause_pa, 0u);
        if ((Gpio(kGplr0) & kGpio1) == 0u) PowerSaveDisplay();
        if (restore_gpio1) {
            SetGpio(kGpdr0, Gpio(kGpdr0) | kGpio1);
            SetGpio(kGpsr0, kGpio1);
            SetGpio(kGafr0L, (Gpio(kGafr0L) & ~0xCu) | 0x4u);
            SetGpio(kGpdr0, Gpio(kGpdr0) & ~kGpio1);
        }
        ProgramCoreClock();
        MarkColdBoot();
    }

    /* sub_9006D9F8 (0x9006D9F8-0x9006DA94): halfword accesses */
    void PowerSaveDisplay() {
        auto& sed = emu_.Get<Sed1356>();
        const uint32_t base = sed.MmioBase();
        auto update = [&](uint32_t reg, uint16_t clear, uint16_t set) {
            const uint16_t v = sed.ReadHalf(base + reg);
            sed.WriteHalf(base + reg, static_cast<uint16_t>((v & ~clear) | set));
        };
        sed.WriteHalf(base + kSedDisplayMode, 0u);
        update(kSedGpioControl, 0x10u, 0u);
        update(kSedLcdDisplayMode, 0u, 0x80u);
        update(kSedGpioControl, 0x2u, 0u);
        update(kSedGpioControl, 0x4u, 0u);
        update(kSedGpioControl, 0u, 0x1u);
        sed.WriteHalf(base + kSedPowerSaveConfig, 0x11u);
    }

    void MarkColdBoot() {
        const uint32_t flags = Ram(kBootFlagsPa);
        if ((flags & kBootFlagsCold) == kBootFlagsCold) return;
        SetRam(kRamImageEntryPa, 0u);
        SetRam(kOemIoctlWordPa, kOemIoctlWordCold);
        SetRam(kStackTopWordPa, kStackTopWordCold);
        SetRam(kBootFlagsPa, flags | kBootFlagsCold);
    }

    /* sub_90061728 */
    void SleepBoot() {
        SetRam(layout_->reset_cause_pa, 0u);
        if (!ResumeFromSaveBlock()) {
            emu_.Get<Fatal>().Die("NEC 900 SABOOT stand-in: sleep-boot save block checksum "
                                  "mismatch; SABOOT's hard boot from 0x900617EC is not modelled");
        }
    }

    /* 0x90061660-0x900616CC */
    bool ResumeFromSaveBlock() {
        uint32_t sum = 0;
        for (uint32_t i = 0; i < kSaveBlockWords; ++i) sum += Ram(kSaveBlockPa + 4u * i);
        const uint32_t pspr = Pm(kPspr);
        if (sum != pspr) {
            LOG(SocReset, "[DEEPSLEEP] nec900 resume: save block sum 0x%08X != PSPR 0x%08X\n",
                sum, pspr);
            return false;
        }
        const uint32_t pc      = Ram(kSaveBlockPa + 0x00u);
        const uint32_t control = Ram(kSaveBlockPa + 0x04u);
        const uint32_t aux     = Ram(kSaveBlockPa + 0x08u);
        const uint32_t ttb     = Ram(kSaveBlockPa + 0x0Cu);
        const uint32_t dacr    = Ram(kSaveBlockPa + 0x10u);
        auto& cpu = emu_.Get<ArmCpu>();
        cpu.SetPendingResumeMmu(control, ttb, dacr);
        cpu.SetPendingResumeAuxControl(aux);
        cpu.SetPendingResumeVector(pc);
        LOG(SocReset, "[DEEPSLEEP] nec900 resume: pc 0x%08X control 0x%08X aux 0x%08X "
                      "ttb 0x%08X dacr 0x%08X\n", pc, control, aux, ttb, dacr);
        return true;
    }

    /* sub_90061CD8 / sub_90061C7C (0x90061CDC-0x90061D2C) */
    void ProgramCoreClock() {
        const uint32_t mhz = Ram(layout_->core_mhz_pa);
        SetGpio(mhz >= 300u ? kGpcr0 : kGpsr0, 0x20000u);
        uint32_t cccr = 0x20000u;
        if (mhz == 100u) cccr = 0x121u;
        if (mhz == 200u || mhz == 300u) cccr = 0x1C1u;
        if (mhz == 400u) cccr = 0x241u;
        auto& clocks = emu_.Get<Pxa255ClockManager>();
        clocks.WriteWord(kCccr, cccr);
        clocks.WriteClkcfg(mhz >= 300u ? 0x3u : 0x2u);
        LOG(SocReset, "[DEEPSLEEP] nec900 SABOOT clock: %u MHz target, CCCR 0x%03X\n", mhz, cccr);
    }

    const NecMobilepro900BootArgsLayout* layout_ = nullptr;
    bool board_inputs_driven_ = false;
};

}

REGISTER_SERVICE(NecMobilepro900Saboot);
