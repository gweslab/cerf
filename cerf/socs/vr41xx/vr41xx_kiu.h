#pragma once

#include "../../peripherals/peripheral_base.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

/* KIUSCANREP STPREP[5:0] 000000 is "64 times" on the VR4102 (UM 21.2.2 p425) and RFU on the
   VR4111 (UM 22.2.2 p463) and VR4121 (UM 22.2.2 p514). VR4111 Figure 22-3 p473 and VR4121
   Figure 22-5 p525 carry Notes 1, 2 and 6; VR4102 chapter 21 contains no sequencer figure
   and documents none of those three rules. */
struct Vr41xxKiuModel {
    uint32_t stprep_zero_count;
    bool     scanstart_auto_clear;
    bool     keyen_scanline_interlock;
    bool     keyen_stop_deferred;
    bool     gpen_retained_on_other_reset;
    bool     gpen_survives_kiurst;
};

/* NEC VR41xx KIU (Keyboard Interface Unit): VR4102 UM ch.21, VR4111 UM ch.22, VR4121 UM
   ch.22. Register map: VR4102 Table 21-1, VR4111 Table 22-1 p459, VR4121 Table 22-1. */
class Vr41xxKiu : public Peripheral {
public:
    using Peripheral::Peripheral;

    ~Vr41xxKiu() override { StopWorker(); }
    void OnShutdown() override { StopWorker(); }

    void OnReady() override;

    uint32_t MmioBase() const override { return 0x0B000180u; }
    uint32_t MmioSize() const override { return 0x20u; }

    uint16_t ReadHalf(uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    uint8_t  ReadByte (uint32_t addr) override { HaltUnsupportedAccess("KIU ReadByte", addr, 0); }
    uint32_t ReadWord (uint32_t addr) override { HaltUnsupportedAccess("KIU ReadWord", addr, 0); }
    void WriteByte(uint32_t addr, uint8_t  v) override { HaltUnsupportedAccess("KIU WriteByte", addr, v); }
    void WriteWord(uint32_t addr, uint32_t v) override { HaltUnsupportedAccess("KIU WriteWord", addr, v); }

    /* matrix_index = 16*KIUDATn + bit (0..95) is the KIUDAT0-5 layout storing KSCAN0..11 x
       KPORT[7..0] (VR4111 UM 22.2.1 p461, VR4102 UM 21.2.1 p424, VR4121 UM 22.2.1 p513).
       nec_mobilepro_700_ce2 keybddr.dll sub_15B4848 @0x15B4848 consumes that index into its
       96-entry table at 0x15B0978. */
    void SetKeyState(uint8_t matrix_index, bool pressed);

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

protected:
    virtual const Vr41xxKiuModel& Model() const = 0;

private:
    mutable std::mutex mtx_;

    /* KIUDAT0-5 content; every bit resets to 0 on both rows (VR4111 UM 22.2.1 p460,
       VR4102 UM 21.2.1 p424, VR4121 UM 22.2.1 p512). */
    uint16_t matrix_[6] = {0, 0, 0, 0, 0, 0};
    /* KPORT[7..0] key contact (VR4111 UM 22.2.2 p463 D0 ATSCAN, VR4102 UM 21.2.2 p426
       "the key scan operation automatically starts after key contact is detected",
       VR4121 UM 22.2.2 p514). */
    uint16_t held_[6]   = {0, 0, 0, 0, 0, 0};
    /* KIUSCANREP reset row: D0 ATSCAN = 1, every other bit 0 (VR4111 UM 22.2.2 p463,
       VR4102 UM 21.2.2 p425, VR4121 UM 22.2.2 p514). */
    uint16_t scanrep_   = 0x0001;
    /* KIUINT, both reset rows 0 (VR4111 UM 22.2.6 p468, VR4102 UM 21.2.6 p431,
       VR4121 UM 22.2.6 p520). */
    uint16_t causes_    = 0;
    /* KIUSCANS SSTAT[1:0], reset 00 Stopped (VR4111 UM 22.2.3 p465, VR4102 UM 21.2.3 p427,
       VR4121 UM 22.2.3 p516). */
    uint16_t sstat_     = 0;
    /* KIUWKI WINTVL(9:0) x 30 us, 0 = No Wait, reset rows 0 (VR4111 UM 22.2.5 p467,
       VR4102 UM 21.2.5 p430, VR4121 UM 22.2.5 p519). */
    uint16_t wintvl_    = 0;
    /* KIUWKS T3CNT/T2CNT/T1CNT; D14:0 reset to 1 (VR4111 UM 22.2.4 p466,
       VR4102 UM 21.2.4 p429, VR4121 UM 22.2.4 p518). */
    uint16_t wks_       = 0x7FFF;
    /* SCANLINE LINE[1:0], both reset rows 0 (VR4111 UM 22.2.9 p472, VR4102 UM 21.2.9 p434,
       VR4121 UM 22.2.9 p524). */
    uint16_t scanline_  = 0;
    uint16_t gpen_      = 0;
    /* Scans whose data stayed 0, against KIUSCANREP STPREP[5:0] (VR4111 UM 22.2.2 p463,
       VR4102 UM 21.2.2 p425, VR4121 UM 22.2.2 p514). */
    uint16_t zero_scans_ = 0;
    /* KIUDAT0-5 hold data no read has taken since the last scan stored it (VR4111 UM 22.2.6
       p468 D2 KDATLOST, VR4102 UM 21.2.6 p431, VR4121 UM 22.2.6 p520). */
    bool     data_unread_ = false;
    bool     scan_in_flight_ = false;
    /* KEYEN cleared during a scanning operation stops the sequencer "after that scanning
       operation has completed" (VR4111 UM Figure 22-3 p473 Note 1, VR4121 UM Figure 22-5
       p525 Note 1). */
    bool     stop_after_scan_ = false;
    /* SCANSTART "set to 1 during the interval or scanning mode", the case Note 6 exempts from
       the automatic clear (VR4111 UM Figure 22-3 p473 Note 6, VR4121 UM Figure 22-5 p525
       Note 6). */
    bool     scanstart_set_while_running_ = false;
    /* SCANSTP "set to 1" before the status changes to scanning, which the sequencer reaches
       through waitkeyin from stopped as well; the arc returns to waitkeyin stating no automatic
       clear (VR4111 UM Figure 22-3 p473 Note 3, VR4121 UM Figure 22-5 p525), and the figure-less
       VR4102 states none on 21.2.2 p425 or p426 while its D3 is R/W with reset 0 (p425). */
    bool     scanstp_set_in_waitkeyin_ = false;
    /* End of the scan period or of the KIUWKI interval now in progress (VR4111 UM 22.2.4
       p466 / 22.2.5 p467, VR4102 UM 21.2.4 p429 / 21.2.5 p430, VR4121 UM 22.2.4 p518 /
       22.2.5 p519). */
    std::chrono::steady_clock::time_point phase_end_{};

    bool EnabledLocked() const;
    bool AnyKeyDownLocked();
    uint32_t ScanRegsLocked();
    void LatchScanLocked();
    void BeginScanLocked();
    void EnterWaitKeyInLocked();
    void ReevaluateWaitKeyInLocked();
    void ClearScanStpLocked();
    void CompleteScanLocked();
    void ApplyScanRepLocked();
    void ArmScanLocked(std::chrono::steady_clock::time_point now);
    void AdvancePhaseLocked();
    uint32_t ScanLinesLocked();
    uint32_t ScanPeriodUsLocked();
    uint32_t StpRepCountLocked() const;
    void PublishCausesLocked();
    void ApplyResetLocked();

    std::mutex              cv_mtx_;
    std::condition_variable cv_;
    std::thread             worker_;
    std::atomic<bool>       stop_{false};
    std::atomic<uint64_t>   wake_seq_{0};

    void NotifyWorker();
    void StopWorker();
    void WorkerLoop();
};
