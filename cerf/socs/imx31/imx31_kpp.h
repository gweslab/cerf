#pragma once

#include "../../jit/guest_cycle_clock.h"
#include "../../jit/host_request_channel.h"
#include "../../peripherals/peripheral_base.h"
#include "../../state/state_stream.h"
#include "../cycle_anchored_counter.h"

#include <cstdint>
#include <mutex>

/* i.MX31 Keypad Port (KPP), PA 0x43FA_8000 - MCIMX31RM Ch 27. Zune front
   controls are a KPP matrix: pyxis_keybd.dll scans 4 cols (KPDR 8-11) x 5 rows
   (KPDR 0-4), key index 5*col+row. SetMatrixKey is the host-input entry. */
class Imx31Kpp : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x43FA8000u; }
    uint32_t MmioSize() const override { return 0x00004000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t value) override;
    uint16_t ReadHalf (uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SetMatrixKey(uint8_t col, uint8_t row, bool pressed);

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

private:
    uint16_t ReadReg16Locked(uint32_t off);
    void     WriteReg16Locked(uint32_t off, uint16_t value);
    uint16_t RowSenseLocked() const;
    bool     AnyEnabledRowLowLocked() const;
    void     EvaluateChainsLocked();
    void     ApplyIrqLocked();
    void     DriveIrqLocked();
    void     ArmSyncLocked(uint64_t now);
    void     ArmEventLocked(uint64_t now);
    void     CaptureDueLocked(uint64_t now);
    void     OnSync();
    void     OnHostKeys();
    void     SetRatio();
    void     Retime();
    void     ResetRegisters();

    mutable std::mutex mtx_;
    uint16_t kpcr_     = 0;
    uint16_t kpsr_     = 0;
    uint16_t kddr_     = 0;
    uint16_t kpdr_col_ = 0xFF00u;
    uint8_t  pressed_[4] = {};
    uint8_t  host_pressed_[4] = {};
    bool     irq_on_   = false;

    GuestCycleClock*        clock_       = nullptr;
    GuestCycleClock::Event* sync_event_  = nullptr;
    HostRequestChannel*     host_requests_ = nullptr;
    CycleAnchoredCounter    ckil_;
    bool                    depress_out_ = false;
    bool                    release_out_ = true;
    bool                    sync_pending_ = false;
    uint16_t                pending_kpsr_ = 0u;
    uint32_t                sync_tick_   = 0u;
    uint32_t                restored_count_ = 0u;
    uint64_t                restored_phase_ = 0u;
    uint64_t                restored_den_   = 1u;
};
