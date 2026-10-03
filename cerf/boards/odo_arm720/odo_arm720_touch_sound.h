#pragma once

#include "../../peripherals/peripheral_base.h"
#include "odo_arm720_pen_timer.h"

#include <cstdint>
#include <mutex>

class Ucb1x00Codec;

class OdoArm720TouchSound : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x1000A000u; }
    uint32_t MmioSize() const override { return 0x20u; }

    uint16_t ReadHalf (uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    bool RaiseSoundStrBits(uint16_t bits);

    void OnPenDown(int host_x, int host_y);
    void OnPenMove(int host_x, int host_y);
    void OnPenUp  ();

    void SetUcbIrqOut(bool asserted);

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

private:
    static const char* SlotName(uint32_t off);
    static uint16_t HostPixelToRaw(int host_v);
    uint16_t SlotRefLocked(uint32_t off, uint16_t*& out_ref);
    void NotifyAudioControlChange(uint16_t old_value, uint16_t new_value);
    void RecomputeTouchAudioIrq();
    bool ShouldTouchAudioBeLiveLocked() const;
    void DoAdcSampleLocked(uint16_t io_adc_cntr_write);
    void TransferUcbRegister(uint16_t value);
    void WriteStatusW1c(uint32_t addr, uint16_t value, uint16_t w1c_mask, uint16_t& reg);
    void CheckModelledBits(uint32_t off, uint16_t value, uint16_t modelled);
    void OnPenTimingPeriod();
    bool PenTimingPending();
    void ResetLine();

    mutable std::mutex state_mutex_;
    uint16_t io_adc_cntr_   = 0;
    uint16_t io_adc_str_    = 0;
    uint16_t ucb_cntr_      = 0;
    uint16_t ucb_str_       = 0;
    uint16_t ucb_register_  = 0;
    uint16_t io_sound_cntr_ = 0;
    uint16_t io_sound_str_  = 0;
    uint16_t intr_mask_     = 0;

    uint16_t adc_x_ = 0;
    uint16_t adc_y_ = 0;

    Ucb1x00Codec*     codec_ = nullptr;
    OdoArm720PenTimer pen_timer_{emu_, [this] { OnPenTimingPeriod(); },
                                 [this] { return PenTimingPending(); }};
};
