#pragma once

#include "../../jit/guest_cycle_clock.h"
#include "../../jit/host_request_channel.h"
#include "../../socs/cycle_anchored_counter.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

class CerfEmulator;
class StateWriter;
class StateReader;

/* touch.dll (CE touch-panel PDD, imgbase 0xF90000): sub_F91DDC @0xF91DDC,
   loc_F91958, loc_F91D40, sub_F92DDC @0xF92DDC; register window in the companion
   at base 0x0A000000. */
class CasioCassiopeiaEm500Touch {
public:
    void Init(CerfEmulator& emu, std::function<void()> on_status_change);

    bool TryReadByte (uint32_t off, uint8_t&  out);
    bool TryWriteByte(uint32_t off, uint8_t   value);
    bool TryReadHalf (uint32_t off, uint16_t& out);
    bool TryWriteHalf(uint32_t off, uint16_t  value);
    bool TryReadWord (uint32_t off, uint32_t& out);
    bool TryWriteWord(uint32_t off, uint32_t  value);

    void SetPen(bool down, int surface_x, int surface_y);
    void OnCaptureLost();

    bool IrqPending() const;

    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);
    void PostRestore();

private:
    struct HostPen {
        bool down;
        int  x;
        int  y;
    };

    void OnHostRequest();
    void OnSampleEvent();
    void OnRateChange();
    void ApplyPenLocked(bool down, int surface_x, int surface_y);
    void SampleLocked();
    void StartSamplingLocked();
    void RescaleSamplesLocked();
    uint64_t SampleHzLocked() const;
    void ArmSampleLocked();
    bool SamplingLocked() const { return pen_down_; }
    void PresentDownLocked();
    void PresentLiftLocked();
    void NotifyStatus();
    /* casio_cassiopeia_em500_ppc2000 touch.dll loc_F91958 @0xF91A38 (0x304 & 1, SYSINTR 24),
       @0xF91A82 (0x304 & 0x18, SYSINTR 17); written back as 1 @0xF91A40-@0xF91A44, @0xF91B48. */
    uint32_t Status() const;
    void     ClearStatus(uint32_t bits);

    CerfEmulator* emu_ = nullptr;

    mutable std::mutex mtx_;

    /* touch.dll sub_F91DDC @0xF91E16/@0xF91E22, loc_F91958 @0xF919BA,
       loc_F91B62 @0xF91B70; nk_main_kernel.exe sub_9F032B60 @0x9F032D30. */
    uint32_t ctrl_300_ = 0;
    /* touch.dll sub_F91DDC @0xF91E2C/@0xF91E34/@0xF91E3C/@0xF91E42. */
    uint32_t param_308_ = 0;
    uint32_t param_30C_ = 0;
    uint32_t param_310_ = 0;
    uint32_t param_318_ = 0;
    /* touch.dll sub_F91DDC @0xF91E02; nk_main_kernel.exe sub_9F032B60 @0x9F032D30. */
    uint32_t cfg_3C8_ = 0;
    /* touch.dll loc_F91D40 @0xF91D4E (mode0 0x320-0x32C) / @0xF91D7E (mode1
       0x350-0x35C); X=(hi[0]-hi[1]+0xFFF)>>1, Y=(hi[2]-hi[3]+0xFFF)>>1, &0xFFF. */
    uint16_t adc0_[4] = {};
    uint16_t adc1_[4] = {};

    uint16_t raw_x_ = 0;
    uint16_t raw_y_ = 0;
    bool     pen_down_ = false;

    std::atomic<bool> sample_pending_{false};
    std::atomic<bool> pen_event_{false};
    /* casio_cassiopeia_em500_ppc2000 nk_main_kernel.exe sub_9F08F334 case17 @0x9F08F388 /
       case24 @0x9F08F3A4, @0x9F033A84 (sw 0); consumed @0x9F036608 (lw 0x304;
       raw & (raw>>8) = pending[7:0] & enable[15:8] cascade demux). */
    std::atomic<uint32_t> int_enable_{0};
    std::function<void()> on_status_change_;

    GuestCycleClock*        clock_        = nullptr;
    GuestCycleClock::Event* sample_event_ = nullptr;
    HostRequestChannel*     host_requests_ = nullptr;
    CycleAnchoredCounter    samples_;
    uint32_t                next_sample_  = 0;
    bool                    sampling_     = false;
    std::vector<HostPen>    host_pen_;
    int                     host_x_       = 0;
    int                     host_y_       = 0;
};
