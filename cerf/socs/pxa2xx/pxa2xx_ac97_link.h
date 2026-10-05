#pragma once

#include "../../core/service.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/ac97_codec.h"
#include "../rated_tick_count.h"

#include <cstdint>
#include <vector>

class StateReader;
class StateWriter;

class Pxa2xxAc97LinkListener {
public:
    virtual ~Pxa2xxAc97LinkListener() = default;
    virtual void OnLinkRun(uint64_t cycle)    = 0;
    virtual void OnLinkStop(uint64_t cycle)   = 0;
    virtual void OnFifoReset(uint64_t cycle, bool cold) = 0;
    virtual void OnCodecWrite(uint64_t cycle) = 0;
    virtual void OnLinkEvent()                = 0;
};

class Pxa2xxAc97Link : public Service, public Ac97FrameSource {
public:
    using Service::Service;

    /* AC '97 Component Specification Revision 2.1 Figure 13 (page 32): BIT_CLK 12.288 MHz, a
       20.8 us (48 kHz) frame; Intel PXA27x Developer's Manual section 13.6.4 (page 13-18): "The
       AC '97 controller divides the AC97_BITCLK by 256 to generate the AC97_SYNC signal". */
    static constexpr uint64_t kBitClockHz   = 12288000u;
    static constexpr uint64_t kBitsPerFrame = 256u;
    static constexpr uint32_t kFrameRateHz  = static_cast<uint32_t>(kBitClockHz / kBitsPerFrame);

    bool ShouldRegister() override;
    void OnReady() override;

    void AddListener(Pxa2xxAc97LinkListener* listener) { listeners_.push_back(listener); }

    bool FrameAt(uint64_t cycle, uint64_t& frame) const override;
    void OnCodecStreamChange() override;

    void     Settle(uint64_t now);
    bool     Running() const { return running_; }
    bool     RequestsEnabled() const { return cold_released_ && !requests_off_; }
    uint64_t FrameIndexAt(uint64_t cycle) const { return bits_.TicksAt(cycle) / kBitsPerFrame; }
    uint64_t CycleOfFrame(uint64_t frame) const { return bits_.CycleOfTick(frame * kBitsPerFrame); }

    void SetColdReset(uint64_t now, bool asserted);
    void SetLinkOff(uint64_t now, bool off, bool discard_fifos);
    bool WarmReset(uint64_t now);
    bool ClockStartPending() const { return start_pending_; }
    bool WarmResetPending() const { return start_pending_ && warm_start_; }

    static bool InCodecWindow(uint32_t off) { return off >= kCodecBase && off < kCodecEnd; }
    uint32_t    CodecWindowRead(uint64_t now, uint32_t off);
    void        CodecWindowWrite(uint64_t now, uint32_t off, uint16_t value);
    bool        ReadCar(uint64_t now);
    void     ClearCar(uint64_t now);

    bool CommandDone(uint64_t now);
    bool StatusDone(uint64_t now);
    bool CodecReady(uint64_t now);
    void ClearDone(uint64_t now, bool command, bool status);

    void ResetLine();
    void Save(StateWriter& w);
    void Restore(StateReader& r);
    void PostRestore();

private:
    enum class Cmd : uint8_t { None = 0, Write = 1, Read = 2 };

    static constexpr uint32_t kCodecBase   = 0x200u;
    static constexpr uint32_t kCodecEnd    = 0x600u;
    static constexpr uint32_t kModemWindow = 0x200u;

    uint32_t PrimaryCodecReg(uint32_t off);
    uint32_t CodecRead(uint64_t now, uint32_t reg);
    void     CodecWrite(uint64_t now, uint32_t reg, uint16_t value);

    void UpdateRun(uint64_t now);
    void AssertColdReset(uint64_t now);
    void     ArmStart(uint64_t now, uint64_t delay_ps, bool warm);
    uint64_t Rescaled(uint64_t at, GuestCycleClock::Rate from, uint64_t now) const;
    void     OnStartEvent();
    uint64_t PsToCycles(uint64_t ps) const;
    uint64_t CyclesToPs(uint64_t cycles) const;
    void FrameCommand(uint64_t now);
    void CompleteCommand(uint64_t at);
    void ArmCommand();
    void OnCpuRate();
    void NotifyEvent();
    void RequireIdle(const char* op, uint32_t reg);

    GuestCycleClock*        clock_    = nullptr;
    GuestCycleClock::Event* cmd_ev_    = nullptr;
    GuestCycleClock::Event* notify_ev_ = nullptr;
    GuestCycleClock::Event* start_ev_  = nullptr;
    GuestCycleClock::Rate   start_rate_;
    GuestCycleClock::Rate   pd_wait_rate_;
    Ac97Codec*              codec_    = nullptr;
    std::vector<Pxa2xxAc97LinkListener*> listeners_;
    RatedTickCount          bits_;

    bool     cold_released_ = false;
    bool     bitclk_        = false;
    bool     off_           = false;
    bool     requests_off_  = false;
    bool     running_       = false;
    bool     ready_         = false;
    Cmd      cmd_           = Cmd::None;
    bool     cmd_framed_    = false;
    uint32_t cmd_reg_       = 0;
    uint16_t cmd_value_     = 0;
    uint64_t cmd_done_bit_  = 0;
    uint16_t latch_         = 0;
    bool     cdone_         = false;
    bool     sdone_         = false;
    bool     caip_          = false;
    bool     start_pending_ = false;
    bool     warm_start_    = false;
    uint64_t start_at_      = 0;
    uint64_t start_left_ps_ = 0;
    bool     pd_wait_       = false;
    uint64_t pd_wait_at_    = 0;
};
