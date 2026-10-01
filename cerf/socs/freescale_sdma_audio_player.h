#pragma once

#define NOMINMAX

#include "../core/service.h"
#include "../host/paced_wave_out.h"
#include "../jit/guest_cycle_clock.h"
#include "freescale_sdma_bus.h"
#include "freescale_sdma_regs.h"

#include <cstdint>
#include <functional>

class FreescaleModuleClocks;
class FreescaleSsiTransmitter;
class FreescaleTimerClocks;
class StateWriter;
class StateReader;
enum class FreescaleLowPowerMode : uint8_t;

struct FreescaleAudioFormat {
    uint32_t rate_hz  = 0;
    uint16_t channels = 0;
    uint16_t bits     = 0;
};

class FreescaleSdmaAudioPlayer : public Service, public FreescaleSdmaChannelSink {
public:
    using Service::Service;

    void OnReady() override;
    void OnShutdown() override;

    bool ClaimChannel(const FreescaleSdmaChannelStart& start) override;
    void ReleaseChannel(uint32_t channel) override;
    void SaveSinkState(StateWriter& w) override;
    void RestoreSinkState(StateReader& r) override;
    void PostRestoreSink() override;

protected:
    virtual FreescaleSdmaChannelHost& Sdma() = 0;
    virtual bool TxEventSsi(int event, uint32_t& ssi) const = 0;
    virtual FreescaleAudioFormat StreamFormat(uint32_t ssi) = 0;
    virtual FreescaleSsiTransmitter& Transmitter(uint32_t ssi) = 0;
    virtual void RegisterTxSources(std::function<void()> on_write) = 0;
    virtual const char* LogTag() const = 0;

private:
    static constexpr uint32_t kMaxBds = cerf_freescale_sdma_detail::kMaxBdWalk;

    void     ResetLine();
    void     OnTxWrite();
    void     CheckClocks(FreescaleLowPowerMode mode) const;
    void     ApplyFormat();
    uint32_t SampleBytes() const { return format_.bits / 8u; }
    uint32_t FrameBytes() const { return static_cast<uint32_t>(format_.channels) * SampleBytes(); }
    void     StartBd();
    void     QueueSamples(uint32_t buf_pa, uint32_t bytes);
    void     ArmBdEnd();
    void     OnBdEnd();

    GuestCycleClock*             clock_        = nullptr;
    GuestCycleClock::Event*      event_        = nullptr;
    const FreescaleModuleClocks* modules_      = nullptr;
    const FreescaleTimerClocks*  timer_clocks_ = nullptr;
    PacedWaveOut                 out_;
    FreescaleAudioFormat         format_;
    bool                         active_       = false;
    uint32_t                     channel_      = 0;
    uint32_t                     ssi_          = 0;
    uint32_t                     bd_count_     = 0;
    uint32_t                     bd_pas_[kMaxBds] = {};
    uint32_t                     next_bd_      = 0;
    uint32_t                     burst_words_  = 0;
    uint32_t                     bd_words_     = 0;
    uint64_t                     bd_end_words_ = 0;
};
