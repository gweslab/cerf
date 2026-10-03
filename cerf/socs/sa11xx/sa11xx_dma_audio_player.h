#pragma once

#define NOMINMAX

#include "../../core/service.h"
#include "../../host/paced_wave_out.h"
#include "sa11xx_audio_config.h"
#include "sa11xx_dma_clients.h"

#include <cstdint>
#include <vector>

class Sa11xxDmaAudioPlayer : public Service, public Sa11xxDmaTransmitObserver {
public:
    using Service::Service;

    void OnReady() override;
    void OnShutdown() override;

    void OnTransmitBlock(uint32_t ddar, uint32_t pa, uint32_t bytes,
                         GuestCycleClock::Rate word_rate) override;
    void OnTransmitStop(uint32_t ddar) override;
    void OnTransmitRestored() override;

protected:
    virtual Sa11xxAudioConfig AudioConfig() const = 0;
    virtual bool              OutputMuted() const { return false; }

private:
    bool Matches(uint32_t ddar) const { return (ddar & cfg_.ddar_mask) == cfg_.ddar_value; }

    Sa11xxAudioConfig    cfg_{};
    PacedWaveOut         out_;
    std::vector<uint8_t> block_;
    uint32_t             rate_   = 0;
    bool                 active_ = false;
};
