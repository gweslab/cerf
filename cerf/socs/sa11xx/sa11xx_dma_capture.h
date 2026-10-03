#pragma once

#define NOMINMAX

#include "../../core/service.h"
#include "../../host/wave_in_sink.h"
#include "sa11xx_audio_config.h"
#include "sa11xx_dma_clients.h"

#include <atomic>
#include <cstdint>
#include <deque>
#include <mutex>

class Sa11xxDmaCapture : public Service, public Sa11xxDmaReceiveSource {
public:
    using Service::Service;

    void OnReady() override;
    void OnShutdown() override;

    bool FillReceived(uint32_t ddar, uint32_t pa, uint32_t bytes,
                      GuestCycleClock::Rate word_rate) override;

protected:
    virtual Sa11xxAudioConfig AudioConfig() const = 0;

private:
    void OnThreadMessage(const MSG& msg);
    void OpenOnThread();
    void OnRecordedData(const uint8_t* data, uint32_t bytes);

    Sa11xxAudioConfig     cfg_{};
    WaveInSink            sink_;
    std::mutex            mtx_;
    std::deque<uint8_t>   fifo_;
    std::atomic<uint32_t> requested_rate_{0};
    uint32_t              open_rate_ = 0;
};
