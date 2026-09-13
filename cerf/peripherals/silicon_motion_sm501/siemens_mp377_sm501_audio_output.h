#pragma once

#include "../../core/service.h"
#include "../../host/paced_wave_out.h"

#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

class StateReader;
class StateWriter;

namespace siemens_mp377 {

// SM501 Databook ch. 11; siemens_mp377_v1040 VGXaudio.dll sub_2987AAC.
class SiemensMp377Sm501AudioOutput : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;
    void OnShutdown() override;

    void QueueAc97PcmSample(uint32_t left20, uint32_t right20);
    void HandleDacPowerDown();
    void SetPlaybackEnabled(bool enabled);
    void SetCaptureEnabled(bool enabled);

    std::unique_lock<std::mutex> LockForState();
    void SetPacerEnabled(bool enabled);
    void SaveState(StateWriter& writer);
    void RestoreState(StateReader& reader);

private:
    static constexpr uint32_t kDefaultRateHz = 48000u;
    static constexpr uint32_t kFramesPerFirmwareHalf = 192u;
    static constexpr uint32_t kHostPacketFrames = kFramesPerFirmwareHalf;
    static constexpr uint32_t kHostPacketBytes = kHostPacketFrames * 4u;

    void ResetDevice();
    std::chrono::microseconds BlockPeriod() const;
    void StartPacer();
    void StopPacer();
    void PacerLoop();
    void ServiceClockTick();
    void ServiceCompletions();

    PacedWaveOut output_;
    std::atomic<bool> active_{false};
    std::atomic<bool> capture_active_{false};
    std::mutex pacer_mutex_;
    std::condition_variable pacer_cv_;
    std::thread pacer_thread_;
    bool pacer_stop_ = false;
    bool pacer_enabled_ = false;
    std::array<uint8_t, kHostPacketBytes> host_packet_{};
    uint32_t host_packet_frames_ = 0u;
    std::mutex pcm_mutex_;
};

} // namespace siemens_mp377
