#pragma once

#define NOMINMAX
#include <windows.h>
#include <mmsystem.h>

#include "dynamic_rate_resampler.h"
#include "wave_out_sink.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>

class PacedWaveOut {
public:
    static constexpr uint32_t kMaxBlock = 0x2000u;   /* DMA LENGTH < 8 KB. */

    void Start(const char* log_tag, uint32_t rate_hz, uint16_t channels,
               uint16_t bits, bool allow_resampler);
    void Stop();
    void SetFormat(uint32_t rate_hz, uint16_t channels, uint16_t bits);

    void BeginAudioOut(std::function<void()> on_block_done);
    bool QueueOutput(const void* host_bytes, uint32_t length);
    void FinishAudioOut();
    void StopAudioOut();

private:
    void OnThreadMessage(const MSG& msg);
    void ApplyFormatLocked();
    uint64_t RequestedFormatLocked() const;
    void SwitchDeviceLocked(uint64_t format);
    bool HasFreeSlotLocked() const;
    void FlushPendingBlockLocked();
    void PlayLocked(const uint8_t* bytes, uint32_t length);
    bool ReleaseSlotLocked(uint32_t slot);
    void SpliceOverDroppedLocked(const uint8_t* dropped, uint32_t length);
    uint32_t QueuedBytesLocked() const;
    uint32_t RateMatchLocked(const uint8_t* bytes, uint32_t length);
    DevicePosition DevicePositionLocked() const;
    void RefreshPositionLocked();
    void DrainPacedCallbacks();

    static constexpr UINT kMsgSetFormat    = WM_USER + 41;
    static constexpr UINT kMsgFlushPending = WM_USER + 42;

    static constexpr uint32_t kSlots = 8;
    static_assert(kSlots <= WaveOutSink::kSilentQueue,
                  "every busy slot can hold one silent-mode completion");

    WaveOutSink           sink_;
    const char*           log_tag_ = "PacedWaveOut";
    bool                  allow_resampler_ = false;
    WAVEHDR               headers_[kSlots] = {};
    uint8_t               buffers_[kSlots][kMaxBlock] = {};
    bool                  slot_busy_[kSlots] = {};
    /* waveOutReset returns in-flight buffers to the application as MM_WOM_DONE:
       https://learn.microsoft.com/en-us/windows/win32/multimedia/mm-wom-done */
    uint32_t              slot_stale_[kSlots] = {};
    uint32_t              outstanding_ = 0;
    static constexpr uint32_t kPending = 56;
    uint8_t               pending_buffer_[kPending][kMaxBlock] = {};
    uint32_t              pending_length_[kPending] = {};
    uint64_t              pending_format_[kPending] = {};
    uint32_t              pending_head_  = 0;
    uint32_t              pending_count_ = 0;
    uint64_t              device_format_ = 0;
    static constexpr uint32_t kDueCap = 2 * kSlots;
    std::chrono::steady_clock::time_point due_[kDueCap] = {};
    uint32_t              due_n_ = 0;
    std::mutex            audio_mutex_;
    std::function<void()> on_block_done_;
    DynamicRateResampler  rate_match_;
    bool                  device_started_ = false;
    bool                  priming_        = false;
    bool                  finished_       = false;
    double                set_point_frames_ = 0.0;
    uint32_t              starved_        = 0;
    uint32_t              device_epoch_   = 0;
    uint32_t              unfed_total_    = 0;
    bool                  position_valid_ = false;
    uint32_t              position_       = 0;
    double                position_wall_s_ = 0.0;
    uint32_t              position_unfed_ = 0;
    int16_t               rate_in_[kMaxBlock / 2]  = {};
    int16_t               rate_out_[kMaxBlock / 2] = {};
    std::atomic<bool>     output_active_{false};
    std::atomic<uint32_t> fmt_rate_{0};
    std::atomic<uint16_t> fmt_channels_{0};
    std::atomic<uint16_t> fmt_bits_{0};
};
