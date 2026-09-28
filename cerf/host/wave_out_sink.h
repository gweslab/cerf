#pragma once

#define NOMINMAX
#include <windows.h>
#include <mmsystem.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <mutex>
#include <thread>

class WaveOutSink {
public:
    using ThreadCallback  = std::function<void()>;
    using MessageHandler  = std::function<void(const MSG&)>;
    using Clock           = std::chrono::steady_clock;

    WaveOutSink() = default;
    ~WaveOutSink();
    WaveOutSink(const WaveOutSink&)            = delete;
    WaveOutSink& operator=(const WaveOutSink&) = delete;

    void Start(ThreadCallback on_start, MessageHandler on_message,
               const char* log_tag);
    void Stop();

    DWORD ThreadId() const { return thread_id_; }
    void Post(UINT message, WPARAM wparam = 0, LPARAM lparam = 0) const;

    bool EnsureFormat(uint32_t sample_rate_hz, uint16_t channels,
                      uint16_t bits, bool allow_resampler, bool busy);
    bool IsOpen() const;
    bool SamplePosition(uint32_t& samples, uint32_t& generation) const;

    void Play(WAVEHDR* hdr);
    void Unprepare(WAVEHDR* hdr);
    void Reset();

    static constexpr UINT kMsgPaceDue = WM_USER + 909;
    void ArmPaceDeadline(Clock::duration delay);

    Clock::duration PeriodFor(uint32_t length) const;

    static constexpr uint32_t kSilentQueue = 8;
    static constexpr WPARAM   kSilentDone  = 1;

private:
    struct SilentBlock {
        WAVEHDR*          hdr;
        Clock::time_point due;
    };

    struct OpenRequest {
        WAVEFORMATEX fmt;
        DWORD        flags;
    };

    void ThreadMain(ThreadCallback on_start, MessageHandler on_message);
    HANDLE CreatePaceTimer() const;
    void ArmTimer(HANDLE timer, Clock::duration delay) const;
    bool FormatMatchesLocked() const;
    OpenRequest BeginOpenLocked();
    MMRESULT OpenDevice(const OpenRequest& req, HWAVEOUT& device) const;
    bool FinishOpenLocked(const OpenRequest& req, MMRESULT r, HWAVEOUT device);
    bool OpenLocked();
    void CloseDeviceLocked();
    void LoseDeviceLocked(const char* call, MMRESULT result);
    void RetryOpen();
    Clock::duration PeriodForLocked(uint32_t length) const;
    void QueueSilentLocked(WAVEHDR* hdr);
    void DeliverDueSilent(const MessageHandler& on_message);
    void CancelSilentLocked();

    static constexpr UINT kMsgRetryOpen = WM_USER + 907;
    static constexpr Clock::duration kReopenInterval = std::chrono::seconds(1);

    mutable std::mutex mtx_;
    SilentBlock        silent_[kSilentQueue] = {};
    uint32_t           silent_count_ = 0;
    Clock::time_point  silent_tail_{};
    HANDLE             silent_timer_ = nullptr;
    HANDLE             pace_timer_   = nullptr;
    uint32_t           req_rate_     = 0;
    uint16_t           req_channels_ = 0;
    uint16_t           req_bits_     = 0;
    bool               req_allow_resampler_ = false;
    Clock::time_point  last_attempt_{};
    MMRESULT           last_fail_    = MMSYSERR_NOERROR;
    bool               retry_posted_ = false;
    uint32_t           generation_   = 0;

    DWORD             thread_id_   = 0;
    HANDLE            ready_event_ = nullptr;
    std::thread       thread_;
    std::atomic<bool> shutdown_{false};

    HWAVEOUT    out_device_     = nullptr;
    uint32_t    open_rate_      = 0;
    uint16_t    open_channels_  = 0;
    uint16_t    open_bits_      = 0;
    const char* log_tag_        = "WaveOutSink";
};
