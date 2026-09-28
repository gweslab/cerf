#include "wave_out_sink.h"

#include "../core/log.h"

#include <algorithm>

WaveOutSink::~WaveOutSink() {
    Stop();
    {
        std::lock_guard<std::mutex> lk(mtx_);
        CloseDeviceLocked();
    }
    if (pace_timer_) CloseHandle(pace_timer_);
    if (silent_timer_) CloseHandle(silent_timer_);
    if (ready_event_) CloseHandle(ready_event_);
}

void WaveOutSink::Start(ThreadCallback on_start, MessageHandler on_message,
                        const char* log_tag) {
    log_tag_     = log_tag;
    ready_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    thread_      = std::thread([this, on_start, on_message] {
        ThreadMain(on_start, on_message);
    });
    WaitForSingleObject(ready_event_, INFINITE);
}

void WaveOutSink::Stop() {
    shutdown_.store(true, std::memory_order_release);
    if (thread_id_) PostThreadMessageW(thread_id_, WM_QUIT, 0, 0);
    if (thread_.joinable()) thread_.join();
}

void WaveOutSink::Post(UINT message, WPARAM wparam, LPARAM lparam) const {
    if (thread_id_) PostThreadMessageW(thread_id_, message, wparam, lparam);
}

HANDLE WaveOutSink::CreatePaceTimer() const {
    HANDLE timer = CreateWaitableTimerExW(nullptr, nullptr,
                                          CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                                          TIMER_ALL_ACCESS);
    if (timer == nullptr) timer = CreateWaitableTimerW(nullptr, FALSE, nullptr);
    if (timer == nullptr) {
        LOG(Caution, "%s: CreateWaitableTimer failed; block pacing has no clock\n", log_tag_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    return timer;
}

void WaveOutSink::ThreadMain(ThreadCallback on_start, MessageHandler on_message) {
    thread_id_    = GetCurrentThreadId();
    pace_timer_   = CreatePaceTimer();
    silent_timer_ = CreatePaceTimer();

    MSG msg;
    PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
    SetEvent(ready_event_);

    if (on_start) on_start();

    const HANDLE waits[2] = { pace_timer_, silent_timer_ };
    while (!shutdown_.load(std::memory_order_acquire)) {
        const DWORD w = MsgWaitForMultipleObjectsEx(2, waits, INFINITE,
                                                    QS_ALLINPUT, MWMO_INPUTAVAILABLE);
        if (w == WAIT_OBJECT_0) {
            MSG due{};
            due.message = kMsgPaceDue;
            if (on_message) on_message(due);
            continue;
        }
        if (w == WAIT_OBJECT_0 + 1) {
            DeliverDueSilent(on_message);
            continue;
        }
        while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) return;
            if (msg.message == kMsgRetryOpen) {
                RetryOpen();
                continue;
            }
            if (on_message) on_message(msg);
        }
    }
}

void WaveOutSink::ArmTimer(HANDLE timer, Clock::duration delay) const {
    const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(delay).count();
    LARGE_INTEGER due;
    due.QuadPart = ns > 0 ? -(ns / 100) : -1;
    if (!SetWaitableTimer(timer, &due, 0, nullptr, nullptr, FALSE)) {
        LOG(Caution, "%s: SetWaitableTimer failed; a block would never be reported\n", log_tag_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
}

void WaveOutSink::ArmPaceDeadline(Clock::duration delay) { ArmTimer(pace_timer_, delay); }

WaveOutSink::Clock::duration WaveOutSink::PeriodFor(uint32_t length) const {
    std::lock_guard<std::mutex> lk(mtx_);
    return PeriodForLocked(length);
}

WaveOutSink::Clock::duration WaveOutSink::PeriodForLocked(uint32_t length) const {
    const uint64_t bytes_per_sec =
        static_cast<uint64_t>(req_rate_) * static_cast<uint32_t>(req_channels_) *
        (static_cast<uint32_t>(req_bits_) / 8u);
    if (bytes_per_sec == 0u) return Clock::duration::zero();
    return std::chrono::duration_cast<Clock::duration>(
        std::chrono::duration<double>(static_cast<double>(length) /
                                      static_cast<double>(bytes_per_sec)));
}

void WaveOutSink::QueueSilentLocked(WAVEHDR* hdr) {
    if (!hdr) {
        LOG(Caution, "%s: silent completion for a null header\n", log_tag_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    for (uint32_t i = 0; i < silent_count_; ++i) {
        if (silent_[i].hdr != hdr) continue;
        LOG(Caution, "%s: header %p is already awaiting a silent completion\n",
            log_tag_, static_cast<void*>(hdr));
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    if (silent_count_ == kSilentQueue) {
        LOG(Caution, "%s: %u silent blocks already pending\n", log_tag_, kSilentQueue);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const auto period = PeriodForLocked(hdr->dwBufferLength);
    if (period == Clock::duration::zero()) {
        LOG(Caution, "%s: cannot pace a silent block at %u Hz x %u ch x %u bit\n",
            log_tag_, req_rate_, req_channels_, req_bits_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const auto now = Clock::now();
    silent_tail_ = std::max(now, silent_tail_) + period;
    silent_[silent_count_++] = SilentBlock{ hdr, silent_tail_ };
    if (silent_count_ == 1) ArmTimer(silent_timer_, silent_[0].due - now);
}

void WaveOutSink::DeliverDueSilent(const MessageHandler& on_message) {
    WAVEHDR* done[kSilentQueue] = {};
    uint32_t n = 0;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const auto now = Clock::now();
        while (n < silent_count_ && silent_[n].due <= now) {
            done[n] = silent_[n].hdr;
            ++n;
        }
        silent_count_ -= n;
        for (uint32_t i = 0; i < silent_count_; ++i) silent_[i] = silent_[i + n];
        if (silent_count_ != 0) ArmTimer(silent_timer_, silent_[0].due - now);
    }
    for (uint32_t i = 0; i < n; ++i) {
        MSG out{};
        out.message = MM_WOM_DONE;
        out.wParam  = kSilentDone;
        out.lParam  = reinterpret_cast<LPARAM>(done[i]);
        if (on_message) on_message(out);
    }
}

void WaveOutSink::CancelSilentLocked() {
    CancelWaitableTimer(silent_timer_);
    for (uint32_t i = 0; i < silent_count_; ++i)
        Post(MM_WOM_DONE, kSilentDone, reinterpret_cast<LPARAM>(silent_[i].hdr));
    silent_count_ = 0;
    silent_tail_  = Clock::time_point{};
}

void WaveOutSink::CloseDeviceLocked() {
    if (out_device_) {
        waveOutReset(out_device_);
        const MMRESULT r = waveOutClose(out_device_);
        if (r != MMSYSERR_NOERROR) {
            LOG(Caution, "%s: waveOutClose failed mmresult=%u - device handle leaked\n",
                log_tag_, r);
        }
        out_device_ = nullptr;
    }
}

void WaveOutSink::LoseDeviceLocked(const char* call, MMRESULT result) {
    const MMRESULT reset = waveOutReset(out_device_);
    const MMRESULT close = waveOutClose(out_device_);
    LOG(Caution, "%s: host audio device lost (%s mmresult=%u, reset %u, close %u) "
            "- silent-mode (blocks paced from their own duration)\n",
            log_tag_, call, result, reset, close);
    out_device_   = nullptr;
    last_fail_    = result;
    last_attempt_ = Clock::now();
}

bool WaveOutSink::FormatMatchesLocked() const {
    return out_device_ != nullptr && open_rate_ == req_rate_ &&
           open_channels_ == req_channels_ && open_bits_ == req_bits_;
}

WaveOutSink::OpenRequest WaveOutSink::BeginOpenLocked() {
    last_attempt_ = Clock::now();
    OpenRequest req{};
    req.fmt.wFormatTag      = WAVE_FORMAT_PCM;
    req.fmt.nChannels       = req_channels_;
    req.fmt.nSamplesPerSec  = req_rate_;
    req.fmt.wBitsPerSample  = req_bits_;
    req.fmt.nBlockAlign     = static_cast<uint16_t>((req_bits_ / 8) * req_channels_);
    req.fmt.nAvgBytesPerSec = req_rate_ * req.fmt.nBlockAlign;
    req.fmt.cbSize          = 0;
    req.flags = CALLBACK_THREAD |
                (req_allow_resampler_ ? 0u : static_cast<DWORD>(WAVE_FORMAT_DIRECT));
    return req;
}

MMRESULT WaveOutSink::OpenDevice(const OpenRequest& req, HWAVEOUT& device) const {
    device = nullptr;
    return waveOutOpen(&device, WAVE_MAPPER, &req.fmt, thread_id_, 0, req.flags);
}

bool WaveOutSink::FinishOpenLocked(const OpenRequest& req, MMRESULT r, HWAVEOUT device) {
    const uint32_t rate     = req.fmt.nSamplesPerSec;
    const uint16_t channels = req.fmt.nChannels;
    const uint16_t bits     = req.fmt.wBitsPerSample;
    if (r != MMSYSERR_NOERROR) {
        if (r != last_fail_) {
            LOG(Caution, "%s: waveOutOpen(%u Hz x %u ch x %u bit) failed mmresult=%u "
                    "- silent-mode (blocks paced from their own duration)\n",
                    log_tag_, rate, channels, bits, r);
        }
        last_fail_ = r;
        return false;
    }
    out_device_    = device;
    open_rate_     = rate;
    open_channels_ = channels;
    open_bits_     = bits;
    last_fail_     = MMSYSERR_NOERROR;
    ++generation_;
    LOG(Periph, "[%s] waveOut opened %u Hz x %u ch x %u bit\n", log_tag_, rate, channels, bits);
    return true;
}

bool WaveOutSink::OpenLocked() {
    const OpenRequest req = BeginOpenLocked();
    HWAVEOUT device = nullptr;
    const MMRESULT r = OpenDevice(req, device);
    return FinishOpenLocked(req, r, device);
}

bool WaveOutSink::EnsureFormat(uint32_t sample_rate_hz, uint16_t channels,
                              uint16_t bits, bool allow_resampler, bool busy) {
    std::lock_guard<std::mutex> lk(mtx_);
    const bool changed = sample_rate_hz != req_rate_ || channels != req_channels_ ||
                         bits != req_bits_ || allow_resampler != req_allow_resampler_;
    req_rate_            = sample_rate_hz;
    req_channels_        = channels;
    req_bits_            = bits;
    req_allow_resampler_ = allow_resampler;
    if (FormatMatchesLocked()) return true;
    if (out_device_) {
        if (busy) return true;
        CloseDeviceLocked();
    }
    if (!changed && Clock::now() - last_attempt_ < kReopenInterval) return false;
    return OpenLocked();
}

void WaveOutSink::RetryOpen() {
    OpenRequest req{};
    {
        std::lock_guard<std::mutex> lk(mtx_);
        retry_posted_ = false;
        if (out_device_ || Clock::now() - last_attempt_ < kReopenInterval) return;
        req = BeginOpenLocked();
    }
    HWAVEOUT device = nullptr;
    const MMRESULT r = OpenDevice(req, device);
    std::lock_guard<std::mutex> lk(mtx_);
    FinishOpenLocked(req, r, device);
}

bool WaveOutSink::IsOpen() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return out_device_ != nullptr;
}

bool WaveOutSink::SamplePosition(uint32_t& samples, uint32_t& generation) const {
    std::lock_guard<std::mutex> lk(mtx_);
    generation = generation_;
    if (!out_device_) return false;
    MMTIME mmt{};
    mmt.wType = TIME_SAMPLES;
    if (waveOutGetPosition(out_device_, &mmt, sizeof(mmt)) != MMSYSERR_NOERROR ||
        mmt.wType != TIME_SAMPLES)
        return false;
    samples = mmt.u.sample;
    return true;
}

void WaveOutSink::Play(WAVEHDR* hdr) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (out_device_) {
        const char* call = "waveOutPrepareHeader";
        MMRESULT r = waveOutPrepareHeader(out_device_, hdr, sizeof(WAVEHDR));
        if (r == MMSYSERR_NOERROR) {
            call = "waveOutWrite";
            r = waveOutWrite(out_device_, hdr, sizeof(WAVEHDR));
            if (r == MMSYSERR_NOERROR) return;
            waveOutUnprepareHeader(out_device_, hdr, sizeof(WAVEHDR));
        }
        if (r != MMSYSERR_NODRIVER) {
            LOG(Caution, "%s: %s failed mmresult=%u\n", log_tag_, call, r);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        LoseDeviceLocked(call, r);
    }
    QueueSilentLocked(hdr);
    if (!retry_posted_ && Clock::now() - last_attempt_ >= kReopenInterval) {
        retry_posted_ = true;
        Post(kMsgRetryOpen);
    }
}

void WaveOutSink::Unprepare(WAVEHDR* hdr) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (out_device_ && hdr) waveOutUnprepareHeader(out_device_, hdr, sizeof(WAVEHDR));
}

void WaveOutSink::Reset() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (out_device_) waveOutReset(out_device_);
    CancelSilentLocked();
}
