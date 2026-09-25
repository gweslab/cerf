#include "paced_wave_out.h"

#include "../core/log.h"

#include <algorithm>
#include <cstring>

void PacedWaveOut::Start(const char* log_tag, uint32_t rate_hz, uint16_t channels,
                         uint16_t bits, bool allow_resampler) {
    log_tag_         = log_tag;
    allow_resampler_ = allow_resampler;
    fmt_rate_.store(rate_hz, std::memory_order_release);
    fmt_channels_.store(channels, std::memory_order_release);
    fmt_bits_.store(bits, std::memory_order_release);
    sink_.Start(
        [this] {
            std::lock_guard<std::mutex> lk(audio_mutex_);
            ApplyFormatLocked();
        },
        [this](const MSG& msg) { OnThreadMessage(msg); },
        log_tag);
}

void PacedWaveOut::Stop() { sink_.Stop(); }

void PacedWaveOut::SetFormat(uint32_t rate_hz, uint16_t channels, uint16_t bits) {
    {
        std::lock_guard<std::mutex> lk(audio_mutex_);
        fmt_rate_.store(rate_hz, std::memory_order_release);
        fmt_channels_.store(channels, std::memory_order_release);
        fmt_bits_.store(bits, std::memory_order_release);
    }
    sink_.Post(kMsgSetFormat);
}

uint64_t PacedWaveOut::RequestedFormatLocked() const {
    return static_cast<uint64_t>(fmt_rate_.load(std::memory_order_acquire)) |
           (static_cast<uint64_t>(fmt_channels_.load(std::memory_order_acquire)) << 32) |
           (static_cast<uint64_t>(fmt_bits_.load(std::memory_order_acquire)) << 48);
}

void PacedWaveOut::SwitchDeviceLocked(uint64_t format) {
    const uint32_t rate     = static_cast<uint32_t>(format);
    const uint16_t channels = static_cast<uint16_t>(format >> 32);
    const uint16_t bits     = static_cast<uint16_t>(format >> 48);
    sink_.EnsureFormat(rate, channels, bits, allow_resampler_, false);
    device_format_ = format;
    ++device_epoch_;
    position_valid_ = false;
    LOG(Periph, "[%s] device format %u Hz x %u ch x %u bit open=%d\n",
        log_tag_, rate, channels, bits, sink_.IsOpen() ? 1 : 0);
}

void PacedWaveOut::ApplyFormatLocked() {
    const uint64_t format = RequestedFormatLocked();
    if (static_cast<uint32_t>(format) == 0u) return;
    if (pending_count_ == 0 && outstanding_ == 0 && format != device_format_)
        SwitchDeviceLocked(format);
}

bool PacedWaveOut::HasFreeSlotLocked() const {
    for (uint32_t i = 0; i < kSlots; ++i)
        if (!slot_busy_[i] && slot_stale_[i] == 0u) return true;
    return false;
}

void PacedWaveOut::FlushPendingBlockLocked() {
    if (priming_) return;
    while (pending_count_ != 0 && HasFreeSlotLocked()) {
        const uint64_t format = pending_format_[pending_head_];
        if (format != device_format_) {
            if (outstanding_ != 0) return;
            SwitchDeviceLocked(format);
        }
        PlayLocked(pending_buffer_[pending_head_], pending_length_[pending_head_]);
        pending_head_ = (pending_head_ + 1u) % kPending;
        --pending_count_;
    }
}

void PacedWaveOut::PlayLocked(const uint8_t* bytes, uint32_t length) {
    uint32_t slot = kSlots;
    for (uint32_t i = 0; i < kSlots; ++i)
        if (!slot_busy_[i] && slot_stale_[i] == 0u) { slot = i; break; }
    if (slot == kSlots) {
        LOG(Caution, "[%s] no free slot with %u outstanding\n", log_tag_, outstanding_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    std::memset(&headers_[slot], 0, sizeof(headers_[slot]));
    std::memcpy(buffers_[slot], bytes, length);
    headers_[slot].lpData         = reinterpret_cast<LPSTR>(buffers_[slot]);
    headers_[slot].dwBufferLength = length;

    if (!sink_.Play(&headers_[slot])) {
        LOG(Caution, "[%s] sink refused a %u-byte block\n", log_tag_, length);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const auto now = std::chrono::steady_clock::now();
    slot_busy_[slot]    = true;
    ++outstanding_;

    if (!on_block_done_) return;
    if (due_n_ == kDueCap) {
        LOG(Caution, "[%s] %u page completions are already scheduled\n",
            log_tag_, due_n_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const bool was_empty = due_n_ == 0;
    const auto base = was_empty ? now : due_[due_n_ - 1];
    due_[due_n_++] = base + sink_.PeriodFor(length);
    if (was_empty) sink_.ArmPaceDeadline(due_[0] - now);
}

bool PacedWaveOut::ReleaseSlotLocked(uint32_t slot) {
    if (!slot_busy_[slot]) return false;
    slot_busy_[slot] = false;
    --outstanding_;
    return true;
}

void PacedWaveOut::OnThreadMessage(const MSG& msg) {
    if (msg.message == kMsgSetFormat) {
        std::lock_guard<std::mutex> lk(audio_mutex_);
        ApplyFormatLocked();
        FlushPendingBlockLocked();
        return;
    }
    if (msg.message == kMsgFlushPending) {
        std::lock_guard<std::mutex> lk(audio_mutex_);
        FlushPendingBlockLocked();
        ApplyFormatLocked();
        return;
    }
    if (msg.message == WaveOutSink::kMsgPaceDue) {
        DrainPacedCallbacks();
        return;
    }
    if (msg.message != MM_WOM_DONE) return;
    {
        std::lock_guard<std::mutex> lk(audio_mutex_);
        if (msg.lParam != 0) {
            sink_.Unprepare(reinterpret_cast<LPWAVEHDR>(msg.lParam));
            for (uint32_t i = 0; i < kSlots; ++i) {
                if (msg.lParam != reinterpret_cast<LPARAM>(&headers_[i])) continue;
                if (slot_stale_[i] != 0u) {
                    --slot_stale_[i];
                    break;
                }
                if (ReleaseSlotLocked(i) && !on_block_done_ &&
                    output_active_.load(std::memory_order_acquire)) {
                    RefreshPositionLocked();
                    if (device_started_ && !finished_ && outstanding_ == 0 &&
                        pending_count_ == 0)
                        ++starved_;
                    if (!device_started_) {
                        device_started_ = true;
                        rate_match_.DeviceStarted();
                    }
                }
                break;
            }
        }
        FlushPendingBlockLocked();
        ApplyFormatLocked();
    }
}

void PacedWaveOut::DrainPacedCallbacks() {
    std::function<void()> cb;
    {
        std::lock_guard<std::mutex> lk(audio_mutex_);
        if (due_n_ == 0) return;
        const auto now = std::chrono::steady_clock::now();
        if (now < due_[0]) {
            sink_.ArmPaceDeadline(due_[0] - now);
            return;
        }

        --due_n_;
        for (uint32_t i = 0; i < due_n_; ++i) due_[i] = due_[i + 1];
        if (due_n_ != 0) sink_.ArmPaceDeadline(due_[0] - now);

        if (!output_active_.load(std::memory_order_acquire)) return;
        cb = on_block_done_;
    }
    if (cb) cb();
}


void PacedWaveOut::BeginAudioOut(std::function<void()> on_block_done) {
    std::lock_guard<std::mutex> lk(audio_mutex_);
    on_block_done_ = std::move(on_block_done);
    rate_match_.Restart();
    device_started_ = false;
    starved_        = 0;
    if (on_block_done_) {
        pending_head_  = 0;
        pending_count_ = 0;
    }
    priming_       = !on_block_done_ && outstanding_ == 0 && pending_count_ == 0;
    finished_      = false;
    due_n_         = 0;
    output_active_.store(true, std::memory_order_release);
}

void PacedWaveOut::FinishAudioOut() {
    std::lock_guard<std::mutex> lk(audio_mutex_);
    finished_ = true;
    if (!priming_) return;
    priming_ = false;
    LOG(Periph, "[%s] stream ended before the set point, %u blocks queued\n",
        log_tag_, pending_count_);
    sink_.Post(kMsgFlushPending);
}

void PacedWaveOut::StopAudioOut() {
    std::lock_guard<std::mutex> lk(audio_mutex_);
    output_active_.store(false, std::memory_order_release);
    on_block_done_ = nullptr;
    device_started_ = false;
    priming_        = false;
    finished_       = false;
    ++device_epoch_;
    position_valid_ = false;
    pending_head_  = 0;
    pending_count_ = 0;
    due_n_         = 0;
    sink_.Reset();
    for (uint32_t i = 0; i < kSlots; ++i) {
        if (slot_busy_[i]) ++slot_stale_[i];
        slot_busy_[i] = false;
    }
    outstanding_ = 0;
}

void PacedWaveOut::SpliceOverDroppedLocked(const uint8_t* dropped, uint32_t length) {
    constexpr uint32_t kFadeFrames = 128;
    const uint32_t chans  = fmt_channels_.load(std::memory_order_relaxed);
    const uint32_t frame  = chans * 2u;
    const uint32_t last   = (pending_head_ + pending_count_ - 1u) % kPending;
    if (pending_format_[last] != RequestedFormatLocked()) return;
    uint8_t*       tail   = pending_buffer_[last];
    const uint32_t frames = std::min({ pending_length_[last] / frame,
                                       length / frame, kFadeFrames });
    uint8_t*       a = tail + pending_length_[last] - frames * frame;
    const uint8_t* b = dropped + length - frames * frame;
    for (uint32_t f = 0; f < frames; ++f) {
        const int32_t w_b = static_cast<int32_t>(f + 1);
        const int32_t w_a = static_cast<int32_t>(frames) - static_cast<int32_t>(f) - 1;
        const int32_t sum = static_cast<int32_t>(frames);
        for (uint32_t c = 0; c < chans; ++c) {
            const uint32_t off = f * frame + c * 2u;
            int16_t sa, sb;
            std::memcpy(&sa, a + off, 2);
            std::memcpy(&sb, b + off, 2);
            const int16_t mix = static_cast<int16_t>((sa * w_a + sb * w_b) / sum);
            std::memcpy(a + off, &mix, 2);
        }
    }
}

uint32_t PacedWaveOut::QueuedBytesLocked() const {
    uint32_t bytes = 0;
    for (uint32_t i = 0; i < kSlots; ++i)
        if (slot_busy_[i]) bytes += headers_[i].dwBufferLength;
    for (uint32_t i = 0; i < pending_count_; ++i)
        bytes += pending_length_[(pending_head_ + i) % kPending];
    return bytes;
}

uint32_t PacedWaveOut::RateMatchLocked(const uint8_t* bytes, uint32_t length) {
    const uint32_t bits  = fmt_bits_.load(std::memory_order_relaxed);
    const uint32_t chans = fmt_channels_.load(std::memory_order_relaxed);
    if (bits != 16 || chans == 0 || chans > DynamicRateResampler::kMaxChannels) {
        LOG(Caution, "[%s] rate match on an unmodeled stream: %u ch x %u bit\n",
            log_tag_, chans, bits);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint32_t frame     = chans * 2u;
    const uint32_t in_frames = length / frame;
    std::memcpy(rate_in_, bytes, static_cast<size_t>(in_frames) * frame);
    const double capacity = static_cast<double>(kSlots + kPending) * in_frames;
    const double fill     = static_cast<double>(QueuedBytesLocked()) / frame;
    /* Arntzen, "Dynamic Rate Control for Retro Game Emulators", §2.3: eq. (2) decreases
       the ratio over half full and increases it below half full. */
    set_point_frames_ = capacity / 2.0;
    if (rate_match_.CountBlock()) rate_match_.Sample(DevicePositionLocked());
    const uint32_t produced = rate_match_.Process(rate_in_, in_frames, chans, fill, capacity,
                                                  rate_out_, kMaxBlock / frame);
    if (produced == UINT32_MAX) {
        LOG(Caution, "[%s] rate match output of a %u-frame block overflows %u frames\n",
            log_tag_, in_frames, kMaxBlock / frame);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    double ratio = 0.0;
    if (rate_match_.TakeEstimate(&ratio)) {
        LOG(Periph, "[%s] rate match %.5f, queue %.0f of %.0f frames, starved %u, unfed %u\n",
            log_tag_, ratio, fill, capacity, starved_, unfed_total_);
        starved_ = 0;
    }
    return produced * frame;
}

DevicePosition PacedWaveOut::DevicePositionLocked() const {
    DevicePosition p;
    p.valid   = position_valid_;
    p.samples = position_;
    p.wall_s  = position_wall_s_;
    p.epoch   = device_epoch_;
    p.unfed   = position_unfed_;
    p.rate_hz = static_cast<uint32_t>(device_format_);
    return p;
}

void PacedWaveOut::RefreshPositionLocked() {
    if (pending_count_ == 0) ++unfed_total_;
    position_unfed_ = unfed_total_;
    position_valid_ = false;
    if (!sink_.IsOpen()) return;
    MMTIME mmt{};
    mmt.wType = TIME_SAMPLES;
    if (waveOutGetPosition(sink_.Device(), &mmt, sizeof(mmt)) != MMSYSERR_NOERROR ||
        mmt.wType != TIME_SAMPLES)
        return;
    position_        = mmt.u.sample;
    position_wall_s_ = std::chrono::duration<double>(
                           std::chrono::steady_clock::now().time_since_epoch()).count();
    position_valid_  = true;
}

bool PacedWaveOut::QueueOutput(const void* host_bytes, uint32_t length) {
    if (length == 0) return false;
    if (length > kMaxBlock) length = kMaxBlock;

    std::lock_guard<std::mutex> lk(audio_mutex_);
    if (!output_active_.load(std::memory_order_acquire)) return false;

    if (!on_block_done_) {
        length     = RateMatchLocked(static_cast<const uint8_t*>(host_bytes), length);
        host_bytes = rate_out_;
        if (length == 0) return true;
    }

    const uint64_t format = RequestedFormatLocked();
    if (priming_ || format != device_format_ || pending_count_ != 0 || !HasFreeSlotLocked()) {
        if (pending_count_ == kPending && !on_block_done_) {
            SpliceOverDroppedLocked(static_cast<const uint8_t*>(host_bytes), length);
            LOG(Periph, "[%s] dropped a %u-byte block: pending stash full (%u) with %u outstanding\n",
                log_tag_, length, pending_count_, outstanding_);
            return false;
        }
        if (on_block_done_ && pending_count_ == kSlots) {
            LOG(Caution, "[%s] pending stash full (%u blocks) with %u outstanding; "
                         "a %u-byte block has nowhere to go\n",
                log_tag_, pending_count_, outstanding_, length);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        const uint32_t slot = (pending_head_ + pending_count_) % kPending;
        std::memcpy(pending_buffer_[slot], host_bytes, length);
        pending_length_[slot] = length;
        pending_format_[slot] = format;
        ++pending_count_;
        if (format != device_format_) sink_.Post(kMsgSetFormat);
        const uint32_t frame = fmt_channels_.load(std::memory_order_relaxed) * 2u;
        if (priming_ && static_cast<double>(QueuedBytesLocked()) / frame >= set_point_frames_) {
            priming_ = false;
            LOG(Periph, "[%s] device starts at the set point, %u blocks queued\n",
                log_tag_, pending_count_);
            sink_.Post(kMsgFlushPending);
        }
        return true;
    }

    if (!on_block_done_) ++unfed_total_;
    PlayLocked(static_cast<const uint8_t*>(host_bytes), length);
    return true;
}
