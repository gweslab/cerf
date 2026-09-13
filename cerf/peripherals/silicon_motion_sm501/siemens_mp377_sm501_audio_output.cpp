#define NOMINMAX

#include "siemens_mp377_sm501_audio_output.h"
#include "siemens_mp377_sm501_audio_mcu.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/audio_activity_widget.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"

#include <algorithm>

#ifndef CREATE_WAITABLE_TIMER_HIGH_RESOLUTION
#define CREATE_WAITABLE_TIMER_HIGH_RESOLUTION 0x00000002
#endif

namespace siemens_mp377 {

bool SiemensMp377Sm501AudioOutput::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetBoard() == Board::SiemensMP377;
}

void SiemensMp377Sm501AudioOutput::OnReady() {
    output_.Start("MP377SM501Audio", 0, 2, 16, true);
    StartPacer();
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) return;
        ResetDevice();
    });
}

void SiemensMp377Sm501AudioOutput::OnShutdown() {
    StopPacer();
    output_.StopAudioOut();
    output_.Stop();
}

void SiemensMp377Sm501AudioOutput::QueueAc97PcmSample(uint32_t left20, uint32_t right20) {
    if (!active_.load(std::memory_order_acquire)) return;
    const int16_t left = static_cast<int16_t>((left20 >> 4u) & 0xFFFFu);
    const int16_t right = static_cast<int16_t>((right20 >> 4u) & 0xFFFFu);
    std::lock_guard<std::mutex> lock(pcm_mutex_);
    uint8_t* out = host_packet_.data() + host_packet_frames_ * 4u;
    out[0] = static_cast<uint8_t>(left);
    out[1] = static_cast<uint8_t>(static_cast<uint16_t>(left) >> 8u);
    out[2] = static_cast<uint8_t>(right);
    out[3] = static_cast<uint8_t>(static_cast<uint16_t>(right) >> 8u);
    ++host_packet_frames_;
    if (host_packet_frames_ == kHostPacketFrames) {
        output_.QueueOutput(host_packet_.data(), kHostPacketBytes);
        emu_.Get<AudioActivityWidget>().NotePresent();
        host_packet_.fill(0u);
        host_packet_frames_ = 0u;
    }
}

void SiemensMp377Sm501AudioOutput::HandleDacPowerDown() {
    if (!active_.load(std::memory_order_acquire)) return;
    SetPacerEnabled(false);
    active_.store(false, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(pcm_mutex_);
        host_packet_frames_ = 0u;
        host_packet_.fill(0u);
    }
    output_.StopAudioOut();
    SetPacerEnabled(capture_active_.load(std::memory_order_acquire));
}

void SiemensMp377Sm501AudioOutput::SetPlaybackEnabled(bool enabled) {
    if (enabled && !active_.load(std::memory_order_acquire)) {
        active_.store(true, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lock(pcm_mutex_);
            host_packet_.fill(0u);
            host_packet_frames_ = 0u;
        }
        output_.SetFormat(kDefaultRateHz, 2, 16);
        output_.BeginAudioOut({});
        SetPacerEnabled(true);
        emu_.Get<AudioActivityWidget>().NotePresent();
    } else if (!enabled && active_.load(std::memory_order_acquire)) {
        active_.store(false, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lock(pcm_mutex_);
            host_packet_.fill(0u);
            host_packet_frames_ = 0u;
        }
        output_.StopAudioOut();
        SetPacerEnabled(capture_active_.load(std::memory_order_acquire));
    }
}

void SiemensMp377Sm501AudioOutput::SetCaptureEnabled(bool enabled) {
    capture_active_.store(enabled, std::memory_order_release);
    SetPacerEnabled(enabled || active_.load(std::memory_order_acquire));
}

std::unique_lock<std::mutex> SiemensMp377Sm501AudioOutput::LockForState() {
    return std::unique_lock<std::mutex>(pacer_mutex_);
}

void SiemensMp377Sm501AudioOutput::SaveState(StateWriter& w) {
    w.Write(active_.load(std::memory_order_acquire));
    w.Write(capture_active_.load(std::memory_order_acquire));
    std::lock_guard<std::mutex> lock(pcm_mutex_);
    w.WriteBytes(host_packet_.data(), host_packet_.size());
    w.Write(host_packet_frames_);
}

void SiemensMp377Sm501AudioOutput::RestoreState(StateReader& r) {
    bool active = false;
    r.Read(active);
    active_.store(active, std::memory_order_release);
    bool capture_active = false;
    r.Read(capture_active);
    capture_active_.store(capture_active, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(pcm_mutex_);
        r.ReadBytes(host_packet_.data(), host_packet_.size());
        r.Read(host_packet_frames_);
        if (host_packet_frames_ > kHostPacketFrames) host_packet_frames_ = 0u;
    }
    if (active_.load(std::memory_order_acquire)) {
        output_.SetFormat(kDefaultRateHz, 2, 16);
        output_.BeginAudioOut({});
    }
    SetPacerEnabled(active || capture_active);
}

void SiemensMp377Sm501AudioOutput::ResetDevice() {
    SetPacerEnabled(false);
    active_.store(false, std::memory_order_release);
    capture_active_.store(false, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(pcm_mutex_);
        host_packet_frames_ = 0u;
        host_packet_.fill(0u);
    }
    output_.StopAudioOut();
}

std::chrono::microseconds SiemensMp377Sm501AudioOutput::BlockPeriod() const {
    constexpr uint64_t usec =
        (static_cast<uint64_t>(kFramesPerFirmwareHalf) * 1000000ull + kDefaultRateHz / 2u) / kDefaultRateHz;
    return std::chrono::microseconds(usec);
}

void SiemensMp377Sm501AudioOutput::StartPacer() {
    std::lock_guard<std::mutex> lock(pacer_mutex_);
    if (pacer_thread_.joinable()) return;
    pacer_stop_ = false;
    pacer_enabled_ = false;
    pacer_thread_ = std::thread([this]() { PacerLoop(); });
}

void SiemensMp377Sm501AudioOutput::StopPacer() {
    {
        std::lock_guard<std::mutex> lock(pacer_mutex_);
        pacer_enabled_ = false;
        pacer_stop_ = true;
    }
    pacer_cv_.notify_all();
    if (pacer_thread_.joinable()) pacer_thread_.join();
}

void SiemensMp377Sm501AudioOutput::SetPacerEnabled(bool enabled) {
    {
        std::lock_guard<std::mutex> lock(pacer_mutex_);
        pacer_enabled_ = enabled;
    }
    pacer_cv_.notify_all();
}

void SiemensMp377Sm501AudioOutput::PacerLoop() {
    auto& freeze = emu_.Get<EmulationFreeze>();
    const MMRESULT timer_period = timeBeginPeriod(1u);
    HANDLE timer = CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    if (timer == nullptr) timer = CreateWaitableTimerW(nullptr, FALSE, nullptr);
    auto wait_until = [timer](std::chrono::steady_clock::time_point deadline) {
        const auto now = std::chrono::steady_clock::now();
        if (deadline <= now) return;
        if (timer == nullptr) {
            std::this_thread::sleep_until(deadline);
            return;
        }
        const auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - now).count();
        const LONGLONG ticks = std::max<LONGLONG>(1, (ns + 99) / 100);
        LARGE_INTEGER due{};
        due.QuadPart = -ticks;
        if (!SetWaitableTimer(timer, &due, 0, nullptr, nullptr, FALSE)) {
            std::this_thread::sleep_until(deadline);
            return;
        }
        WaitForSingleObject(timer, INFINITE);
    };
    std::unique_lock<std::mutex> lock(pacer_mutex_);
    while (!pacer_stop_) {
        pacer_cv_.wait(lock, [this]() { return pacer_stop_ || pacer_enabled_; });
        if (pacer_stop_) break;
        auto next = std::chrono::steady_clock::now() + BlockPeriod();
        while (pacer_enabled_ && !pacer_stop_) {
            lock.unlock();
            wait_until(next);
            lock.lock();
            if (!pacer_enabled_ || pacer_stop_) break;
            lock.unlock();
            {
                auto frozen = freeze.WorkerSection();
                ServiceClockTick();
            }
            lock.lock();
            const auto period = BlockPeriod();
            next += period;
            const auto now = std::chrono::steady_clock::now();
            if (next <= now) next = now + period;
        }
    }
    lock.unlock();
    if (timer != nullptr) {
        CancelWaitableTimer(timer);
        CloseHandle(timer);
    }
    if (timer_period == TIMERR_NOERROR) timeEndPeriod(1u);
}

void SiemensMp377Sm501AudioOutput::ServiceClockTick() {
    if (active_.load(std::memory_order_acquire) || capture_active_.load(std::memory_order_acquire))
        ServiceCompletions();
}

void SiemensMp377Sm501AudioOutput::ServiceCompletions() {
    if (!active_.load(std::memory_order_acquire) && !capture_active_.load(std::memory_order_acquire)) return;
    emu_.Get<SiemensMp377Sm501AudioMcu>().RunAc97Frames(kFramesPerFirmwareHalf);
}

REGISTER_SERVICE(SiemensMp377Sm501AudioOutput);

} // namespace siemens_mp377
