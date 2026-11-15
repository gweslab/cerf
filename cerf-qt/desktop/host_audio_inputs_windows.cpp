#define NOMINMAX
#include <windows.h>
#include <mmsystem.h>

#include "host_message_thread.h"
#include "winmm_wave_format.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/instance_threads.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/audio_inputs.h>

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace cerffrontend {

namespace {

class HostAudioInput final : public cerfcore::AudioInputDevice {
public:
    HostAudioInput(cerfcore::CerfEmulator& emu, std::string stream);
    ~HostAudioInput() override { thread_.Stop(); }
    HostAudioInput(const HostAudioInput&)            = delete;
    HostAudioInput& operator=(const HostAudioInput&) = delete;

    bool Open(const cerfcore::AudioFormat& format, Captured captured) override;
    void Close() override;

private:
    struct RecordBuffer {
        WAVEHDR              hdr{};
        std::vector<uint8_t> bytes;
    };

    static constexpr UINT     kMsgOpen        = WM_USER + 0x10u;
    static constexpr UINT     kMsgClose       = WM_USER + 0x11u;
    static constexpr uint32_t kRecordBuffers  = 8u;
    static constexpr uint32_t kRecordBufBytes = 4096u;

    bool Call(std::unique_lock<std::mutex>& lk, UINT message);
    void OnMessage(const MSG& msg);
    bool OpenLocked();
    void CloseLocked();

    const std::string       stream_;
    std::mutex              mtx_;
    std::condition_variable done_cv_;
    cerfcore::AudioFormat   format_;
    Captured                captured_;
    RecordBuffer            buffers_[kRecordBuffers];
    HWAVEIN                 device_ = nullptr;
    bool                    done_   = false;
    bool                    result_ = false;
    HostMessageThread       thread_;
};

HostAudioInput::HostAudioInput(cerfcore::CerfEmulator& emu, std::string stream) : stream_(std::move(stream)) {
    thread_.Start(emu.Get<cerfcore::InstanceThreads>(), [this](const MSG& msg) { OnMessage(msg); });
}

bool HostAudioInput::Open(const cerfcore::AudioFormat& format, Captured captured) {
    std::unique_lock<std::mutex> lk(mtx_);
    format_   = format;
    captured_ = std::move(captured);
    return Call(lk, kMsgOpen);
}

void HostAudioInput::Close() {
    std::unique_lock<std::mutex> lk(mtx_);
    Call(lk, kMsgClose);
}

bool HostAudioInput::Call(std::unique_lock<std::mutex>& lk, UINT message) {
    done_ = false;
    thread_.Post(message);
    done_cv_.wait(lk, [this] { return done_; });
    return result_;
}

void HostAudioInput::OnMessage(const MSG& msg) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (msg.message == kMsgOpen || msg.message == kMsgClose) {
        if (msg.message == kMsgOpen) {
            result_ = OpenLocked();
            if (!result_) {
                LOG(Caution, "[%s] microphone capture unavailable at %u Hz (host waveIn open failed); the guest "
                             "records silence\n",
                    stream_.c_str(), format_.rate_hz);
            }
        } else {
            CloseLocked();
            result_ = true;
        }
        done_ = true;
        done_cv_.notify_all();
        return;
    }
    if (msg.message != MM_WIM_DATA || device_ == nullptr) return;
    WAVEHDR* const hdr = reinterpret_cast<WAVEHDR*>(msg.lParam);
    captured_(reinterpret_cast<const uint8_t*>(hdr->lpData), hdr->dwBytesRecorded);
    hdr->dwBytesRecorded = 0;
    hdr->dwFlags &= ~WHDR_DONE;
    waveInAddBuffer(device_, hdr, sizeof(WAVEHDR));
}

bool HostAudioInput::OpenLocked() {
    WAVEFORMATEX   fmt = PcmWaveFormat(format_);
    const MMRESULT r   = waveInOpen(&device_, WAVE_MAPPER, &fmt, thread_.ThreadId(), 0, CALLBACK_THREAD);
    if (r != MMSYSERR_NOERROR) {
        LOG(Caution, "%s: waveInOpen(%u Hz x %u ch x %u bit) failed mmresult=%u - microphone capture unavailable\n",
            stream_.c_str(), format_.rate_hz, format_.channels, format_.bits, r);
        device_ = nullptr;
        return false;
    }
    for (RecordBuffer& b : buffers_) {
        b.bytes.assign(kRecordBufBytes, 0);
        b.hdr                = WAVEHDR{};
        b.hdr.lpData         = reinterpret_cast<LPSTR>(b.bytes.data());
        b.hdr.dwBufferLength = kRecordBufBytes;
        if (waveInPrepareHeader(device_, &b.hdr, sizeof(WAVEHDR)) != MMSYSERR_NOERROR ||
            waveInAddBuffer(device_, &b.hdr, sizeof(WAVEHDR)) != MMSYSERR_NOERROR) {
            LOG(Caution, "%s: record buffer prime failed\n", stream_.c_str());
            CloseLocked();
            return false;
        }
    }
    if (waveInStart(device_) != MMSYSERR_NOERROR) {
        LOG(Caution, "%s: waveInStart failed\n", stream_.c_str());
        CloseLocked();
        return false;
    }
    LOG(Periph, "[%s] waveIn opened %u Hz x %u ch x %u bit\n", stream_.c_str(), format_.rate_hz, format_.channels,
        format_.bits);
    return true;
}

void HostAudioInput::CloseLocked() {
    waveInReset(device_);
    for (RecordBuffer& b : buffers_) {
        if (b.hdr.dwFlags & WHDR_PREPARED) waveInUnprepareHeader(device_, &b.hdr, sizeof(WAVEHDR));
    }
    waveInClose(device_);
    device_ = nullptr;
}

class HostAudioInputs final : public cerfcore::AudioInputs {
public:
    using cerfcore::AudioInputs::AudioInputs;

    std::unique_ptr<cerfcore::AudioInputDevice> CreateInput(const std::string& stream) override {
        return std::make_unique<HostAudioInput>(emu_, stream);
    }
};

}

REGISTER_SERVICE_AS(HostAudioInputs, cerfcore::AudioInputs);

}
