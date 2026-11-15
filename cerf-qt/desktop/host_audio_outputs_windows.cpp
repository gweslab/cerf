#define NOMINMAX
#include <windows.h>
#include <mmsystem.h>

#include "host_message_thread.h"
#include "winmm_wave_format.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/fatal.h>
#include <cerfcore/core/instance_threads.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/audio_outputs.h>

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

namespace cerffrontend {

namespace {

class HostAudioOutput final : public cerfcore::AudioOutputDevice {
public:
    HostAudioOutput(cerfcore::CerfEmulator& emu, std::string stream);
    ~HostAudioOutput() override { thread_.Stop(); }
    HostAudioOutput(const HostAudioOutput&)            = delete;
    HostAudioOutput& operator=(const HostAudioOutput&) = delete;

    bool Open(const cerfcore::AudioFormat& format, Consumed consumed) override;
    void Close() override;
    bool Submit(uint32_t block, const uint8_t* bytes, uint32_t length) override;
    void Drop() override;
    bool PlayedFrames(uint64_t& frames) const override;

private:
    void OnMessage(const MSG& msg);

    cerfcore::CerfEmulator&               emu_;
    const std::string                     stream_;
    mutable std::mutex                    mtx_;
    std::unordered_map<uint32_t, WAVEHDR> headers_;
    Consumed                              consumed_;
    HWAVEOUT                              device_    = nullptr;
    MMRESULT                              last_fail_ = MMSYSERR_NOERROR;
    HostMessageThread                     thread_;
};

HostAudioOutput::HostAudioOutput(cerfcore::CerfEmulator& emu, std::string stream)
    : emu_(emu), stream_(std::move(stream)) {
    thread_.Start(emu.Get<cerfcore::InstanceThreads>(), [this](const MSG& msg) { OnMessage(msg); });
}

void HostAudioOutput::OnMessage(const MSG& msg) {
    if (msg.message != MM_WOM_DONE) return;
    WAVEHDR* const hdr = reinterpret_cast<WAVEHDR*>(msg.lParam);
    Consumed       consumed;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (device_) waveOutUnprepareHeader(device_, hdr, sizeof(WAVEHDR));
        consumed = consumed_;
    }
    consumed(static_cast<uint32_t>(hdr->dwUser));
}

bool HostAudioOutput::Open(const cerfcore::AudioFormat& format, Consumed consumed) {
    const WAVEFORMATEX fmt    = PcmWaveFormat(format);
    HWAVEOUT           device = nullptr;
    const MMRESULT     r      = waveOutOpen(&device, WAVE_MAPPER, &fmt, thread_.ThreadId(), 0, CALLBACK_THREAD);
    std::lock_guard<std::mutex> lk(mtx_);
    if (r != MMSYSERR_NOERROR) {
        if (r != last_fail_) {
            LOG(Caution, "%s: waveOutOpen(%u Hz x %u ch x %u bit) failed mmresult=%u "
                         "- silent-mode (blocks paced from their own duration)\n",
                stream_.c_str(), format.rate_hz, format.channels, format.bits, r);
        }
        last_fail_ = r;
        return false;
    }
    device_    = device;
    consumed_  = std::move(consumed);
    last_fail_ = MMSYSERR_NOERROR;
    LOG(Periph, "[%s] waveOut opened %u Hz x %u ch x %u bit\n", stream_.c_str(), format.rate_hz, format.channels,
        format.bits);
    return true;
}

void HostAudioOutput::Close() {
    std::lock_guard<std::mutex> lk(mtx_);
    waveOutReset(device_);
    const MMRESULT r = waveOutClose(device_);
    if (r != MMSYSERR_NOERROR) {
        LOG(Caution, "%s: waveOutClose failed mmresult=%u - device handle leaked\n", stream_.c_str(), r);
    }
    device_ = nullptr;
}

bool HostAudioOutput::Submit(uint32_t block, const uint8_t* bytes, uint32_t length) {
    std::lock_guard<std::mutex> lk(mtx_);
    WAVEHDR& hdr       = headers_[block];
    hdr                = WAVEHDR{};
    hdr.lpData         = reinterpret_cast<LPSTR>(const_cast<uint8_t*>(bytes));
    hdr.dwBufferLength = length;
    hdr.dwUser         = block;
    const char* call   = "waveOutPrepareHeader";
    MMRESULT    r      = waveOutPrepareHeader(device_, &hdr, sizeof(WAVEHDR));
    if (r == MMSYSERR_NOERROR) {
        call = "waveOutWrite";
        r    = waveOutWrite(device_, &hdr, sizeof(WAVEHDR));
        if (r == MMSYSERR_NOERROR) return true;
        waveOutUnprepareHeader(device_, &hdr, sizeof(WAVEHDR));
    }
    if (r != MMSYSERR_NODRIVER) emu_.Get<cerfcore::Fatal>().Die("%s: %s failed mmresult=%u", stream_.c_str(), call, r);
    LOG(Caution, "%s: host audio device lost (%s mmresult=%u) - silent-mode (blocks paced from their own duration)\n",
        stream_.c_str(), call, r);
    last_fail_ = r;
    return false;
}

void HostAudioOutput::Drop() {
    std::lock_guard<std::mutex> lk(mtx_);
    waveOutReset(device_);
}

bool HostAudioOutput::PlayedFrames(uint64_t& frames) const {
    std::lock_guard<std::mutex> lk(mtx_);
    MMTIME mmt{};
    mmt.wType = TIME_SAMPLES;
    if (waveOutGetPosition(device_, &mmt, sizeof(mmt)) != MMSYSERR_NOERROR || mmt.wType != TIME_SAMPLES) return false;
    frames = mmt.u.sample;
    return true;
}

class HostAudioOutputs final : public cerfcore::AudioOutputs {
public:
    using cerfcore::AudioOutputs::AudioOutputs;

    std::unique_ptr<cerfcore::AudioOutputDevice> CreateOutput(const std::string& stream) override {
        return std::make_unique<HostAudioOutput>(emu_, stream);
    }
};

}

REGISTER_SERVICE_AS(HostAudioOutputs, cerfcore::AudioOutputs);

}
