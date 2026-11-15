#include "../pcm_format.h"
#include "core_audio_format.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/audio_inputs.h>

#include <AudioToolbox/AudioToolbox.h>

#include <memory>
#include <string>
#include <utility>

namespace cerffrontend {

namespace {

class HostAudioInput final : public cerfcore::AudioInputDevice {
public:
    explicit HostAudioInput(std::string stream) : stream_(std::move(stream)) {}
    HostAudioInput(const HostAudioInput&)            = delete;
    HostAudioInput& operator=(const HostAudioInput&) = delete;

    bool Open(const cerfcore::AudioFormat& format, Captured captured) override;
    void Close() override;

private:
    static constexpr uint32_t kRecordBufBytes = 4096u;
    static constexpr uint32_t kRecordBuffers  = 3u;

    static void Input(void* user, AudioQueueRef queue, AudioQueueBufferRef buffer, const AudioTimeStamp* start,
                      UInt32 packets, const AudioStreamPacketDescription* descriptions);

    const std::string stream_;
    Captured          captured_;
    AudioQueueRef     queue_ = nullptr;
};

void HostAudioInput::Input(void* user, AudioQueueRef queue, AudioQueueBufferRef buffer, const AudioTimeStamp*,
                           UInt32, const AudioStreamPacketDescription*) {
    HostAudioInput* const self = static_cast<HostAudioInput*>(user);
    if (buffer->mAudioDataByteSize != 0u) {
        self->captured_(static_cast<const uint8_t*>(buffer->mAudioData), buffer->mAudioDataByteSize);
    }
    ::AudioQueueEnqueueBuffer(queue, buffer, 0, nullptr);
}

bool HostAudioInput::Open(const cerfcore::AudioFormat& format, Captured captured) {
    const uint32_t frame = format.FrameBytes();
    OSStatus       err   = kAudio_ParamError;
    const char*    step  = "format";
    AudioQueueRef  queue = nullptr;
    captured_            = std::move(captured);
    if (PcmFormatSupported(format)) {
        const AudioStreamBasicDescription fmt = LinearPcmDescription(format);
        step = "AudioQueueNewInput";
        err  = ::AudioQueueNewInput(&fmt, &Input, this, nullptr, nullptr, 0, &queue);
        for (uint32_t i = 0; err == noErr && i < kRecordBuffers; ++i) {
            AudioQueueBufferRef buffer = nullptr;
            step = "AudioQueueAllocateBuffer";
            err  = ::AudioQueueAllocateBuffer(queue, kRecordBufBytes / frame * frame, &buffer);
            if (err == noErr) {
                step = "AudioQueueEnqueueBuffer";
                err  = ::AudioQueueEnqueueBuffer(queue, buffer, 0, nullptr);
            }
        }
        if (err == noErr) {
            step = "AudioQueueStart";
            err  = ::AudioQueueStart(queue, nullptr);
        }
    }
    if (err != noErr) {
        if (queue != nullptr) ::AudioQueueDispose(queue, true);
        LOG(Caution, "[%s] microphone capture unavailable at %u Hz (CoreAudio %s: OSStatus %d); the guest records "
                     "silence\n",
            stream_.c_str(), format.rate_hz, step, static_cast<int>(err));
        return false;
    }
    queue_ = queue;
    LOG(Periph, "[%s] CoreAudio capture opened %u Hz x %u ch x %u bit\n", stream_.c_str(), format.rate_hz,
        format.channels, format.bits);
    return true;
}

void HostAudioInput::Close() {
    ::AudioQueueStop(queue_, true);
    ::AudioQueueDispose(queue_, true);
    queue_ = nullptr;
}

class HostAudioInputs final : public cerfcore::AudioInputs {
public:
    using cerfcore::AudioInputs::AudioInputs;

    std::unique_ptr<cerfcore::AudioInputDevice> CreateInput(const std::string& stream) override {
        return std::make_unique<HostAudioInput>(stream);
    }
};

}

REGISTER_SERVICE_AS(HostAudioInputs, cerfcore::AudioInputs);

}
