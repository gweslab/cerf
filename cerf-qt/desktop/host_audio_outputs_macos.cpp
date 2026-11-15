#include "../pcm_format.h"
#include "core_audio_format.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/audio_outputs.h>

#include <AudioToolbox/AudioToolbox.h>

#include <algorithm>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <utility>

namespace cerffrontend {

namespace {

class HostAudioOutput final : public cerfcore::AudioOutputDevice {
public:
    explicit HostAudioOutput(std::string stream) : stream_(std::move(stream)) {}
    HostAudioOutput(const HostAudioOutput&)            = delete;
    HostAudioOutput& operator=(const HostAudioOutput&) = delete;

    bool Open(const cerfcore::AudioFormat& format, Consumed consumed) override;
    void Close() override;
    bool Submit(uint32_t block, const uint8_t* bytes, uint32_t length) override;
    void Drop() override;
    bool PlayedFrames(uint64_t& frames) const override;

private:
    struct Block {
        uint32_t       id;
        const uint8_t* bytes;
        uint32_t       length;
    };

    struct Stream {
        HostAudioOutput* owner;
        uint8_t          silence;
    };

    static OSStatus Render(void* ref, AudioUnitRenderActionFlags* flags, const AudioTimeStamp* stamp, UInt32 bus,
                           UInt32 frames, AudioBufferList* io);
    static OSStatus CreateUnit(const cerfcore::AudioFormat& format, Stream* stream, AudioUnit& unit,
                               const char*& step);
    void FillLocked(uint8_t* out, uint32_t bytes);
    void DropQueuedLocked();

    const std::string  stream_;
    mutable std::mutex mtx_;
    std::deque<Block>  writes_;
    Consumed           consumed_;
    uint32_t           head_offset_   = 0;
    AudioUnit          unit_          = nullptr;
    Stream*            render_        = nullptr;
    uint32_t           frame_bytes_   = 0;
    uint64_t           frames_played_ = 0;
    OSStatus           last_fail_     = noErr;
};

OSStatus HostAudioOutput::Render(void* ref, AudioUnitRenderActionFlags*, const AudioTimeStamp*, UInt32, UInt32,
                                 AudioBufferList* io) {
    Stream* const               stream = static_cast<Stream*>(ref);
    HostAudioOutput* const      self   = stream->owner;
    std::lock_guard<std::mutex> lk(self->mtx_);
    for (UInt32 i = 0; i < io->mNumberBuffers; ++i) {
        uint8_t* const out   = static_cast<uint8_t*>(io->mBuffers[i].mData);
        const uint32_t bytes = io->mBuffers[i].mDataByteSize;
        if (self->render_ == stream) {
            self->FillLocked(out, bytes);
        } else {
            std::memset(out, stream->silence, bytes);
        }
    }
    return noErr;
}

void HostAudioOutput::FillLocked(uint8_t* out, uint32_t bytes) {
    uint32_t filled = 0;
    while (filled < bytes && !writes_.empty()) {
        const Block    block = writes_.front();
        const uint32_t n     = std::min(bytes - filled, block.length - head_offset_);
        std::memcpy(out + filled, block.bytes + head_offset_, n);
        filled += n;
        head_offset_ += n;
        if (head_offset_ == block.length) {
            writes_.pop_front();
            head_offset_ = 0;
            consumed_(block.id);
        }
    }
    frames_played_ += filled / frame_bytes_;
    if (filled < bytes) std::memset(out + filled, render_->silence, bytes - filled);
}

OSStatus HostAudioOutput::CreateUnit(const cerfcore::AudioFormat& format, Stream* stream, AudioUnit& unit,
                                     const char*& step) {
    AudioComponentDescription desc{};
    desc.componentType             = kAudioUnitType_Output;
    desc.componentSubType          = kAudioUnitSubType_DefaultOutput;
    desc.componentManufacturer     = kAudioUnitManufacturer_Apple;
    const AudioComponent component = ::AudioComponentFindNext(nullptr, &desc);
    if (component == nullptr) {
        step = "AudioComponentFindNext";
        return kAudio_ParamError;
    }
    const AudioStreamBasicDescription fmt = LinearPcmDescription(format);
    AURenderCallbackStruct            callback{&Render, stream};
    OSStatus                          err = noErr;
    if ((err = ::AudioComponentInstanceNew(component, &unit)) != noErr) {
        step = "AudioComponentInstanceNew";
    } else if ((err = ::AudioUnitSetProperty(unit, kAudioUnitProperty_StreamFormat, kAudioUnitScope_Input, 0, &fmt,
                                             sizeof(fmt))) != noErr) {
        step = "StreamFormat";
    } else if ((err = ::AudioUnitSetProperty(unit, kAudioUnitProperty_SetRenderCallback, kAudioUnitScope_Input, 0,
                                             &callback, sizeof(callback))) != noErr) {
        step = "SetRenderCallback";
    } else if ((err = ::AudioUnitInitialize(unit)) != noErr) {
        step = "AudioUnitInitialize";
    }
    return err;
}

bool HostAudioOutput::Open(const cerfcore::AudioFormat& format, Consumed consumed) {
    auto*       stream = new Stream{this, static_cast<uint8_t>(format.bits == 8u ? 0x80u : 0u)};
    AudioUnit   unit   = nullptr;
    OSStatus    err    = kAudio_ParamError;
    const char* step   = "format";
    if (PcmFormatSupported(format)) {
        step = nullptr;
        err  = CreateUnit(format, stream, unit, step);
    }
    if (step == nullptr) {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            unit_          = unit;
            render_        = stream;
            consumed_      = std::move(consumed);
            frame_bytes_   = format.FrameBytes();
            frames_played_ = 0;
            head_offset_   = 0;
            last_fail_     = noErr;
        }
        err = ::AudioOutputUnitStart(unit);
        if (err == noErr) {
            LOG(Periph, "[%s] CoreAudio playback opened %u Hz x %u ch x %u bit\n", stream_.c_str(), format.rate_hz,
                format.channels, format.bits);
            return true;
        }
        step = "AudioOutputUnitStart";
        std::lock_guard<std::mutex> lk(mtx_);
        unit_   = nullptr;
        render_ = nullptr;
        DropQueuedLocked();
    }
    if (unit != nullptr) {
        ::AudioUnitUninitialize(unit);
        ::AudioComponentInstanceDispose(unit);
    }
    delete stream;
    std::lock_guard<std::mutex> lk(mtx_);
    if (err != last_fail_) {
        LOG(Caution, "%s: CoreAudio playback open (%u Hz x %u ch x %u bit) failed at %s: OSStatus %d "
                     "- silent-mode (blocks paced from their own duration)\n",
            stream_.c_str(), format.rate_hz, format.channels, format.bits, step, static_cast<int>(err));
    }
    last_fail_ = err;
    return false;
}

void HostAudioOutput::DropQueuedLocked() {
    for (const Block& b : writes_) consumed_(b.id);
    writes_.clear();
    head_offset_ = 0;
}

void HostAudioOutput::Close() {
    AudioUnit unit   = nullptr;
    Stream*   stream = nullptr;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        unit    = unit_;
        stream  = render_;
        unit_   = nullptr;
        render_ = nullptr;
        DropQueuedLocked();
    }
    ::AudioOutputUnitStop(unit);
    ::AudioUnitUninitialize(unit);
    ::AudioComponentInstanceDispose(unit);
    delete stream;
}

bool HostAudioOutput::Submit(uint32_t block, const uint8_t* bytes, uint32_t length) {
    std::lock_guard<std::mutex> lk(mtx_);
    writes_.push_back(Block{block, bytes, length});
    return true;
}

void HostAudioOutput::Drop() {
    std::lock_guard<std::mutex> lk(mtx_);
    DropQueuedLocked();
}

bool HostAudioOutput::PlayedFrames(uint64_t& frames) const {
    std::lock_guard<std::mutex> lk(mtx_);
    frames = frames_played_;
    return true;
}

class HostAudioOutputs final : public cerfcore::AudioOutputs {
public:
    using cerfcore::AudioOutputs::AudioOutputs;

    std::unique_ptr<cerfcore::AudioOutputDevice> CreateOutput(const std::string& stream) override {
        return std::make_unique<HostAudioOutput>(stream);
    }
};

}

REGISTER_SERVICE_AS(HostAudioOutputs, cerfcore::AudioOutputs);

}
