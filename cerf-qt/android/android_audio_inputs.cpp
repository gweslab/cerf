#include "../pcm_format.h"
#include "android_audio_rate.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/instance_threads.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/audio_inputs.h>

#include <aaudio/AAudio.h>

#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace cerffrontend {

namespace {

class AndroidAudioInput final : public cerfcore::AudioInputDevice {
public:
    AndroidAudioInput(cerfcore::CerfEmulator& emu, std::string name) : emu_(emu), name_(std::move(name)) {}
    AndroidAudioInput(const AndroidAudioInput&)            = delete;
    AndroidAudioInput& operator=(const AndroidAudioInput&) = delete;

    bool Open(const cerfcore::AudioFormat& format, Captured captured) override;
    void Close() override;

private:
    static constexpr int32_t kReadFrames  = 1024;
    static constexpr int64_t kReadSliceNs = 20'000'000;

    void ReadMain();
    bool Reading();
    void Deliver(const int16_t* samples, size_t frames);

    cerfcore::CerfEmulator& emu_;
    const std::string       name_;
    std::mutex              mtx_;
    Captured                captured_;
    AAudioStream*           stream_   = nullptr;
    uint16_t                bits_     = 0;
    uint16_t                channels_ = 0;
    uint32_t                group_    = 1;
    uint32_t                grouped_  = 0;
    bool                    reading_  = false;
    std::vector<int32_t>    sums_;
    std::vector<int16_t>    averaged_;
    std::vector<uint8_t>    narrowed_;
    std::thread             reader_;
};

bool AndroidAudioInput::Open(const cerfcore::AudioFormat& format, Captured captured) {
    aaudio_result_t err    = AAUDIO_ERROR_INVALID_FORMAT;
    const uint32_t  group  = AaudioRateMultiple(format.rate_hz);
    AAudioStream*   stream = nullptr;
    if (PcmFormatSupported(format)) {
        AAudioStreamBuilder* builder = nullptr;
        err = AAudio_createStreamBuilder(&builder);
        if (err == AAUDIO_OK) {
            AAudioStreamBuilder_setDirection(builder, AAUDIO_DIRECTION_INPUT);
            AAudioStreamBuilder_setSampleRate(builder, static_cast<int32_t>(format.rate_hz * group));
            AAudioStreamBuilder_setChannelCount(builder, format.channels);
            AAudioStreamBuilder_setFormat(builder, AAUDIO_FORMAT_PCM_I16);
            err = AAudioStreamBuilder_openStream(builder, &stream);
            AAudioStreamBuilder_delete(builder);
        }
        if (err == AAUDIO_OK) {
            err = AAudioStream_requestStart(stream);
            if (err != AAUDIO_OK) AAudioStream_close(stream);
        }
    }
    if (err != AAUDIO_OK) {
        LOG(Caution, "[%s] microphone capture unavailable at %u Hz (AAudio capture open: %s); the guest records "
                     "silence\n",
            name_.c_str(), format.rate_hz, AAudio_convertResultToText(err));
        return false;
    }
    stream_   = stream;
    bits_     = format.bits;
    channels_ = format.channels;
    group_    = group;
    grouped_  = 0;
    sums_.assign(channels_, 0);
    captured_ = std::move(captured);
    reading_  = true;
    LOG(Periph, "[%s] AAudio capture opened %u Hz x %u ch x %u bit (device %u Hz)\n", name_.c_str(), format.rate_hz,
        format.channels, format.bits, format.rate_hz * group);
    reader_ = emu_.Get<cerfcore::InstanceThreads>().Start([this] { ReadMain(); });
    return true;
}

void AndroidAudioInput::Close() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        reading_ = false;
    }
    if (reader_.joinable()) reader_.join();
    AAudioStream_close(stream_);
    stream_ = nullptr;
}

bool AndroidAudioInput::Reading() {
    std::lock_guard<std::mutex> lk(mtx_);
    return reading_;
}

void AndroidAudioInput::Deliver(const int16_t* samples, size_t frames) {
    const int16_t* out   = samples;
    size_t         count = frames * channels_;
    if (group_ != 1u) {
        averaged_.clear();
        for (size_t f = 0; f < frames; ++f) {
            for (size_t ch = 0; ch < channels_; ++ch) sums_[ch] += samples[f * channels_ + ch];
            if (++grouped_ != group_) continue;
            for (size_t ch = 0; ch < channels_; ++ch) {
                averaged_.push_back(static_cast<int16_t>(sums_[ch] / static_cast<int32_t>(group_)));
                sums_[ch] = 0;
            }
            grouped_ = 0;
        }
        out   = averaged_.data();
        count = averaged_.size();
    }
    if (count == 0u) return;
    if (bits_ == 8u) {
        narrowed_.resize(count);
        for (size_t i = 0; i < count; ++i) narrowed_[i] = static_cast<uint8_t>((out[i] >> 8) + 128);
        captured_(narrowed_.data(), count);
        return;
    }
    captured_(reinterpret_cast<const uint8_t*>(out), count * sizeof(int16_t));
}

void AndroidAudioInput::ReadMain() {
    std::vector<int16_t> samples(static_cast<size_t>(kReadFrames) * channels_);
    while (Reading()) {
        const aaudio_result_t n = AAudioStream_read(stream_, samples.data(), kReadFrames, kReadSliceNs);
        if (n > 0) Deliver(samples.data(), static_cast<size_t>(n));
        if (n >= 0) continue;
        LOG(Caution, "[%s] host microphone lost (AAudioStream_read: %s); the guest records silence\n",
            name_.c_str(), AAudio_convertResultToText(n));
        return;
    }
}

class AndroidAudioInputs final : public cerfcore::AudioInputs {
public:
    using cerfcore::AudioInputs::AudioInputs;

    std::unique_ptr<cerfcore::AudioInputDevice> CreateInput(const std::string& stream) override {
        return std::make_unique<AndroidAudioInput>(emu_, stream);
    }
};

}

REGISTER_SERVICE_AS(AndroidAudioInputs, cerfcore::AudioInputs);

}
