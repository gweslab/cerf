#include "../pcm_format.h"
#include "android_audio_rate.h"

#include <cerfcore/core/byte_order.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/instance_threads.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/audio_outputs.h>

#include <aaudio/AAudio.h>

#include <algorithm>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace cerffrontend {

namespace {

class AndroidAudioOutput final : public cerfcore::AudioOutputDevice {
public:
    AndroidAudioOutput(cerfcore::CerfEmulator& emu, std::string name);
    ~AndroidAudioOutput() override;
    AndroidAudioOutput(const AndroidAudioOutput&)            = delete;
    AndroidAudioOutput& operator=(const AndroidAudioOutput&) = delete;

    bool Open(const cerfcore::AudioFormat& format, Consumed consumed) override;
    void Close() override;
    bool Submit(uint32_t block, const uint8_t* bytes, uint32_t length) override;
    void Drop() override;
    bool PlayedFrames(uint64_t& frames) const override;

private:
    enum class Request : uint8_t { kNone, kOpen, kClose };

    struct Block {
        uint32_t       id;
        const uint8_t* bytes;
        uint32_t       length;
    };

    static constexpr int64_t  kWriteSliceNs = 10'000'000;
    static constexpr int64_t  kStateWaitNs  = 1'000'000'000;
    static constexpr uint32_t kChunkFrames  = 1024u;

    void            OwnerMain();
    void            FinishOwner();
    bool            OpenStreamLocked(std::unique_lock<std::mutex>& lk);
    void            CloseStreamLocked(std::unique_lock<std::mutex>& lk);
    void            FlushStreamLocked(std::unique_lock<std::mutex>& lk);
    const uint8_t*  DeviceFrames(const uint8_t* src, uint32_t frames);
    aaudio_result_t WriteBlock(AAudioStream* stream, const Block& block);
    bool            StopWriting();
    void            CompleteQueuedLocked();
    void            LoseDeviceLocked(std::unique_lock<std::mutex>& lk, const char* call, aaudio_result_t err);
    bool            Ask(std::unique_lock<std::mutex>& lk, Request request);

    const std::string       name_;
    mutable std::mutex      mtx_;
    std::condition_variable work_cv_;
    std::condition_variable done_cv_;
    std::deque<Block>       writes_;
    Consumed                consumed_;
    cerfcore::AudioFormat   requested_;
    AAudioStream*           stream_         = nullptr;
    Request                 request_        = Request::kNone;
    bool                    request_result_ = false;
    bool                    flush_          = false;
    bool                    abort_          = false;
    bool                    started_        = false;
    bool                    shutdown_       = false;
    uint16_t                bits_           = 0;
    uint16_t                channels_       = 0;
    uint32_t                repeat_         = 1;
    uint64_t                frames_written_ = 0;
    aaudio_result_t         last_fail_      = AAUDIO_OK;
    std::vector<int16_t>    widened_;
    std::thread             owner_thread_;
};

AndroidAudioOutput::AndroidAudioOutput(cerfcore::CerfEmulator& emu, std::string name) : name_(std::move(name)) {
    owner_thread_ = emu.Get<cerfcore::InstanceThreads>().Start([this] { OwnerMain(); }, [this] { FinishOwner(); });
}

AndroidAudioOutput::~AndroidAudioOutput() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        shutdown_ = true;
    }
    work_cv_.notify_all();
    if (owner_thread_.joinable()) owner_thread_.join();
}

void AndroidAudioOutput::CompleteQueuedLocked() {
    for (const Block& b : writes_) consumed_(b.id);
    writes_.clear();
}

void AndroidAudioOutput::OwnerMain() {
    std::unique_lock<std::mutex> lk(mtx_);
    while (true) {
        work_cv_.wait(lk, [this] {
            return shutdown_ || request_ != Request::kNone || flush_ || (stream_ != nullptr && !writes_.empty());
        });
        if (shutdown_) return;
        if (request_ == Request::kOpen) {
            request_result_ = OpenStreamLocked(lk);
            request_        = Request::kNone;
            done_cv_.notify_all();
            continue;
        }
        if (request_ == Request::kClose) {
            CompleteQueuedLocked();
            if (stream_ != nullptr) CloseStreamLocked(lk);
            request_result_ = true;
            request_        = Request::kNone;
            done_cv_.notify_all();
            continue;
        }
        if (flush_) {
            flush_ = false;
            if (stream_ != nullptr) FlushStreamLocked(lk);
            abort_ = false;
            continue;
        }
        const Block block = writes_.front();
        writes_.pop_front();
        AAudioStream* const stream = stream_;
        lk.unlock();
        const aaudio_result_t err = WriteBlock(stream, block);
        lk.lock();
        consumed_(block.id);
        if (err < 0 && !abort_ && !shutdown_ && request_ == Request::kNone && stream_ == stream)
            LoseDeviceLocked(lk, "AAudioStream_write", err);
    }
}

void AndroidAudioOutput::FinishOwner() {
    std::unique_lock<std::mutex> lk(mtx_);
    shutdown_ = true;
    CompleteQueuedLocked();
    if (stream_ != nullptr) CloseStreamLocked(lk);
    if (request_ != Request::kNone) {
        request_        = Request::kNone;
        request_result_ = false;
        done_cv_.notify_all();
    }
}

bool AndroidAudioOutput::StopWriting() {
    std::lock_guard<std::mutex> lk(mtx_);
    return abort_ || shutdown_ || request_ != Request::kNone;
}

const uint8_t* AndroidAudioOutput::DeviceFrames(const uint8_t* src, uint32_t frames) {
    if (bits_ == 16u && repeat_ == 1u) return src;
    const size_t channels = channels_;
    widened_.resize(static_cast<size_t>(frames) * repeat_ * channels);
    for (size_t f = 0; f < frames; ++f) {
        for (size_t ch = 0; ch < channels; ++ch) {
            const size_t  i      = f * channels + ch;
            const int16_t sample = bits_ == 8u ? static_cast<int16_t>((static_cast<int>(src[i]) - 128) * 256)
                                               : static_cast<int16_t>(cerfcore::cerf::le::U16(src, i * 2u));
            for (size_t r = 0; r < repeat_; ++r) widened_[(f * repeat_ + r) * channels + ch] = sample;
        }
    }
    return reinterpret_cast<const uint8_t*>(widened_.data());
}

aaudio_result_t AndroidAudioOutput::WriteBlock(AAudioStream* stream, const Block& block) {
    const uint32_t in_frame  = cerfcore::AudioFormat{0u, channels_, bits_}.FrameBytes();
    const uint32_t out_frame = cerfcore::AudioFormat{0u, channels_, 16u}.FrameBytes();
    const uint8_t* src       = block.bytes;
    uint32_t       frames    = block.length / in_frame;
    while (frames != 0u && !StopWriting()) {
        const uint32_t chunk = std::min(frames, kChunkFrames);
        const uint8_t* out   = DeviceFrames(src, chunk);
        const uint32_t total = chunk * repeat_;
        uint32_t       done  = 0;
        while (done != total) {
            if (StopWriting()) return AAUDIO_OK;
            const aaudio_result_t n = AAudioStream_write(stream, out + static_cast<size_t>(done) * out_frame,
                                                         static_cast<int32_t>(total - done), kWriteSliceNs);
            if (n < 0) return n;
            if (!started_) {
                const aaudio_result_t err = AAudioStream_requestStart(stream);
                if (err != AAUDIO_OK) return err;
                started_ = true;
            }
            std::lock_guard<std::mutex> lk(mtx_);
            frames_written_ += static_cast<uint64_t>(n);
            done += static_cast<uint32_t>(n);
        }
        src += static_cast<size_t>(chunk) * in_frame;
        frames -= chunk;
    }
    return AAUDIO_OK;
}

bool AndroidAudioOutput::OpenStreamLocked(std::unique_lock<std::mutex>& lk) {
    const cerfcore::AudioFormat format = requested_;
    const uint32_t              repeat = AaudioRateMultiple(format.rate_hz);
    AAudioStream*               stream = nullptr;
    aaudio_result_t             err    = AAUDIO_ERROR_INVALID_FORMAT;
    const char*                 step   = "format";
    lk.unlock();
    if (PcmFormatSupported(format)) {
        AAudioStreamBuilder* builder = nullptr;
        step = "AAudio_createStreamBuilder";
        err  = AAudio_createStreamBuilder(&builder);
        if (err == AAUDIO_OK) {
            AAudioStreamBuilder_setDirection(builder, AAUDIO_DIRECTION_OUTPUT);
            AAudioStreamBuilder_setSampleRate(builder, static_cast<int32_t>(format.rate_hz * repeat));
            AAudioStreamBuilder_setChannelCount(builder, format.channels);
            AAudioStreamBuilder_setFormat(builder, AAUDIO_FORMAT_PCM_I16);
            step = "AAudioStreamBuilder_openStream";
            err  = AAudioStreamBuilder_openStream(builder, &stream);
        }
        if (builder != nullptr) AAudioStreamBuilder_delete(builder);
    }
    lk.lock();
    if (err == AAUDIO_OK) {
        stream_         = stream;
        bits_           = format.bits;
        channels_       = format.channels;
        repeat_         = repeat;
        frames_written_ = 0;
        started_        = false;
        last_fail_      = AAUDIO_OK;
        LOG(Periph, "[%s] AAudio playback opened %u Hz x %u ch x %u bit (device %u Hz)\n", name_.c_str(),
            format.rate_hz, format.channels, format.bits, format.rate_hz * repeat);
        return true;
    }
    if (err != last_fail_) {
        LOG(Caution, "%s: AAudio playback open (%u Hz x %u ch x %u bit) failed at %s: %s "
                     "- silent-mode (blocks paced from their own duration)\n",
            name_.c_str(), format.rate_hz, format.channels, format.bits, step, AAudio_convertResultToText(err));
    }
    last_fail_ = err;
    return false;
}

void AndroidAudioOutput::CloseStreamLocked(std::unique_lock<std::mutex>& lk) {
    AAudioStream* const stream = stream_;
    stream_                    = nullptr;
    lk.unlock();
    AAudioStream_close(stream);
    lk.lock();
}

void AndroidAudioOutput::FlushStreamLocked(std::unique_lock<std::mutex>& lk) {
    AAudioStream* const stream = stream_;
    lk.unlock();
    aaudio_result_t       err   = AAudioStream_requestPause(stream);
    aaudio_stream_state_t state = AAudioStream_getState(stream);
    while (err == AAUDIO_OK && state == AAUDIO_STREAM_STATE_PAUSING)
        err = AAudioStream_waitForStateChange(stream, state, &state, kStateWaitNs);
    if (err == AAUDIO_OK) err = AAudioStream_requestFlush(stream);
    lk.lock();
    started_ = false;
    if (err != AAUDIO_OK && stream_ == stream) LoseDeviceLocked(lk, "AAudioStream_requestFlush", err);
}

void AndroidAudioOutput::LoseDeviceLocked(std::unique_lock<std::mutex>& lk, const char* call, aaudio_result_t err) {
    CompleteQueuedLocked();
    CloseStreamLocked(lk);
    LOG(Caution, "%s: host audio device lost (%s: %s) - silent-mode (blocks paced from their own duration)\n",
        name_.c_str(), call, AAudio_convertResultToText(err));
    last_fail_ = err;
}

bool AndroidAudioOutput::Ask(std::unique_lock<std::mutex>& lk, Request request) {
    request_ = request;
    work_cv_.notify_all();
    done_cv_.wait(lk, [this] { return request_ == Request::kNone; });
    return request_result_;
}

bool AndroidAudioOutput::Open(const cerfcore::AudioFormat& format, Consumed consumed) {
    std::unique_lock<std::mutex> lk(mtx_);
    if (shutdown_) return false;
    requested_ = format;
    consumed_  = std::move(consumed);
    return Ask(lk, Request::kOpen);
}

void AndroidAudioOutput::Close() {
    std::unique_lock<std::mutex> lk(mtx_);
    abort_ = true;
    if (!shutdown_) Ask(lk, Request::kClose);
    abort_ = false;
}

bool AndroidAudioOutput::Submit(uint32_t block, const uint8_t* bytes, uint32_t length) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (stream_ == nullptr) return false;
    writes_.push_back(Block{block, bytes, length});
    work_cv_.notify_all();
    return true;
}

void AndroidAudioOutput::Drop() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (stream_ == nullptr) return;
    abort_ = true;
    flush_ = true;
    CompleteQueuedLocked();
    work_cv_.notify_all();
}

bool AndroidAudioOutput::PlayedFrames(uint64_t& frames) const {
    std::lock_guard<std::mutex> lk(mtx_);
    if (stream_ == nullptr) return false;
    const int64_t delay = AAudioStream_getFramesWritten(stream_) - AAudioStream_getFramesRead(stream_);
    if (delay < 0 || static_cast<uint64_t>(delay) > frames_written_) return false;
    frames = (frames_written_ - static_cast<uint64_t>(delay)) / repeat_;
    return true;
}

class AndroidAudioOutputs final : public cerfcore::AudioOutputs {
public:
    using cerfcore::AudioOutputs::AudioOutputs;

    std::unique_ptr<cerfcore::AudioOutputDevice> CreateOutput(const std::string& stream) override {
        return std::make_unique<AndroidAudioOutput>(emu_, stream);
    }
};

}

REGISTER_SERVICE_AS(AndroidAudioOutputs, cerfcore::AudioOutputs);

}
