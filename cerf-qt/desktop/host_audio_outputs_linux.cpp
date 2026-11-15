#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/instance_threads.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/audio_outputs.h>

#include <alsa/asoundlib.h>

#include <cerrno>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>

namespace cerffrontend {

namespace {

class HostAudioOutput final : public cerfcore::AudioOutputDevice {
public:
    HostAudioOutput(cerfcore::CerfEmulator& emu, std::string stream);
    ~HostAudioOutput() override;
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

    static constexpr unsigned kBufferUs    = 92880;
    static constexpr int      kWaitSliceMs = 100;

    void WriterMain();
    void FinishWriter();
    int  WriteBlock(snd_pcm_t* pcm, const Block& block, uint32_t frame_bytes);
    void CompleteQueuedLocked();
    void LoseDeviceLocked(const char* call, int err);

    const std::string       stream_;
    mutable std::mutex      mtx_;
    std::condition_variable work_cv_;
    std::condition_variable idle_cv_;
    std::deque<Block>       writes_;
    Consumed                consumed_;
    snd_pcm_t*              pcm_            = nullptr;
    bool                    writing_        = false;
    bool                    abort_          = false;
    bool                    shutdown_       = false;
    uint32_t                frame_bytes_    = 0;
    uint64_t                frames_written_ = 0;
    int                     last_fail_      = 0;
    std::thread             writer_thread_;
};

HostAudioOutput::HostAudioOutput(cerfcore::CerfEmulator& emu, std::string stream) : stream_(std::move(stream)) {
    writer_thread_ = emu.Get<cerfcore::InstanceThreads>().Start([this] { WriterMain(); }, [this] { FinishWriter(); });
}

HostAudioOutput::~HostAudioOutput() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        shutdown_ = true;
    }
    work_cv_.notify_all();
    if (writer_thread_.joinable()) writer_thread_.join();
}

void HostAudioOutput::FinishWriter() {
    std::lock_guard<std::mutex> lk(mtx_);
    shutdown_ = true;
    writing_  = false;
    idle_cv_.notify_all();
}

void HostAudioOutput::CompleteQueuedLocked() {
    for (const Block& b : writes_) consumed_(b.id);
    writes_.clear();
}

void HostAudioOutput::WriterMain() {
    std::unique_lock<std::mutex> lk(mtx_);
    while (true) {
        work_cv_.wait(lk, [this] { return shutdown_ || (!writes_.empty() && pcm_ != nullptr); });
        if (shutdown_) return;
        const Block block = writes_.front();
        writes_.pop_front();
        snd_pcm_t* const pcm         = pcm_;
        const uint32_t   frame_bytes = frame_bytes_;
        writing_                     = true;
        abort_                       = false;
        lk.unlock();
        const int err = WriteBlock(pcm, block, frame_bytes);
        lk.lock();
        writing_ = false;
        idle_cv_.notify_all();
        consumed_(block.id);
        if (err < 0 && !abort_ && pcm_ == pcm) LoseDeviceLocked("snd_pcm_writei", err);
    }
}

int HostAudioOutput::WriteBlock(snd_pcm_t* pcm, const Block& block, uint32_t frame_bytes) {
    const uint8_t*    src    = block.bytes;
    snd_pcm_uframes_t frames = block.length / frame_bytes;
    while (frames != 0u) {
        std::unique_lock<std::mutex> lk(mtx_);
        if (abort_ || shutdown_) return 0;
        const snd_pcm_sframes_t n = snd_pcm_writei(pcm, src, frames);
        if (n > 0) {
            frames_written_ += static_cast<uint64_t>(n);
            src += static_cast<size_t>(n) * frame_bytes;
            frames -= static_cast<snd_pcm_uframes_t>(n);
            continue;
        }
        if (n == -EAGAIN || n == 0) {
            lk.unlock();
            const int ready = snd_pcm_wait(pcm, kWaitSliceMs);
            if (ready >= 0) continue;
            lk.lock();
            if (abort_ || shutdown_) return 0;
            const int recovered = snd_pcm_recover(pcm, ready, 1);
            if (recovered < 0) return recovered;
            continue;
        }
        const int err = n == -EBADFD ? snd_pcm_prepare(pcm) : snd_pcm_recover(pcm, static_cast<int>(n), 1);
        if (err < 0) return err;
    }
    return 0;
}

bool HostAudioOutput::Open(const cerfcore::AudioFormat& format, Consumed consumed) {
    std::lock_guard<std::mutex> lk(mtx_);
    int              err = 0;
    snd_pcm_t*       pcm = nullptr;
    snd_pcm_format_t pcm_format = SND_PCM_FORMAT_UNKNOWN;
    if (format.bits == 16u) pcm_format = SND_PCM_FORMAT_S16_LE;
    if (format.bits == 8u) pcm_format = SND_PCM_FORMAT_U8;
    if (pcm_format == SND_PCM_FORMAT_UNKNOWN) {
        err = -EINVAL;
    } else {
        err = snd_pcm_open(&pcm, "default", SND_PCM_STREAM_PLAYBACK, SND_PCM_NONBLOCK);
        if (err == 0) {
            err = snd_pcm_set_params(pcm, pcm_format, SND_PCM_ACCESS_RW_INTERLEAVED, format.channels, format.rate_hz,
                                     1, kBufferUs);
        }
    }
    if (err < 0) {
        if (pcm != nullptr) snd_pcm_close(pcm);
        if (err != last_fail_) {
            LOG(Caution, "%s: ALSA playback open (%u Hz x %u ch x %u bit) failed: %s "
                         "- silent-mode (blocks paced from their own duration)\n",
                stream_.c_str(), format.rate_hz, format.channels, format.bits, snd_strerror(err));
        }
        last_fail_ = err;
        return false;
    }
    pcm_            = pcm;
    consumed_       = std::move(consumed);
    frame_bytes_    = format.FrameBytes();
    frames_written_ = 0;
    last_fail_      = 0;
    LOG(Periph, "[%s] ALSA playback opened %u Hz x %u ch x %u bit\n", stream_.c_str(), format.rate_hz,
        format.channels, format.bits);
    work_cv_.notify_all();
    return true;
}

void HostAudioOutput::Close() {
    std::unique_lock<std::mutex> lk(mtx_);
    if (pcm_ == nullptr) return;
    abort_ = true;
    snd_pcm_drop(pcm_);
    idle_cv_.wait(lk, [this] { return !writing_; });
    CompleteQueuedLocked();
    snd_pcm_close(pcm_);
    pcm_ = nullptr;
}

bool HostAudioOutput::Submit(uint32_t block, const uint8_t* bytes, uint32_t length) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (pcm_ == nullptr) return false;
    writes_.push_back(Block{block, bytes, length});
    work_cv_.notify_all();
    return true;
}

void HostAudioOutput::LoseDeviceLocked(const char* call, int err) {
    snd_pcm_close(pcm_);
    pcm_ = nullptr;
    CompleteQueuedLocked();
    LOG(Caution, "%s: host audio device lost (%s: %s) - silent-mode (blocks paced from their own duration)\n",
        stream_.c_str(), call, snd_strerror(err));
    last_fail_ = err;
}

bool HostAudioOutput::PlayedFrames(uint64_t& frames) const {
    std::lock_guard<std::mutex> lk(mtx_);
    snd_pcm_sframes_t delay = 0;
    if (pcm_ == nullptr || snd_pcm_delay(pcm_, &delay) < 0 || delay < 0 ||
        static_cast<uint64_t>(delay) > frames_written_) {
        return false;
    }
    frames = frames_written_ - static_cast<uint64_t>(delay);
    return true;
}

void HostAudioOutput::Drop() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (pcm_ == nullptr) return;
    abort_ = true;
    snd_pcm_drop(pcm_);
    CompleteQueuedLocked();
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
