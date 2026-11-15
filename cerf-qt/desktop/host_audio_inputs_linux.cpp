#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/instance_threads.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/audio_inputs.h>

#include <alsa/asoundlib.h>

#include <cerrno>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace cerffrontend {

namespace {

class HostAudioInput final : public cerfcore::AudioInputDevice {
public:
    HostAudioInput(cerfcore::CerfEmulator& emu, std::string stream) : emu_(emu), stream_(std::move(stream)) {}
    HostAudioInput(const HostAudioInput&)            = delete;
    HostAudioInput& operator=(const HostAudioInput&) = delete;

    bool Open(const cerfcore::AudioFormat& format, Captured captured) override;
    void Close() override;

private:
    static constexpr uint32_t kRecordBufBytes = 4096u;
    static constexpr unsigned kBufferUs       = 92880;

    void ReadMain();

    cerfcore::CerfEmulator& emu_;
    const std::string       stream_;
    std::mutex              mtx_;
    Captured                captured_;
    snd_pcm_t*              pcm_         = nullptr;
    uint32_t                frame_bytes_ = 0;
    bool                    reading_     = false;
    std::thread             reader_;
};

bool HostAudioInput::Open(const cerfcore::AudioFormat& format, Captured captured) {
    snd_pcm_format_t pcm_format = SND_PCM_FORMAT_UNKNOWN;
    if (format.bits == 16u) pcm_format = SND_PCM_FORMAT_S16_LE;
    if (format.bits == 8u) pcm_format = SND_PCM_FORMAT_U8;
    snd_pcm_t* pcm = nullptr;
    int        err = -EINVAL;
    if (pcm_format != SND_PCM_FORMAT_UNKNOWN) {
        err = snd_pcm_open(&pcm, "default", SND_PCM_STREAM_CAPTURE, 0);
        if (err == 0) {
            err = snd_pcm_set_params(pcm, pcm_format, SND_PCM_ACCESS_RW_INTERLEAVED, format.channels, format.rate_hz,
                                     1, kBufferUs);
        }
        if (err == 0) err = snd_pcm_start(pcm);
    }
    if (err < 0) {
        if (pcm != nullptr) snd_pcm_close(pcm);
        LOG(Caution, "[%s] microphone capture unavailable at %u Hz (ALSA capture open: %s); the guest records "
                     "silence\n",
            stream_.c_str(), format.rate_hz, snd_strerror(err));
        return false;
    }
    pcm_         = pcm;
    frame_bytes_ = format.FrameBytes();
    captured_    = std::move(captured);
    reading_     = true;
    LOG(Periph, "[%s] ALSA capture opened %u Hz x %u ch x %u bit\n", stream_.c_str(), format.rate_hz,
        format.channels, format.bits);
    reader_ = emu_.Get<cerfcore::InstanceThreads>().Start([this] { ReadMain(); });
    return true;
}

void HostAudioInput::Close() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        reading_ = false;
        snd_pcm_drop(pcm_);
    }
    if (reader_.joinable()) reader_.join();
    snd_pcm_close(pcm_);
    pcm_ = nullptr;
}

void HostAudioInput::ReadMain() {
    std::vector<uint8_t>         buf(kRecordBufBytes);
    std::unique_lock<std::mutex> lk(mtx_);
    while (reading_) {
        lk.unlock();
        const snd_pcm_sframes_t n = snd_pcm_readi(pcm_, buf.data(), kRecordBufBytes / frame_bytes_);
        if (n > 0) captured_(buf.data(), static_cast<size_t>(n) * frame_bytes_);
        lk.lock();
        if (n >= 0 || !reading_) continue;
        int err = snd_pcm_recover(pcm_, static_cast<int>(n), 1);
        if (err == 0) err = snd_pcm_start(pcm_);
        if (err < 0) {
            LOG(Caution, "[%s] host microphone lost (snd_pcm_readi: %s); the guest records silence\n",
                stream_.c_str(), snd_strerror(err));
            return;
        }
    }
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
