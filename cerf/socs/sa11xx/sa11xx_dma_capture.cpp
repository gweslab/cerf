#define NOMINMAX

#include "sa11xx_dma_capture.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/audio_activity_widget.h"
#include "sa11xx_dma.h"

#include <algorithm>
#include <vector>

namespace {
constexpr UINT kMsgOpen = WM_USER + 0x10u;
}

void Sa11xxDmaCapture::OnReady() {
    cfg_ = AudioConfig();
    sink_.Start(nullptr, [this](const MSG& msg) { OnThreadMessage(msg); }, cfg_.log_tag);
    emu_.Get<Sa11xxDma>().RegisterReceiveSource(this);
    emu_.Get<AudioActivityWidget>().NotePresent();
}

void Sa11xxDmaCapture::OnShutdown() { sink_.Stop(); }

bool Sa11xxDmaCapture::FillReceived(uint32_t ddar, uint32_t pa, uint32_t bytes,
                                    GuestCycleClock::Rate word_rate) {
    if ((ddar & cfg_.ddar_mask) != cfg_.ddar_value) return false;
    const uint64_t den  = word_rate.den * cfg_.channels;
    const uint32_t rate = static_cast<uint32_t>((word_rate.num + den / 2u) / den);
    if (requested_rate_.exchange(rate) != rate) sink_.Post(kMsgOpen);
    std::vector<uint8_t> data(bytes, 0u);
    size_t taken = 0;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        taken = std::min<size_t>(bytes, fifo_.size());
        std::copy(fifo_.begin(), fifo_.begin() + taken, data.begin());
        fifo_.erase(fifo_.begin(), fifo_.begin() + taken);
    }
    emu_.Get<EmulatedMemory>().CopyIn(pa, data.data(), bytes);
    if (taken != 0u) emu_.Get<AudioActivityWidget>().MarkRx();
    return true;
}

void Sa11xxDmaCapture::OnThreadMessage(const MSG& msg) {
    if (msg.message == kMsgOpen) {
        OpenOnThread();
    } else if (msg.message == MM_WIM_DATA) {
        auto* hdr = reinterpret_cast<LPWAVEHDR>(msg.lParam);
        if (!hdr) return;
        OnRecordedData(reinterpret_cast<const uint8_t*>(hdr->lpData), hdr->dwBytesRecorded);
        sink_.Requeue(hdr);
    }
}

void Sa11xxDmaCapture::OpenOnThread() {
    const uint32_t rate = requested_rate_.load();
    if (rate == open_rate_) return;
    open_rate_ = rate;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        fifo_.clear();
    }
    if (!sink_.EnsureFormat(rate, cfg_.channels, cfg_.bits_per_sample)) {
        LOG(Caution, "[%s] microphone capture unavailable at %u Hz (host waveIn open failed); "
                     "the guest records silence\n", cfg_.log_tag, rate);
    }
}

void Sa11xxDmaCapture::OnRecordedData(const uint8_t* data, uint32_t bytes) {
    if (bytes == 0u) return;
    std::lock_guard<std::mutex> lk(mtx_);
    fifo_.insert(fifo_.end(), data, data + bytes);
    const size_t cap = static_cast<size_t>(cfg_.max_page_bytes) * 4u;
    if (fifo_.size() > cap) fifo_.erase(fifo_.begin(), fifo_.end() - cap);
}
