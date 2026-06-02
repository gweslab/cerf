#define NOMINMAX

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../core/rate_probe.h"
#include "../../core/service.h"
#include "../../boards/board_detector.h"
#include "../../cpu/emulated_memory.h"
#include "../../socs/sa1110/sa1110_dma.h"

#include <windows.h>
#include <mmsystem.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

namespace {

constexpr uint32_t kDdarSspTxMask  = 0xFFFFFF00u;
constexpr uint32_t kDdarSspTxValue = 0x81C01B00u;

constexpr uint32_t kSampleRate     = 22050u;
constexpr uint16_t kChannels       = 2u;
constexpr uint16_t kBitsPerSample  = 16u;
constexpr uint32_t kMaxPageBytes   = 16384u;
constexpr uint32_t kPagesQueued    = 4u;

constexpr UINT kMsgSubmitPage = WM_USER + 0x10u;

struct PendingPage {
    uint32_t dma_channel;
    bool     buffer_b;
    uint32_t src_pa;
    uint32_t byte_count;
};

class Ipaq3650AudioPlayer : public Service {
public:
    using Service::Service;
    ~Ipaq3650AudioPlayer() override {
        shutdown_.store(true, std::memory_order_release);
        if (audio_thread_id_) {
            PostThreadMessageW(audio_thread_id_, WM_QUIT, 0, 0);
        }
        if (audio_thread_.joinable()) audio_thread_.join();
        if (out_device_)        waveOutClose(out_device_);
        if (thread_ready_event_) CloseHandle(thread_ready_event_);
    }

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::Ipaq3650;
    }

    void OnReady() override {
        for (uint32_t i = 0; i < kPagesQueued; ++i) {
            slots_[i].bytes.resize(kMaxPageBytes);
        }
        thread_ready_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        audio_thread_ = std::thread([this] { AudioThreadMain(); });
        WaitForSingleObject(thread_ready_event_, INFINITE);

        emu_.Get<Sa1110Dma>().RegisterSink(
            [this](const Sa1110Dma::ChannelState& st) {
                return OnDmaStart(st);
            });
    }

private:
    struct Slot {
        WAVEHDR              hdr{};
        std::vector<uint8_t> bytes;
        uint32_t             dma_channel = 0;
        bool                 buffer_b    = false;
        bool                 in_flight   = false;
    };

    HWAVEOUT          out_device_         = nullptr;
    DWORD             audio_thread_id_    = 0;
    HANDLE            thread_ready_event_ = nullptr;
    std::thread       audio_thread_;
    std::atomic<bool> shutdown_{false};

    std::mutex             slots_mtx_;
    Slot                   slots_[kPagesQueued];
    uint32_t               next_slot_ = 0;
    std::deque<PendingPage> page_queue_;
    bool                   waveout_open_attempted_ = false;

    bool OnDmaStart(const Sa1110Dma::ChannelState& st) {
        if ((st.ddar & kDdarSspTxMask) != kDdarSspTxValue) return false;
        const uint32_t src_pa = st.buffer_b ? st.dbsb : st.dbsa;
        const uint32_t bytes  = st.buffer_b ? st.dbtb : st.dbta;
        if (bytes == 0) return false;
        if (bytes > kMaxPageBytes) return false;

        auto* pending = new PendingPage{
            st.channel_index, st.buffer_b, src_pa, bytes,
        };
        PostThreadMessageW(audio_thread_id_, kMsgSubmitPage,
                           0, reinterpret_cast<LPARAM>(pending));
#if CERF_DEV_MODE
        emu_.Get<RateProbe>().Inc(RateProbe::Counter::AudioMsgs);
#endif
        return true;
    }

    void AudioThreadMain() {
        audio_thread_id_ = GetCurrentThreadId();
        MSG msg;
        PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
        SetEvent(thread_ready_event_);

        while (!shutdown_.load(std::memory_order_acquire) &&
               GetMessageW(&msg, nullptr, 0, 0) > 0) {
            if (msg.message == kMsgSubmitPage) {
                if (!waveout_open_attempted_) OpenWaveOut();
                auto* p = reinterpret_cast<PendingPage*>(msg.lParam);
                SubmitPage(*p);
                delete p;
                continue;
            }
            if (msg.message == MM_WOM_DONE) {
                auto* hdr = reinterpret_cast<LPWAVEHDR>(msg.lParam);
                OnPageDone(hdr);
                continue;
            }
        }
    }

    void OpenWaveOut() {
        waveout_open_attempted_ = true;
        WAVEFORMATEX fmt{};
        fmt.wFormatTag      = WAVE_FORMAT_PCM;
        fmt.nChannels       = kChannels;
        fmt.nSamplesPerSec  = kSampleRate;
        fmt.wBitsPerSample  = kBitsPerSample;
        fmt.nBlockAlign     = static_cast<uint16_t>(
                                (fmt.wBitsPerSample / 8) * fmt.nChannels);
        fmt.nAvgBytesPerSec = fmt.nSamplesPerSec * fmt.nBlockAlign;

        const MMRESULT r = waveOutOpen(&out_device_, WAVE_MAPPER, &fmt,
                                       audio_thread_id_, 0,
                                       CALLBACK_THREAD | WAVE_FORMAT_DIRECT);
        if (r != MMSYSERR_NOERROR) {
            LOG(Caution, "Ipaq3650AudioPlayer: waveOutOpen failed mmresult=%u\n", r);
            out_device_ = nullptr;
        } else {
            LOG(Periph, "[Ipaq3650AudioPlayer] waveOut opened %u Hz x %u ch x %u bit\n",
                kSampleRate, kChannels, kBitsPerSample);
        }
    }

    Slot* AllocSlotLocked() {
        for (uint32_t tries = 0; tries < kPagesQueued; ++tries) {
            const uint32_t idx = (next_slot_ + tries) % kPagesQueued;
            if (!slots_[idx].in_flight) {
                next_slot_ = (idx + 1) % kPagesQueued;
                return &slots_[idx];
            }
        }
        return nullptr;
    }

    void LoadIntoSlot(Slot& slot, const PendingPage& p) {
        auto& mem = emu_.Get<EmulatedMemory>();
        for (uint32_t i = 0; i < p.byte_count; ++i) {
            slot.bytes[i] = mem.ReadByte(p.src_pa + i);
        }
        slot.dma_channel = p.dma_channel;
        slot.buffer_b    = p.buffer_b;

        std::memset(&slot.hdr, 0, sizeof(slot.hdr));
        slot.hdr.lpData         = reinterpret_cast<LPSTR>(slot.bytes.data());
        slot.hdr.dwBufferLength = p.byte_count;
        slot.hdr.dwUser         = reinterpret_cast<DWORD_PTR>(&slot);

        MMRESULT r = waveOutPrepareHeader(out_device_, &slot.hdr,
                                          sizeof(WAVEHDR));
        if (r != MMSYSERR_NOERROR) {
            LOG(Caution, "Ipaq3650AudioPlayer: waveOutPrepareHeader failed %u\n", r);
            emu_.Get<Sa1110Dma>().CompleteTransfer(p.dma_channel, p.buffer_b);
            return;
        }
        {
            std::lock_guard<std::mutex> lk(slots_mtx_);
            slot.in_flight = true;
        }
        r = waveOutWrite(out_device_, &slot.hdr, sizeof(WAVEHDR));
        if (r != MMSYSERR_NOERROR) {
            LOG(Caution, "Ipaq3650AudioPlayer: waveOutWrite failed %u\n", r);
            waveOutUnprepareHeader(out_device_, &slot.hdr, sizeof(WAVEHDR));
            {
                std::lock_guard<std::mutex> lk(slots_mtx_);
                slot.in_flight = false;
            }
            emu_.Get<Sa1110Dma>().CompleteTransfer(p.dma_channel, p.buffer_b);
        }
    }

    void SubmitPage(const PendingPage& p) {
        if (!out_device_) {
            emu_.Get<Sa1110Dma>().CompleteTransfer(p.dma_channel, p.buffer_b);
            return;
        }
        Slot* slot;
        {
            std::lock_guard<std::mutex> lk(slots_mtx_);
            slot = AllocSlotLocked();
            if (!slot) {
                page_queue_.push_back(p);
                return;
            }
        }
        LoadIntoSlot(*slot, p);
    }

    void OnPageDone(LPWAVEHDR hdr) {
        if (!hdr || !out_device_) return;
        auto* slot = reinterpret_cast<Slot*>(hdr->dwUser);
        waveOutUnprepareHeader(out_device_, &slot->hdr, sizeof(WAVEHDR));

        const uint32_t completed_ch  = slot->dma_channel;
        const bool     completed_buf = slot->buffer_b;
        PendingPage    next_page{};
        bool           have_next = false;
        {
            std::lock_guard<std::mutex> lk(slots_mtx_);
            slot->in_flight = false;
            if (!page_queue_.empty()) {
                next_page = page_queue_.front();
                page_queue_.pop_front();
                have_next = true;
            }
        }

        LOG(Periph, "[Ipaq3650AudioPlayer] waveOut DONE ch=%u buf=%c\n",
            completed_ch, completed_buf ? 'B' : 'A');
        emu_.Get<Sa1110Dma>().CompleteTransfer(completed_ch, completed_buf);

        if (have_next) LoadIntoSlot(*slot, next_page);
    }
};

}  /* namespace */

REGISTER_SERVICE(Ipaq3650AudioPlayer);
