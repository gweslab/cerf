#define NOMINMAX

#include "sa11xx_dma_audio_player.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../core/rate_probe.h"
#include "../../cpu/emulated_memory.h"
#include "../../state/emulation_freeze.h"
#include "../../host/audio_activity_widget.h"

#include <cstring>

namespace {
constexpr UINT kMsgSubmitPage = WM_USER + 0x10u;
}  /* namespace */

void Sa11xxDmaAudioPlayer::OnReady() {
    cfg_ = AudioConfig();
    for (uint32_t i = 0; i < kPagesQueued; ++i) slots_[i].bytes.resize(cfg_.max_page_bytes);
    sink_.Start(nullptr,
                [this](const MSG& msg) { OnThreadMessage(msg); },
                cfg_.log_tag);
    emu_.Get<Sa11xxDma>().RegisterSink(
        [this](const Sa11xxDma::ChannelState& st) { return OnDmaStart(st); });
    emu_.Get<AudioActivityWidget>().NotePresent();
}

void Sa11xxDmaAudioPlayer::OnShutdown() { sink_.Stop(); }

bool Sa11xxDmaAudioPlayer::OnDmaStart(const Sa11xxDma::ChannelState& st) {
    if ((st.ddar & cfg_.ddar_mask) != cfg_.ddar_value) return false;
    const uint32_t src_pa = st.buffer_b ? st.dbsb : st.dbsa;
    const uint32_t bytes  = st.buffer_b ? st.dbtb : st.dbta;
    if (bytes == 0 || bytes > cfg_.max_page_bytes) return false;

    auto* pending = new PendingPage{
        st.channel_index, st.buffer_b, src_pa, bytes, SampleRateHz(),
    };
    sink_.Post(kMsgSubmitPage, 0, reinterpret_cast<LPARAM>(pending));
#if CERF_DEV_MODE
    emu_.Get<RateProbe>().Inc(RateProbe::Counter::AudioMsgs);
#endif
    return true;
}

void Sa11xxDmaAudioPlayer::OnThreadMessage(const MSG& msg) {
    if (msg.message == kMsgSubmitPage) {
        auto* p = reinterpret_cast<PendingPage*>(msg.lParam);
        SubmitPage(*p);
        delete p;
    } else if (msg.message == MM_WOM_DONE) {
        OnPageDone(reinterpret_cast<LPWAVEHDR>(msg.lParam));
    }
}

Sa11xxDmaAudioPlayer::Slot* Sa11xxDmaAudioPlayer::AllocSlotLocked() {
    for (uint32_t tries = 0; tries < kPagesQueued; ++tries) {
        const uint32_t idx = (next_slot_ + tries) % kPagesQueued;
        if (!slots_[idx].in_flight) {
            next_slot_ = (idx + 1) % kPagesQueued;
            return &slots_[idx];
        }
    }
    return nullptr;
}

void Sa11xxDmaAudioPlayer::SubmitPage(const PendingPage& p) {
    sink_.EnsureFormat(p.rate_hz, cfg_.channels, cfg_.bits_per_sample,
                       cfg_.allow_resampler, /*busy=*/false);
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

void Sa11xxDmaAudioPlayer::LoadIntoSlot(Slot& slot, const PendingPage& p) {
    {
        auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
        auto& mem = emu_.Get<EmulatedMemory>();
        for (uint32_t i = 0; i < p.byte_count; ++i) {
            slot.bytes[i] = mem.ReadByte(p.src_pa + i);
        }
    }
    if (OutputMuted()) std::memset(slot.bytes.data(), 0, p.byte_count);
    else               emu_.Get<AudioActivityWidget>().MarkTx();
    slot.dma_channel = p.dma_channel;
    slot.buffer_b    = p.buffer_b;

    std::memset(&slot.hdr, 0, sizeof(slot.hdr));
    slot.hdr.lpData         = reinterpret_cast<LPSTR>(slot.bytes.data());
    slot.hdr.dwBufferLength = p.byte_count;
    slot.hdr.dwUser         = reinterpret_cast<DWORD_PTR>(&slot);

    {
        std::lock_guard<std::mutex> lk(slots_mtx_);
        slot.in_flight = true;
    }
    sink_.Play(&slot.hdr);
}

void Sa11xxDmaAudioPlayer::OnPageDone(LPWAVEHDR hdr) {
    if (!hdr) return;
    auto* slot = reinterpret_cast<Slot*>(hdr->dwUser);
    sink_.Unprepare(&slot->hdr);

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

    LOG(Periph, "[%s] waveOut DONE ch=%u buf=%c\n",
        cfg_.log_tag, completed_ch, completed_buf ? 'B' : 'A');
    /* Raises the DMA-done IRQ that wakes the guest wavedev IST; dropping this
       leaves the IST blocked on the audio DMA and deadlocks playback. */
    {
        auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
        emu_.Get<Sa11xxDma>().CompleteTransfer(completed_ch, completed_buf);
    }

    if (have_next) LoadIntoSlot(*slot, next_page);
}
