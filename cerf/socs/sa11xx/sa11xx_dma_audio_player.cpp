#define NOMINMAX

#include "sa11xx_dma_audio_player.h"

#include "../../core/cerf_emulator.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/audio_activity_widget.h"
#include "sa11xx_dma.h"

#include <cstring>

void Sa11xxDmaAudioPlayer::OnReady() {
    cfg_ = AudioConfig();
    out_.Start(cfg_.log_tag, 0u, cfg_.channels, cfg_.bits_per_sample, cfg_.allow_resampler);
    emu_.Get<Sa11xxDma>().RegisterTransmitObserver(this);
    emu_.Get<AudioActivityWidget>().NotePresent();
}

void Sa11xxDmaAudioPlayer::OnShutdown() { out_.Stop(); }

void Sa11xxDmaAudioPlayer::OnTransmitBlock(uint32_t ddar, uint32_t pa, uint32_t bytes,
                                           GuestCycleClock::Rate word_rate) {
    if (!Matches(ddar)) return;
    const uint64_t den  = word_rate.den * cfg_.channels;
    const uint32_t rate = static_cast<uint32_t>((word_rate.num + den / 2u) / den);
    if (rate != rate_) {
        rate_ = rate;
        out_.SetFormat(rate, cfg_.channels, cfg_.bits_per_sample);
    }
    if (!active_) {
        out_.BeginAudioOut({});
        active_ = true;
    }
    block_.resize(bytes);
    emu_.Get<EmulatedMemory>().CopyOut(pa, block_.data(), bytes);
    if (OutputMuted()) std::memset(block_.data(), 0, bytes);
    else               emu_.Get<AudioActivityWidget>().MarkTx();
    out_.QueueOutput(block_.data(), bytes);
}

void Sa11xxDmaAudioPlayer::OnTransmitStop(uint32_t ddar) {
    if (!Matches(ddar) || !active_) return;
    out_.FinishAudioOut();
    active_ = false;
}

void Sa11xxDmaAudioPlayer::OnTransmitRestored() {
    out_.StopAudioOut();
    active_ = false;
    rate_   = 0u;
}
