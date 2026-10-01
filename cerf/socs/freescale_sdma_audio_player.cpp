#include "freescale_sdma_audio_player.h"

#include "../core/byte_order.h"
#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../core/log.h"
#include "../cpu/emulated_memory.h"
#include "../host/audio_activity_widget.h"
#include "../state/state_stream.h"
#include "freescale_module_clocks.h"
#include "freescale_ssi_transmitter.h"
#include "guest_cpu_reset.h"

#include <algorithm>

using cerf_freescale_sdma_detail::kBdCont;
using cerf_freescale_sdma_detail::kBdDone;
using cerf_freescale_sdma_detail::kBdWrap;

void FreescaleSdmaAudioPlayer::OnReady() {
    clock_ = &emu_.Get<GuestCycleClock>();
    event_ = clock_->Add([this] { OnBdEnd(); });
    RegisterTxSources([this] { OnTxWrite(); });
    modules_      = &emu_.Get<FreescaleModuleClocks>();
    timer_clocks_ = &emu_.Get<FreescaleTimerClocks>();
    emu_.Get<FreescaleModuleClocks>().RegisterGateListener([this] { OnTxWrite(); });
    clock_->RegisterIdleListener([this] {
        if (active_ && Transmitter(ssi_).Transmitting()) CheckClocks(timer_clocks_->WfiMode());
    });
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) { ResetLine(); });
    out_.Start(LogTag(), 0u, 0u, 0u, true);
    Sdma().RegisterChannelSink(this);
    emu_.Get<AudioActivityWidget>().NotePresent();
}

void FreescaleSdmaAudioPlayer::OnShutdown() { out_.Stop(); }

void FreescaleSdmaAudioPlayer::ResetLine() {
    active_ = false;
    clock_->Disarm(event_);
    out_.StopAudioOut();
}

void FreescaleSdmaAudioPlayer::OnTxWrite() {
    if (!active_) return;
    ApplyFormat();
    if (Transmitter(ssi_).Transmitting()) CheckClocks(FreescaleLowPowerMode::kRun);
    ArmBdEnd();
}

/* MCIMX51RM Table 7-32 note: "clocks to the module will be stopped immediately";
   MCIMX31RM Table 3-12: "00 clock is off during all modes". */
void FreescaleSdmaAudioPlayer::CheckClocks(FreescaleLowPowerMode mode) const {
    FreescaleModule ssi = FreescaleModule::kSsi1;
    switch (ssi_) {
        case 1u: ssi = FreescaleModule::kSsi1; break;
        case 2u: ssi = FreescaleModule::kSsi2; break;
        case 3u: ssi = FreescaleModule::kSsi3; break;
        default:
            emu_.Get<Fatal>().Die("%s: SSI%u has no clock gate mapping", LogTag(), ssi_);
    }
    if (modules_->ModuleRunsIn(ssi, mode) && modules_->ModuleRunsIn(FreescaleModule::kSdma, mode)) {
        return;
    }
    emu_.Get<Fatal>().Die("%s: SSI%u transmits on SDMA channel %u while its SSI or SDMA clock "
                          "gate is off in low-power mode %u; the stopped stream is not modeled",
                          LogTag(), ssi_, channel_, static_cast<unsigned>(mode));
}

void FreescaleSdmaAudioPlayer::ApplyFormat() {
    const FreescaleAudioFormat live = StreamFormat(ssi_);
    if (live.channels != format_.channels || live.bits != format_.bits) {
        emu_.Get<Fatal>().Die("%s: SSI%u frame layout changed from %u ch x %u bit to %u ch x "
                              "%u bit while SDMA channel %u plays", LogTag(), ssi_,
                              format_.channels, format_.bits, live.channels, live.bits, channel_);
    }
    if (live.rate_hz == format_.rate_hz) return;
    format_.rate_hz = live.rate_hz;
    out_.SetFormat(format_.rate_hz, format_.channels, format_.bits);
}

/* MCIMX31RM §40.12.3.5 NOTE: a channel moves "a number of data that matches the watermark
   level"; the guests load the watermark in bytes as context GR7 (zune_keel cspddk.dll
   sub_31540C4 and sync_2 cspddk.dll sub_C09C4640: ctx[9] = watermark). */
bool FreescaleSdmaAudioPlayer::ClaimChannel(const FreescaleSdmaChannelStart& start) {
    uint32_t ssi = 0;
    if (!TxEventSsi(start.event, ssi)) return false;
    if (active_) {
        emu_.Get<Fatal>().Die("%s: SDMA channel %u starts on SSI%u while channel %u plays; a "
                              "second concurrent stream is not modelled", LogTag(),
                              start.channel, ssi, channel_);
    }

    auto&    mem   = emu_.Get<EmulatedMemory>();
    uint32_t count = 0;
    uint32_t bd_pa = start.base_bd_pa;
    for (;;) {
        if (count == kMaxBds) {
            emu_.Get<Fatal>().Die("%s: SDMA channel %u BD ring at PA 0x%08X has no W flag "
                                  "within %u BDs", LogTag(), start.channel,
                                  start.base_bd_pa, kMaxBds);
        }
        const uint8_t* bd = mem.TryTranslateWrite(bd_pa);
        if (bd == nullptr) return false;
        bd_pas_[count++] = bd_pa;
        if ((cerf::le::U32(bd) & kBdWrap) != 0u) break;
        bd_pa += start.stride;
    }

    format_ = StreamFormat(ssi);
    uint32_t watermark = 0;
    if (!Sdma().ChannelWatermark(start.channel, watermark)) {
        emu_.Get<Fatal>().Die("%s: SDMA channel %u starts on SSI%u with no context loaded",
                              LogTag(), start.channel, ssi);
    }
    if (watermark == 0u || watermark % SampleBytes() != 0u) {
        emu_.Get<Fatal>().Die("%s: SDMA channel %u watermark %u bytes is not a whole number of "
                              "%u-byte samples", LogTag(), start.channel, watermark,
                              SampleBytes());
    }
    channel_      = start.channel;
    ssi_          = ssi;
    bd_count_     = count;
    next_bd_      = 0u;
    burst_words_  = watermark / SampleBytes();
    bd_end_words_ = 0u;
    active_       = true;
    Transmitter(ssi).SetDmaBurst(burst_words_);
    out_.SetFormat(format_.rate_hz, format_.channels, format_.bits);
    out_.BeginAudioOut({});
    LOG(Periph, "[%s] claim SSI%u stream (ch%u ev=%d bds=%u %u Hz x %u ch x %u bit, "
        "%u-word bursts)\n", LogTag(), ssi, start.channel, start.event, count, format_.rate_hz,
        format_.channels, format_.bits, burst_words_);
    StartBd();
    return true;
}

void FreescaleSdmaAudioPlayer::ReleaseChannel(uint32_t channel) {
    if (!active_ || channel != channel_) return;
    active_ = false;
    Transmitter(ssi_).SetDmaBurst(0u);
    clock_->Disarm(event_);
    out_.FinishAudioOut();
}

void FreescaleSdmaAudioPlayer::StartBd() {
    const uint32_t bd_pa = bd_pas_[next_bd_];
    const uint8_t* bd    = emu_.Get<EmulatedMemory>().TryTranslateWrite(bd_pa);
    if (bd == nullptr) {
        emu_.Get<Fatal>().Die("%s: SDMA channel %u BD %u at PA 0x%08X no longer translates",
                              LogTag(), channel_, next_bd_, bd_pa);
    }
    const uint32_t word0 = cerf::le::U32(bd);
    const uint32_t bytes = word0 & 0xFFFFu;
    /* MCIMX51RM p.52-231: "The SDMA script cannot process a BD with a Done bit to 0". */
    if ((word0 & kBdDone) == 0u) {
        emu_.Get<Fatal>().Die("%s: SDMA channel %u BD %u at PA 0x%08X (word0 0x%08X) is not "
                              "owned by the SDMA when its transfer starts; the script stop "
                              "is not modelled", LogTag(), channel_, next_bd_, bd_pa, word0);
    }
    if (bytes == 0u || bytes % FrameBytes() != 0u ||
        (bytes / SampleBytes()) % burst_words_ != 0u) {
        emu_.Get<Fatal>().Die("%s: SDMA channel %u BD %u count %u is not a whole number of "
                              "%u-byte frames and %u-word bursts", LogTag(), channel_, next_bd_,
                              bytes, FrameBytes(), burst_words_);
    }
    QueueSamples(cerf::le::U32(bd, 4), bytes);
    bd_words_ = bytes / SampleBytes();
    bd_end_words_ += bd_words_;
    ArmBdEnd();
}

void FreescaleSdmaAudioPlayer::QueueSamples(uint32_t buf_pa, uint32_t bytes) {
    auto&   mem = emu_.Get<EmulatedMemory>();
    uint8_t chunk[PacedWaveOut::kMaxBlock];
    for (uint32_t off = 0; off < bytes;) {
        const uint32_t n = std::min<uint32_t>(bytes - off, PacedWaveOut::kMaxBlock);
        mem.CopyOut(buf_pa + off, chunk, n);
        out_.QueueOutput(chunk, n);
        off += n;
    }
    emu_.Get<AudioActivityWidget>().MarkTx();
}

void FreescaleSdmaAudioPlayer::ArmBdEnd() {
    uint64_t cycle = 0;
    if (active_ && Transmitter(ssi_).CycleOfDmaWords(bd_end_words_, cycle)) {
        clock_->Arm(event_, cycle);
    } else {
        clock_->Disarm(event_);
    }
}

/* MCIMX51RM Table 52-96 D: "when D=1 SDMA owns the buffer descriptor"; p.52-231: "Each time a
   BD is processed, its Done bit is reset by the SDMA". */
void FreescaleSdmaAudioPlayer::OnBdEnd() {
    const uint64_t moved = Transmitter(ssi_).DmaWords();
    if (moved < bd_end_words_) {
        emu_.Get<Fatal>().Die("%s: SDMA channel %u BD end event after %llu of %llu words",
                              LogTag(), channel_, static_cast<unsigned long long>(moved),
                              static_cast<unsigned long long>(bd_end_words_));
    }
    const uint32_t bd_pa = bd_pas_[next_bd_];
    const uint8_t* bd    = emu_.Get<EmulatedMemory>().TryTranslateWrite(bd_pa);
    if (bd == nullptr) {
        emu_.Get<Fatal>().Die("%s: SDMA channel %u BD %u at PA 0x%08X no longer translates",
                              LogTag(), channel_, next_bd_, bd_pa);
    }
    const uint32_t word0 = cerf::le::U32(bd);
    /* MCIMX51RM Table 52-96 (p.52-230) C: "0 No further buffer descriptors". */
    if ((word0 & kBdCont) == 0u) {
        emu_.Get<Fatal>().Die("%s: SDMA channel %u BD %u (word0 0x%08X) completes without "
                              "the C flag; the script stop is not modelled", LogTag(),
                              channel_, next_bd_, word0);
    }
    Sdma().SignalChannelBdDone(channel_, bd_pa);
    next_bd_ = (next_bd_ + 1u) % bd_count_;
    StartBd();
}

void FreescaleSdmaAudioPlayer::SaveSinkState(StateWriter& w) {
    w.Write<uint32_t>("audio_active", active_ ? 1u : 0u);
    w.Write("audio_channel", channel_);
    w.Write("audio_ssi", ssi_);
    w.Write("audio_rate", format_.rate_hz);
    w.Write("audio_channels", format_.channels);
    w.Write("audio_bits", format_.bits);
    w.Write("audio_bd_count", bd_count_);
    w.WriteBytes("audio_bd_pas", bd_pas_, sizeof(bd_pas_));
    w.Write("audio_next_bd", next_bd_);
    w.Write("audio_burst_words", burst_words_);
    w.Write("audio_bd_words", bd_words_);
    w.Write("audio_bd_end_words", bd_end_words_);
}

void FreescaleSdmaAudioPlayer::RestoreSinkState(StateReader& r) {
    uint32_t active = 0;
    r.Read("audio_active", active);
    r.Read("audio_channel", channel_);
    r.Read("audio_ssi", ssi_);
    r.Read("audio_rate", format_.rate_hz);
    r.Read("audio_channels", format_.channels);
    r.Read("audio_bits", format_.bits);
    r.Read("audio_bd_count", bd_count_);
    r.ReadBytes("audio_bd_pas", bd_pas_, sizeof(bd_pas_));
    r.Read("audio_next_bd", next_bd_);
    r.Read("audio_burst_words", burst_words_);
    r.Read("audio_bd_words", bd_words_);
    r.Read("audio_bd_end_words", bd_end_words_);
    clock_->Disarm(event_);
    out_.StopAudioOut();
    active_ = active != 0u;
    if (!active_) return;
    out_.SetFormat(format_.rate_hz, format_.channels, format_.bits);
    out_.BeginAudioOut({});
}

void FreescaleSdmaAudioPlayer::PostRestoreSink() {
    if (!active_) return;
    const uint8_t* bd   = emu_.Get<EmulatedMemory>().TryTranslateWrite(bd_pas_[next_bd_]);
    const uint64_t sent = Transmitter(ssi_).DmaWords() - (bd_end_words_ - bd_words_);
    const uint32_t from = static_cast<uint32_t>(sent) * SampleBytes();
    QueueSamples(cerf::le::U32(bd, 4) + from, bd_words_ * SampleBytes() - from);
    ArmBdEnd();
}
