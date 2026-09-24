#include "pxa255_ac97.h"

#include "../../boards/board_context.h"
#include "pxa255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/audio_activity_widget.h"
#include "../../peripherals/ac97_codec.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <algorithm>
#include <cstring>

REGISTER_SERVICE(Pxa255Ac97);

bool Pxa255Ac97::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Pxa255;
}

/* Stop the audio thread before any peer its completion callback re-enters is
   destroyed. */
void Pxa255Ac97::OnShutdown() { audio_out_.Stop(); }

void Pxa255Ac97::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
    audio_out_.Start("Pxa255Ac97", kSampleRate, kChannels, kBitsPerSamp,
                     /*allow_resampler=*/false);
    emu_.Get<AudioActivityWidget>().NotePresent();
}

void Pxa255Ac97::BeginAudioOut(std::function<void()> on_block_done) {
    audio_out_.BeginAudioOut(std::move(on_block_done));
}

void Pxa255Ac97::StopAudioOut() { audio_out_.StopAudioOut(); }

void Pxa255Ac97::QueueOutput(const void* host_bytes, uint32_t length) {
    audio_out_.QueueOutput(host_bytes, length);
    emu_.Get<AudioActivityWidget>().MarkTx();
}

void Pxa255Ac97::SaveState(StateWriter& w) {
    w.Write("pocr", pocr_);
    w.Write("picr", picr_);
    w.Write("mccr", mccr_);
    w.Write("gcr", gcr_);
    w.Write("mocr", mocr_);
    w.Write("micr", micr_);
    w.WriteBytes("codec", codec_, sizeof(codec_));
    /* When a real codec is registered (e.g. Wm9705Codec) it holds the live
       register file; codec_ above is only the no-codec shadow. */
    if (auto* codec = emu_.TryGet<Ac97Codec>()) codec->SaveState(w);
}

void Pxa255Ac97::RestoreState(StateReader& r) {
    r.Read("pocr", pocr_);
    r.Read("picr", picr_);
    r.Read("mccr", mccr_);
    r.Read("gcr", gcr_);
    r.Read("mocr", mocr_);
    r.Read("micr", micr_);
    r.ReadBytes("codec", codec_, sizeof(codec_));
    if (auto* codec = emu_.TryGet<Ac97Codec>()) codec->RestoreState(r);
    /* No host sink buffer or DMA pacing callback survives a snapshot; a still-
       active audio/touch coupling would block the guest DMA thread on a
       completion that never arrives, so reset it for the guest to re-arm. */
    StopAudioOut();
    StopTouchCapture();
}

uint16_t Pxa255Ac97::CodecRead(uint32_t reg) {
    if (auto* codec = emu_.TryGet<Ac97Codec>()) return codec->ReadReg(reg);
    return codec_[reg];
}

void Pxa255Ac97::CodecWrite(uint32_t reg, uint16_t value) {
    if (auto* codec = emu_.TryGet<Ac97Codec>()) { codec->WriteReg(reg, value); return; }
    codec_[reg] = value;
}

uint32_t Pxa255Ac97::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (InCodecWindow(off)) return CodecRead((off - kCodecBase) >> 1);
    switch (off) {
        case kMODR: { uint16_t w = 0; return PopTouchWords(&w, 1u) ? w : 0u; }
        case kMISR: {
            std::lock_guard<std::mutex> lk(touch_mutex_);
            return touch_fifo_.empty() ? 0u : kMisrFsr;
        }
        case kPOCR: return pocr_;
        case kPICR: return picr_;
        case kMCCR: return mccr_;
        case kGCR:  return gcr_;
        case kMOCR: return mocr_;
        case kMICR: return micr_;
        case kGSR:  return kGsrReady;  /* codec ready, commands done. */
        case kCAR:  return 0u;         /* §13.8.3.7 Table 13-13: CAIP=0 -> AC-link free. */
        default:    return 0u;         /* status / codec / FIFO idle. */
    }
}

void Pxa255Ac97::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (InCodecWindow(off)) {
        CodecWrite((off - kCodecBase) >> 1, static_cast<uint16_t>(value));
        return;
    }
    switch (off) {
        case kPOCR: pocr_ = value; return;
        case kPICR: picr_ = value; return;
        case kMCCR: mccr_ = value; return;
        case kGCR:  gcr_  = value; return;
        case kMOCR: mocr_ = value; return;
        case kMICR: micr_ = value; return;
        /* §13.8.3.7 Table 13-13: CAR.CAIP is HW-owned and no codec is modeled, so
           CAR always reads CAIP=0 (free). Storing a write would let a stale CAIP=1
           read back BUSY and spin the driver's CODEC-access poll (§13.6.3). */
        case kCAR:  return;
        default:    return;            /* GSR W1C status / FIFO writes. */
    }
}

uint16_t Pxa255Ac97::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (InCodecWindow(off)) return CodecRead((off - kCodecBase) >> 1);
    const uint32_t word  = ReadWord(addr & ~0x3u);
    const uint32_t shift = (off & 0x2u) * 8u;
    return static_cast<uint16_t>((word >> shift) & 0xFFFFu);
}

void Pxa255Ac97::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - MmioBase();
    if (InCodecWindow(off)) {
        CodecWrite((off - kCodecBase) >> 1, value);
        return;
    }
    const uint32_t shift = (off & 0x2u) * 8u;
    const uint32_t word  = ReadWord(addr & ~0x3u);
    WriteWord(addr & ~0x3u,
              (word & ~(0xFFFFu << shift)) | (static_cast<uint32_t>(value) << shift));
}

void Pxa255Ac97::PushTouchSample(const uint16_t* words, uint32_t count) {
    std::function<void()> cb;
    {
        std::lock_guard<std::mutex> lk(touch_mutex_);
        for (uint32_t i = 0; i < count; ++i) touch_fifo_.push_back(words[i]);
        cb = on_touch_sample_;
    }
    /* Invoke without the lock: the DMA callback re-enters PopTouchWords. */
    if (cb) cb();
}

void Pxa255Ac97::BeginTouchCapture(std::function<void()> on_sample) {
    std::lock_guard<std::mutex> lk(touch_mutex_);
    on_touch_sample_ = std::move(on_sample);
}

void Pxa255Ac97::StopTouchCapture() {
    std::lock_guard<std::mutex> lk(touch_mutex_);
    on_touch_sample_ = nullptr;
    touch_fifo_.clear();
}

uint32_t Pxa255Ac97::PopTouchWords(uint16_t* out, uint32_t max) {
    std::lock_guard<std::mutex> lk(touch_mutex_);
    const uint32_t n = std::min<uint32_t>(max, static_cast<uint32_t>(touch_fifo_.size()));
    for (uint32_t i = 0; i < n; ++i) out[i] = touch_fifo_[i];
    touch_fifo_.erase(touch_fifo_.begin(), touch_fifo_.begin() + n);
    return n;
}

uint32_t Pxa255Ac97::TouchFifoCount() {
    std::lock_guard<std::mutex> lk(touch_mutex_);
    return static_cast<uint32_t>(touch_fifo_.size());
}
