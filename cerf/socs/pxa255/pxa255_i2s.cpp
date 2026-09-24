#include "pxa255_i2s.h"

#include "../../host/audio_activity_widget.h"

#include <utility>

REGISTER_SERVICE(Pxa255I2s);

void Pxa255I2s::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
    /* rate 0: defer opening the host device until the guest starts I2S audio
       (BeginAudioOut -> SetFormat), so AC'97-only boards hold no idle I2S device. */
    audio_out_.Start("Pxa255I2s", /*rate=*/0, 0, 0, /*allow_resampler=*/true);
    emu_.Get<AudioActivityWidget>().NotePresent();
}

void Pxa255I2s::OnShutdown() { audio_out_.Stop(); }

void Pxa255I2s::BeginAudioOut(std::function<void()> on_block_done) {
    audio_out_.SetFormat(SampleRateHz(), 2, 16);
    audio_out_.BeginAudioOut(std::move(on_block_done));
}

void Pxa255I2s::QueueOutput(const void* host_bytes, uint32_t length) {
    audio_out_.QueueOutput(host_bytes, length);
    emu_.Get<AudioActivityWidget>().MarkTx();
}

void Pxa255I2s::StopAudioOut() { audio_out_.StopAudioOut(); }

uint32_t Pxa255I2s::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
    case kSACR0: return sacr0_;
    case kSACR1: return sacr1_;
    case kSASR0:
        /* Tx FIFO modeled as perpetually empty: TNF set, and TFS (DMA service
           request) set while enabled. If TNF/TFS ever read 0 here the guest audio
           driver's FIFO/DMA service loop blocks waiting to feed a FIFO that never
           drains - the classic audio-stub boot deadlock. */
        return kSasr0Tnf | ((sacr0_ & kSacr0Enb) ? kSasr0Tfs : 0u);
    case kSAIMR: return saimr_;
    case kSAICR: return 0u;          /* SAICR clears on write; nothing latched. */
    case kSADIV: return sadiv_;
    case kSADR:  return 0u;          /* Rx FIFO empty (no audio input). */
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa255I2s::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
    case kSACR0: sacr0_ = value; return;
    case kSACR1: sacr1_ = value; return;
    case kSAIMR: saimr_ = value; return;
    case kSAICR: return;             /* clear-on-write; no latched status to clear. */
    case kSADIV: sadiv_ = value; return;
    case kSADR:  return;             /* Tx sample consumed instantly (no output). */
    case kSASR0: return;             /* read-only status. */
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa255I2s::SaveState(StateWriter& w) {
    w.Write("sacr0", sacr0_); w.Write("sacr1", sacr1_); w.Write("saimr", saimr_); w.Write("sadiv", sadiv_);
}

void Pxa255I2s::RestoreState(StateReader& r) {
    r.Read("sacr0", sacr0_); r.Read("sacr1", sacr1_); r.Read("saimr", saimr_); r.Read("sadiv", sadiv_);
    /* No host sink / DMA pacing callback survives a snapshot; reset so the guest re-arms. */
    audio_out_.StopAudioOut();
}
