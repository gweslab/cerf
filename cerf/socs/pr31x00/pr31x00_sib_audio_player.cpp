#define NOMINMAX

#include "pr31x00_sib_audio.h"

#include "pr31x00_intc.h"

#include "../../boards/board_context.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "../../core/cerf_emulator.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/audio_activity_widget.h"
#include "../../core/fatal.h"
#include "../../host/paced_wave_out.h"
#include "../../state/state_stream.h"
#include "../rated_tick_count.h"

#include <cstdint>
#include <vector>

namespace {

/* Interrupt Status 1 (§8.3.1): SND0_5INT<22> at the sound DMA halfway point,
   SND1_0INT<21> at end-of-buffer (§13.5). The wavedev IST (wavedev.dll
   sub_1872AD0, SYSINTR 13) blocks until one wakes it, so dropping them hangs audio. */
constexpr uint32_t kSndSet    = 0;   /* Interrupt Status 1 */
constexpr uint32_t kSnd0_5Int = 1u << 22;
constexpr uint32_t kSnd1_0Int = 1u << 21;

/* TMPR3911 Figure 13.4.1 p13-16, §13.4 p13-15, Table 13.3.4 p13-13. */
constexpr uint32_t kDmaLeadSamples = 2;

class Pr31x00SibAudioPlayer : public Pr31x00SibAudioSink {
public:
    using Pr31x00SibAudioSink::Pr31x00SibAudioSink;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd) return false;
        const std::string_view soc = bd->GetSocId();
        return soc == SocId::Pr31500 || soc == SocId::Pr31700;
    }

    void OnReady() override {
        clock_ = &emu_.Get<GuestCycleClock>();
        event_ = clock_->Add([this] { OnHalfEnd(); });
        clock_->RegisterRateListener([this] { OnRateChange(); });
        paced_.Start("SibAudio", 0, /*channels=*/1, /*bits=*/16,
                     true);
        emu_.Get<AudioActivityWidget>().NotePresent();
    }

    void OnShutdown() override { paced_.Stop(); }

    void StartSoundTx(uint32_t src_pa, uint32_t bytes, GuestCycleClock::Rate rate) override {
        src_pa_ = src_pa;
        bytes_  = bytes;
        half_   = 0;
        rate_   = rate;
        active_ = true;
        if (bytes_ < 8u) {
            emu_.Get<Fatal>().Die("Pr31x00SibAudioPlayer: a %u-byte sound DMA buffer (one word) "
                                  "is not modeled", bytes_);
        }
        if (!samples_.SetRate(clock_->ClockRate(), rate_)) {
            emu_.Get<Fatal>().Die("Pr31x00SibAudioPlayer: the %llu/%llu Hz sound rate against the "
                                  "core clock overflows the 64-bit scale",
                                  static_cast<unsigned long long>(rate.num),
                                  static_cast<unsigned long long>(rate.den));
        }
        samples_.Start(clock_->Cycles());
        half_end_ = HalfSamples(0u);
        paced_.SetFormat(HostRateHz(), 1, 16);
        paced_.BeginAudioOut({});
        QueueHalf(0u);
        ArmHalfEnd();
    }

    void StopSoundTx() override {
        active_ = false;
        clock_->Disarm(event_);
        paced_.FinishAudioOut();
    }

    void SaveState(StateWriter& w) override {
        const uint64_t now = clock_->Cycles();
        const RatedTickCount::Position at =
            active_ ? samples_.PositionAt(now) : RatedTickCount::Position{};
        w.Write<uint8_t>("snd_active", active_ ? 1u : 0u);
        w.Write("snd_src_pa", src_pa_);
        w.Write("snd_bytes", bytes_);
        w.Write("snd_half", half_);
        w.Write("snd_rate_num", rate_.num);
        w.Write("snd_rate_den", rate_.den);
        w.Write("snd_half_end", half_end_);
        w.Write("snd_sample", at.ticks);
        w.Write("snd_phase", at.phase);
        w.Write("snd_phase_den", at.phase_den);
    }

    void RestoreState(StateReader& r) override {
        uint8_t                  active = 0;
        RatedTickCount::Position at;
        r.Read("snd_active", active);
        r.Read("snd_src_pa", src_pa_);
        r.Read("snd_bytes", bytes_);
        r.Read("snd_half", half_);
        r.Read("snd_rate_num", rate_.num);
        r.Read("snd_rate_den", rate_.den);
        r.Read("snd_half_end", half_end_);
        r.Read("snd_sample", at.ticks);
        r.Read("snd_phase", at.phase);
        r.Read("snd_phase_den", at.phase_den);

        clock_->Disarm(event_);
        paced_.StopAudioOut();
        active_ = active != 0u;
        if (!active_) return;
        const uint64_t now = clock_->Cycles();
        samples_.SetRate(clock_->ClockRate(), rate_);
        samples_.PlaceAt(now, at);
        paced_.SetFormat(HostRateHz(), 1, 16);
        paced_.BeginAudioOut({});
        const int64_t played = static_cast<int64_t>(at.ticks - (half_end_ - HalfSamples(half_)));
        QueueHalf(played > 0 ? static_cast<uint32_t>(played) : 0u);
        ArmHalfEnd();
    }

private:
    /* TMPR3911 Figure 13.4.1 p13-16 (BUFFER SIZE / 2), §13.6.1 p13-19 (length - 1). */
    uint32_t HalfBytes(uint32_t h) const {
        const uint32_t first = ((bytes_ / 4u - 1u) / 2u + 1u) * 4u;
        return h ? bytes_ - first : first;
    }

    uint32_t HalfSamples(uint32_t h) const { return HalfBytes(h) / 2u; }

    uint32_t HostRateHz() const {
        return static_cast<uint32_t>((rate_.num + rate_.den / 2u) / rate_.den);
    }

    void QueueHalf(uint32_t skip_samples) {
        const uint32_t off = (half_ ? HalfBytes(0u) : 0u) + skip_samples * 2u;
        const uint32_t len = HalfBytes(half_) - skip_samples * 2u;
        if (len == 0u) return;
        auto& mem = emu_.Get<EmulatedMemory>();
        buf_.resize(len);
        /* MSB-first codec words (philips_nino_300 wavedev.dll sub_1871F50) -> LE host PCM. */
        for (uint32_t i = 0; i + 1u < len; i += 2u) {
            buf_[i]     = mem.ReadByte(src_pa_ + off + i + 1u);
            buf_[i + 1] = mem.ReadByte(src_pa_ + off + i);
        }
        emu_.Get<AudioActivityWidget>().MarkTx();
        paced_.QueueOutputInHostBlocks(buf_.data(), static_cast<uint32_t>(buf_.size()));
    }

    void ArmHalfEnd() {
        clock_->Arm(event_, samples_.CycleOfTick(half_end_ - kDmaLeadSamples));
    }

    void OnRateChange() {
        if (!active_) return;
        if (!samples_.Rescale(clock_->Cycles(), clock_->ClockRate(), rate_)) {
            emu_.Get<Fatal>().Die("Pr31x00SibAudioPlayer: the sound sample phase does not fit "
                                  "the new core clock ratio");
        }
        ArmHalfEnd();
    }

    void OnHalfEnd() {
        emu_.Get<Pr31x00Intc>().SetPending(kSndSet, half_ == 0u ? kSnd0_5Int : kSnd1_0Int);
        half_ ^= 1u;
        half_end_ += HalfSamples(half_);
        QueueHalf(0u);
        ArmHalfEnd();
    }

    GuestCycleClock*        clock_ = nullptr;
    GuestCycleClock::Event* event_ = nullptr;
    RatedTickCount          samples_;
    PacedWaveOut            paced_;
    std::vector<uint8_t>    buf_;
    GuestCycleClock::Rate   rate_;
    uint32_t                src_pa_   = 0;
    uint32_t                bytes_    = 0;
    uint32_t                half_     = 0;
    uint64_t                half_end_ = 0;
    bool                    active_   = false;
};

}  /* namespace */

REGISTER_SERVICE_AS(Pr31x00SibAudioPlayer, Pr31x00SibAudioSink);
