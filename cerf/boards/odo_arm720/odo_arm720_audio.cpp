#define NOMINMAX

#include "odo_arm720_audio_player.h"
#include "odo_arm720_touch_sound.h"

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "odo_id.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/audio_activity_widget.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../peripherals/philips_ucb1200/ucb1x00_codec.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <mutex>

namespace {

constexpr uint32_t kRecordDmaPa    = 0x10040810u;
constexpr uint32_t kPlaybackDmaPa  = 0x10050810u;
constexpr uint32_t kDmaPairSize    = 0x08u;
constexpr uint32_t kSlotDmaLow     = 0x00u;
constexpr uint32_t kSlotDmaHigh    = 0x04u;

constexpr uint32_t kDramPaBase     = 0x0C000000u;

constexpr uint16_t kIoSoundStrPlaybackPageDone = (1u << 13);

constexpr uint64_t kSampleRate    = 22050u;
constexpr uint16_t kChannels      = 1u;
constexpr uint16_t kBitsPerSample = 16u;
constexpr uint32_t kPageSamples   = 1024u;
constexpr uint32_t kPageBytes     = kPageSamples * sizeof(uint16_t);
constexpr uint32_t kPages         = 2u;
constexpr uint32_t kRingSamples   = kPageSamples * kPages;

constexpr GuestCycleClock::Rate kSampleClock{kSampleRate, 1u};

RasterScanClock::Frame RingFrame() {
    RasterScanClock::Frame frame;
    frame.ticks   = kRingSamples;
    frame.edge[0] = kPageSamples;
    frame.edge[1] = kRingSamples;
    frame.edges   = kPages;
    return frame;
}

/* UCB1300 datasheet p.50: audio control register A, AUD_DIV[n] in bits 0 to 6. */
constexpr uint8_t  kUcbRegAudioCtlA = 7u;
constexpr uint16_t kAudDivMask      = 0x7Fu;
constexpr uint16_t kAudDivModelled  = 5u;

class AudioDmaPair : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Odo;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioSize() const override final { return kDmaPairSize; }
    virtual const char* PortName() const = 0;

    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off != kSlotDmaLow && off != kSlotDmaHigh) {
            HaltUnsupportedAccess("WriteHalf", addr, value);
        }
#if CERF_DEV_MODE
        LOG(Periph, "Odo %s write +0x%02X = 0x%04X\n",
            PortName(), off, value);
#endif
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (off == kSlotDmaLow) dma_low_  = value;
        else                    dma_high_ = value;
    }

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (off != kSlotDmaLow && off != kSlotDmaHigh) {
            HaltUnsupportedAccess("ReadHalf", addr, 0);
        }
        emu_.Get<Fatal>().Die(
            "odo audio: %s read at +0x%02X; the running transfer address the register "
            "returns is not modelled", PortName(), off);
    }

    uint32_t GetEffectivePa() {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const uint32_t chip_addr =
            (static_cast<uint32_t>(dma_high_ & 0xFFu) << 16) |
            static_cast<uint32_t>(dma_low_);
        return kDramPaBase + chip_addr;
    }

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        w.Write("dma_low", dma_low_);  w.Write("dma_high", dma_high_);
    }
    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        r.Read("dma_low", dma_low_);  r.Read("dma_high", dma_high_);
    }

private:
    mutable std::mutex state_mutex_;
    uint16_t           dma_low_  = 0;
    uint16_t           dma_high_ = 0;
};

class OdoArm720AudioRecordDma : public AudioDmaPair {
public:
    using AudioDmaPair::AudioDmaPair;
    uint32_t    MmioBase() const override { return kRecordDmaPa; }
    const char* PortName() const override { return "AUDIO RECORD_DMA"; }
};

class OdoArm720AudioPlaybackDma : public AudioDmaPair {
public:
    using AudioDmaPair::AudioDmaPair;
    uint32_t    MmioBase() const override { return kPlaybackDmaPa; }
    const char* PortName() const override { return "AUDIO PLAYBACK_DMA"; }
};

}

REGISTER_SERVICE(OdoArm720AudioRecordDma);
REGISTER_SERVICE(OdoArm720AudioPlaybackDma);
REGISTER_SERVICE(OdoArm720AudioPlayer);


bool OdoArm720AudioPlayer::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Odo;
}

void OdoArm720AudioPlayer::OnReady() {
    clock_ = &emu_.Get<GuestCycleClock>();
    event_ = clock_->Add([this] { OnPageEnd(); });
    clock_->RegisterRateListener([this] { OnRateChange(); });
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) { ResetLine(); });
    out_.Start("OdoArm720Audio", static_cast<uint32_t>(kSampleRate), kChannels,
               kBitsPerSample, true);
    emu_.Get<AudioActivityWidget>().NotePresent();
}

void OdoArm720AudioPlayer::OnShutdown() { out_.Stop(); }

void OdoArm720AudioPlayer::ResetLine() {
    playing_ = false;
    clock_->Disarm(event_);
    out_.StopAudioOut();
}

void OdoArm720AudioPlayer::SetPlaybackEnabled(bool enabled) {
    if (enabled == playing_) return;
    if (!enabled) {
        playing_ = false;
        clock_->Disarm(event_);
        out_.FinishAudioOut();
        return;
    }
    CheckDacRate();
    const uint64_t now = clock_->Cycles();
    RequireScan(scan_.Start(now, clock_->ClockRate(), kSampleClock, RingFrame()),
                "the playback sample grid");
    playing_ = true;
    out_.BeginAudioOut({});
    QueuePage(0u, 0u);
    ArmPageEnd(now);
}

void OdoArm720AudioPlayer::CheckDacRate() {
    const uint16_t aud_div = static_cast<uint16_t>(
        emu_.Get<Ucb1x00Codec>().ReadReg(kUcbRegAudioCtlA) & kAudDivMask);
    if (aud_div != kAudDivModelled) {
        emu_.Get<Fatal>().Die(
            "odo audio: playback with codec AUD_DIV %u; the DAC rate is modelled only "
            "for AUD_DIV %u (%llu Hz)", aud_div, kAudDivModelled,
            static_cast<unsigned long long>(kSampleRate));
    }
}

void OdoArm720AudioPlayer::RequireScan(bool placed, const char* what) {
    if (placed) return;
    const GuestCycleClock::Rate core = clock_->ClockRate();
    emu_.Get<Fatal>().Die(
        "odo audio: %s does not fit the 64-bit scale of the %llu Hz sample clock "
        "against the %llu/%llu Hz core", what,
        static_cast<unsigned long long>(kSampleRate),
        static_cast<unsigned long long>(core.num),
        static_cast<unsigned long long>(core.den));
}

void OdoArm720AudioPlayer::ArmPageEnd(uint64_t now) {
    uint64_t at = 0;
    RequireScan(scan_.EdgeCycle(scan_.EdgesThrough(now), at), "the next page end");
    clock_->Arm(event_, at);
}

void OdoArm720AudioPlayer::OnPageEnd() {
    const uint64_t now = clock_->Cycles();
    CheckDacRate();
    const uint32_t page = static_cast<uint32_t>(scan_.TickInFrame(now) / kPageSamples);
    if (emu_.Get<OdoArm720TouchSound>().RaiseSoundStrBits(kIoSoundStrPlaybackPageDone)) {
        emu_.Get<Fatal>().Die(
            "odo audio: playback page %u ended with the previous page-done "
            "(ioSoundStr bit 13) still set; the underrun is not modelled",
            (page + kPages - 1u) % kPages);
    }
    QueuePage(page, 0u);
    ArmPageEnd(now);
}

void OdoArm720AudioPlayer::QueuePage(uint32_t page, uint32_t first_sample) {
    uint8_t        bytes[kPageBytes];
    const uint32_t offset = first_sample * static_cast<uint32_t>(sizeof(uint16_t));
    const uint32_t length = kPageBytes - offset;
    const uint32_t pa     = emu_.Get<OdoArm720AudioPlaybackDma>().GetEffectivePa() +
                            page * kPageBytes + offset;
    emu_.Get<EmulatedMemory>().CopyOut(pa, bytes, length);
    out_.QueueOutput(bytes, length);
    emu_.Get<AudioActivityWidget>().MarkTx();
}

void OdoArm720AudioPlayer::OnRateChange() {
    if (!playing_) return;
    const uint64_t now = clock_->Cycles();
    RequireScan(scan_.Rescale(now, clock_->ClockRate(), kSampleClock),
                "the playback sample grid at the new core rate");
    ArmPageEnd(now);
}

void OdoArm720AudioPlayer::SaveState(StateWriter& w) {
    const uint64_t now = clock_->Cycles();
    const RasterScanClock::Position at =
        playing_ ? scan_.PositionAt(now) : RasterScanClock::Position{};
    w.Write<uint32_t>("playback_running", playing_ ? 1u : 0u);
    w.Write<uint32_t>("playback_sample",
                      playing_ ? static_cast<uint32_t>(scan_.TickInFrame(now)) : 0u);
    w.Write<uint64_t>("playback_phase", at.phase);
    w.Write<uint64_t>("playback_phase_den", at.phase_den);
}

void OdoArm720AudioPlayer::RestoreState(StateReader& r) {
    uint32_t running = 0, sample = 0;
    uint64_t phase = 0, phase_den = 0;
    r.Read("playback_running", running);
    r.Read("playback_sample", sample);
    r.Read("playback_phase", phase);
    r.Read("playback_phase_den", phase_den);
    ResetLine();
    if (running == 0u) return;
    const uint64_t now = clock_->Cycles();
    RequireScan(scan_.Resume(now, clock_->ClockRate(), kSampleClock, RingFrame(),
                             RasterScanClock::Position{sample, phase, phase_den}),
                "the restored playback sample grid");
    playing_ = true;
    ArmPageEnd(now);
}

void OdoArm720AudioPlayer::PostRestore() {
    if (!playing_) return;
    const uint64_t sample = scan_.TickInFrame(clock_->Cycles());
    out_.BeginAudioOut({});
    QueuePage(static_cast<uint32_t>(sample / kPageSamples),
              static_cast<uint32_t>(sample % kPageSamples));
}
