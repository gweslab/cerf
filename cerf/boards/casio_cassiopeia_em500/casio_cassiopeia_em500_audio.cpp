#include "casio_cassiopeia_em500_audio.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/audio_activity_widget.h"
#include "../../jit/mips/mips_mmu.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/state_stream.h"

#include <algorithm>
#include <iterator>
#include <vector>

namespace {

/* loc_F62984 @0xF6298C-@0xF629C0: li $v1 select + li $a1 doubler pairs skipped by
   btnez on slti 0x2711 / 0x3A99 / 0x4A39 / 0x6591 and slt 0x9C41, at @0xF62990 /
   @0xF6299A / @0xF629A4 / @0xF629AE / @0xF629B8. */
uint32_t RateHzFor(uint32_t select, bool doubler) {
    if (!doubler) {
        switch (select) {
            case 0x40u: return 8000u;
            case 0x10u: return 11025u;
            case 0x30u: return 16000u;
            case 0x00u: return 22050u;
            default: break;
        }
    } else {
        switch (select) {
            case 0x30u: return 32000u;
            case 0x00u: return 44100u;
            default: break;
        }
    }
    LOG(Caution, "EM-500 audio 0x0880 rate select 0x%02X with doubler %u is not a "
                 "loc_F62984 ladder row\n", select, doubler ? 1u : 0u);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

}  /* namespace */

void CasioCassiopeiaEm500Audio::Init(CerfEmulator& emu,
                                     std::function<void()> on_irq_change) {
    emu_ = &emu;
    on_irq_change_ = std::move(on_irq_change);
    clock_ = &emu.Get<GuestCycleClock>();
    event_ = clock_->Add([this] { OnBlockEnd(); });
    clock_->RegisterRateListener([this] { OnRateChange(); });
    auto& reset = emu.Get<GuestCpuReset>();
    reset.RegisterResetListener([this](ResetLineKind) { OnResetLine(); });
    reset.RegisterResetReleaseListener([this] { on_irq_change_(); });
    paced_.Start("Em500Audio", /*rate_hz=*/0, /*channels=*/0, /*bits=*/0,
                 /*allow_resampler=*/true);
    emu.Get<AudioActivityWidget>().NotePresent();
}

void CasioCassiopeiaEm500Audio::OnShutdown() { paced_.Stop(); }

void CasioCassiopeiaEm500Audio::OnResetLine() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        clock_->Disarm(event_);
        reg_880_ = reg_884_ = reg_888_ = reg_890_ = reg_898_ = reg_8A0_ = 0u;
        reg_8C4_ = reg_8C8_ = reg_8CC_ = 0u;
        std::fill(std::begin(desc_), std::end(desc_), 0u);
        std::fill(std::begin(blocks_), std::end(blocks_), Block{});
        queued_   = 0u;
        ran_dry_  = false;
        rate_hz_  = 0u;
        channels_ = 0u;
    }
    status_8A8_.store(0u, std::memory_order_release);
    paced_.StopAudioOut();
}

void CasioCassiopeiaEm500Audio::SetRateDoubler(bool on) {
    std::unique_lock<std::mutex> lk(mtx_);
    rate_doubler_ = on;
    RequireStreamFormat(lk);
}

void CasioCassiopeiaEm500Audio::RequireStreamFormat(std::unique_lock<std::mutex>& lk) {
    if (!Running() && queued_ == 0u) return;
    const uint32_t select          = reg_880_ & kRateSelectMask;
    const bool     doubler         = rate_doubler_;
    const uint16_t channels        = Channels();
    const uint32_t stream_rate     = rate_hz_;
    const uint16_t stream_channels = channels_;
    const uint32_t queued          = queued_;
    lk.unlock();
    const uint32_t rate = RateHzFor(select, doubler);
    if (rate == stream_rate && channels == stream_channels) return;
    emu_->Get<Fatal>().Die("EM-500 audio: the %u Hz x %u ch stream changed to %u Hz x %u ch "
                           "with %u blocks in flight", stream_rate, stream_channels, rate,
                           channels, queued);
}

bool CasioCassiopeiaEm500Audio::TryReadHalf(uint32_t off, uint16_t& out) {
    if (off == kOffStatus8A8) {
        out = status_8A8_.exchange(0u, std::memory_order_acq_rel);
        on_irq_change_();
        return true;
    }
    std::lock_guard<std::mutex> lk(mtx_);
    switch (off) {
        case kOffCtrl880:   out = static_cast<uint16_t>(reg_880_); return true;
        case kOffEnable884:
            out = static_cast<uint16_t>(
                reg_884_ | (queued_ != 0u ? kEnableBusyBit : 0u));
            return true;
        case kOffFormat888: out = static_cast<uint16_t>(reg_888_); return true;
        case kOffLatch8A0:  out = static_cast<uint16_t>(reg_8A0_); return true;
        default: return false;
    }
}

bool CasioCassiopeiaEm500Audio::TryWriteHalf(uint32_t off, uint16_t value) {
    const auto merge = [value](uint32_t& reg) { reg = (reg & 0xFFFF0000u) | value; };
    if (off == kOffLatch8A0) { OnLatchWrite(value, 0xFFFF0000u); return true; }
    std::unique_lock<std::mutex> lk(mtx_);
    switch (off) {
        case kOffCtrl880:   merge(reg_880_); break;
        /* dword_F622D4 @0xF62384 lhu 0x884 / @0xF62386 or 1 / @0xF62388 sh, loc_F61D94
           @0xF61DB2-@0xF61DB8, sub_F62520 @0xF6257E-@0xF62586 and loc_F62984
           @0xF62A38-@0xF62A3E / @0xF62A7E-@0xF62A86 read-modify-write 0x0884 with no
           mask clearing bit2. */
        case kOffEnable884:
            reg_884_ = (reg_884_ & 0xFFFF0000u) |
                       (value & static_cast<uint16_t>(~kEnableBusyBit));
            return true;
        case kOffFormat888: merge(reg_888_); break;
        case kOffAckL8C8:   merge(reg_8C8_); return true;
        case kOffAckR8CC:   merge(reg_8CC_); return true;
        default: return false;
    }
    RequireStreamFormat(lk);
    return true;
}

bool CasioCassiopeiaEm500Audio::TryReadWord(uint32_t off, uint32_t& out) {
    std::lock_guard<std::mutex> lk(mtx_);
    switch (off) {
        case kOffCtrl880:   out = reg_880_; return true;
        case kOffEnable884:
            out = reg_884_ | (queued_ != 0u ? kEnableBusyBit : 0u);
            return true;
        case kOffFormat888: out = reg_888_; return true;
        case kOffChan890:   out = reg_890_; return true;
        case kOffStrobe898: out = reg_898_; return true;
        case kOffLatch8A0:  out = reg_8A0_; return true;
        case kOffGate8C4:   out = reg_8C4_; return true;
        default: return false;
    }
}

bool CasioCassiopeiaEm500Audio::TryWriteWord(uint32_t off, uint32_t value) {
    if (off >= kOffDescLo && off <= kOffDescHi && (off & 3u) == 0u) {
        const uint32_t index = (off - kOffDescLo) / 4u;
        uint32_t in_flight = 0;
        bool     refill    = false;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            in_flight = queued_;
            refill    = index >= kDescNextStart && queued_ == 1u && Running() && PlayEnabled();
            if (in_flight == 0u || refill) desc_[index] = value;
        }
        if (in_flight != 0u && !refill) {
            emu_->Get<Fatal>().Die("EM-500 audio: DMA descriptor 0x%04X write 0x%08X with %u "
                                   "blocks in flight; not modeled", off, value, in_flight);
        }
        if (index == kDescNextEnd) QueueDescriptor(kDescNextStart);
        return true;
    }
    switch (off) {
        case kOffChan890:   OnChannelWrite(value); return true;
        case kOffLatch8A0:  OnLatchWrite(value, 0u); return true;
        default: break;
    }
    std::unique_lock<std::mutex> lk(mtx_);
    switch (off) {
        case kOffCtrl880:   reg_880_ = value; break;
        case kOffStrobe898:
            /* loc_F618CC @0xF6196E sw $s1(=1); dword_F622D4 @0xF6238E sw $a3(=1)
               gated on 0x0884 bit0 @0xF62380; loc_F61EAC @0xF61EF8 lw / @0xF61EFA
               li $a2,2 / @0xF61EFC neg / @0xF61EFE and / @0xF61F00 sw. */
            if (value > 1u) {
                LOG(Caution, "EM-500 audio 0x0898 write 0x%08X outside the "
                             "loc_F618CC / dword_F622D4 / loc_F61EAC set\n", value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            reg_898_ = value;
            return true;
        case kOffEnable884: reg_884_ = value & ~kEnableBusyBit; return true;
        case kOffFormat888: reg_888_ = value; break;
        case kOffGate8C4:   reg_8C4_ = value; return true;
        case kOffAckL8C8:   reg_8C8_ = value; return true;
        case kOffAckR8CC:   reg_8CC_ = value; return true;
        default: return false;
    }
    RequireStreamFormat(lk);
    return true;
}

void CasioCassiopeiaEm500Audio::OnLatchWrite(uint32_t value, uint32_t keep_mask) {
    bool     started = false;
    bool     drained = false;
    uint32_t chan    = 0;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const bool was = Running();
        reg_8A0_ = (reg_8A0_ & keep_mask) | (value & ~keep_mask);
        started = !was && Running();
        drained = was && !Running() && queued_ == 0u;
        chan    = reg_890_;
    }
    if (started && (chan & kChanPlay) == 0u) {
        emu_->Get<Fatal>().Die("EM-500 audio: 0x08A0 start with 0x0890 = 0x%08X (playback not "
                               "enabled); not modeled", chan);
    }
    if (drained) paced_.FinishAudioOut();
    if (!started) return;
    StartStream();
    StartTransfers();
}

void CasioCassiopeiaEm500Audio::OnChannelWrite(uint32_t value) {
    if ((value & kChanCapture) != 0u) {
        emu_->Get<Fatal>().Die("EM-500 audio: 0x0890 write 0x%08X enables capture; not modeled",
                               value);
    }
    bool     started       = false;
    bool     clears_active = false;
    uint32_t in_flight     = 0;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const bool was = PlayEnabled();
        in_flight     = queued_;
        clears_active = was && (value & kChanPlay) == 0u && in_flight != 0u;
        if (!clears_active) {
            reg_890_ = value;
            started  = !was && PlayEnabled() && Running();
        }
    }
    if (clears_active) {
        emu_->Get<Fatal>().Die("EM-500 audio: 0x0890 write 0x%08X clears playback enable with %u "
                               "blocks in flight; not modeled", value, in_flight);
    }
    if (!started) return;
    StartStream();
    StartTransfers();
}

void CasioCassiopeiaEm500Audio::StartTransfers() {
    QueueDescriptor(kDescCurStart);
    QueueDescriptor(kDescNextStart);
}

uint32_t CasioCassiopeiaEm500Audio::FrameBytes() const {
    return static_cast<uint32_t>(channels_) * (kBitsPerSample / 8u);
}

void CasioCassiopeiaEm500Audio::StartStream() {
    uint32_t select = 0;
    bool     doubler = false;
    uint32_t in_flight = 0;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        select    = reg_880_ & kRateSelectMask;
        doubler   = rate_doubler_;
        in_flight = queued_;
    }
    if (in_flight != 0u) {
        emu_->Get<Fatal>().Die("EM-500 audio: stream restart with %u blocks in flight; not "
                               "modeled", in_flight);
    }
    const uint32_t rate = RateHzFor(select, doubler);
    uint16_t channels = 0;
    bool     fits = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        rate_hz_     = rate;
        channels_    = Channels();
        ran_dry_     = false;
        fits = frames_.SetRate(clock_->ClockRate(), GuestCycleClock::Rate{rate_hz_, 1u});
        frames_.Start(clock_->Cycles());
        channels = channels_;
    }
    if (!fits) {
        emu_->Get<Fatal>().Die("EM-500 audio: a %u Hz sample clock against the core clock "
                               "overflows the 64-bit scale", rate);
    }
    paced_.SetFormat(rate, channels, kBitsPerSample);
    paced_.BeginAudioOut({});
}

void CasioCassiopeiaEm500Audio::QueueDescriptor(uint32_t start_index) {
    uint32_t start_va = 0;
    uint32_t end_va = 0;
    uint32_t frame_bytes = 0;
    bool     dry = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!Running() || !PlayEnabled()) return;
        start_va = desc_[start_index];
        end_va = desc_[start_index + 1u];
        frame_bytes = FrameBytes();
        dry = ran_dry_;
    }
    if (dry) {
        emu_->Get<Fatal>().Die("EM-500 audio: DMA descriptor 0x%08X..0x%08X queued after the "
                               "stream ran dry; not modeled", start_va, end_va);
    }
    const uint64_t span = static_cast<uint64_t>(end_va) -
                          static_cast<uint64_t>(start_va) + 1ull;
    if (end_va < start_va || span > PacedWaveOut::kMaxBlock) {
        LOG(Caution, "EM-500 audio DMA descriptor 0x%08X..0x%08X is not a block of "
                     "at most %u bytes\n", start_va, end_va, PacedWaveOut::kMaxBlock);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint32_t length = static_cast<uint32_t>(span);
    if (length % frame_bytes != 0u) {
        emu_->Get<Fatal>().Die("EM-500 audio: DMA descriptor 0x%08X..0x%08X is not a whole "
                               "number of %u-byte frames", start_va, end_va, frame_bytes);
    }
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const uint64_t start = queued_ != 0u ? blocks_[queued_ - 1u].end
                                             : frames_.TicksAt(clock_->Cycles());
        blocks_[queued_] = Block{start_va, length, start + length / frame_bytes};
        ++queued_;
        if (queued_ == 1u) ArmBlockEndLocked();
    }
    QueueHostBytes(start_va, length);
}

void CasioCassiopeiaEm500Audio::QueueHostBytes(uint32_t va, uint32_t length) {
    std::vector<uint8_t> block(length);
    /* VR4102 UM ch.5 p131 "(3) kseg1": references are not mapped through TLB and the
       physical address is the virtual address minus 0xA0000000. */
    emu_->Get<EmulatedMemory>().CopyOut(MipsSeg::UnmappedPa(va), block.data(), length);
    emu_->Get<AudioActivityWidget>().MarkTx();
    paced_.QueueOutputInHostBlocks(block.data(), length);
}

void CasioCassiopeiaEm500Audio::ArmBlockEndLocked() {
    clock_->Arm(event_, frames_.CycleOfTick(blocks_[0].end));
}

void CasioCassiopeiaEm500Audio::OnRateChange() {
    bool fits = true;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (rate_hz_ == 0u) return;
        fits = frames_.Rescale(clock_->Cycles(), clock_->ClockRate(),
                               GuestCycleClock::Rate{rate_hz_, 1u});
        if (fits && queued_ != 0u) ArmBlockEndLocked();
    }
    if (!fits) {
        emu_->Get<Fatal>().Die("EM-500 audio: the %u Hz sample phase does not fit the new core "
                               "clock ratio", rate_hz_);
    }
}

void CasioCassiopeiaEm500Audio::OnBlockEnd() {
    bool drained = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        desc_[kDescCurStart] = desc_[kDescNextStart];
        desc_[kDescCurEnd] = desc_[kDescNextEnd];
        blocks_[0] = blocks_[1];
        --queued_;
        if (queued_ != 0u) ArmBlockEndLocked();
        else ran_dry_ = true;
        /* casio_cassiopeia_em500_ppc2000 wavedev.dll loc_F61EAC @0xF61EBC sw 0 -> 0x08A0;
           @0xF61EC8 lw 0x0884 / @0xF61ECC and 4 / @0xF61ECE beqz / @0xF61ED2 b. */
        drained = queued_ == 0u && !Running();
    }
    status_8A8_.fetch_or(kStatusBlockDone, std::memory_order_acq_rel);
    on_irq_change_();
    if (drained) paced_.FinishAudioOut();
}

void CasioCassiopeiaEm500Audio::SaveState(StateWriter& w) const {
    std::lock_guard<std::mutex> lk(mtx_);
    w.Write("reg_880", reg_880_);
    w.Write("reg_884", reg_884_);
    w.Write("reg_888", reg_888_);
    w.Write("reg_890", reg_890_);
    w.Write("reg_898", reg_898_);
    w.Write("reg_8A0", reg_8A0_);
    for (uint32_t v : desc_) w.Write("desc", v);
    w.Write("reg_8C4", reg_8C4_);
    w.Write("reg_8C8", reg_8C8_);
    w.Write("reg_8CC", reg_8CC_);
    w.Write<uint8_t>("rate_doubler", rate_doubler_ ? 1u : 0u);
    w.Write("status_8A8", status_8A8_.load(std::memory_order_acquire));
    const uint64_t now       = clock_->Cycles();
    const bool     streaming = rate_hz_ != 0u;
    w.Write("stream_rate", rate_hz_);
    w.Write("stream_channels", channels_);
    w.Write("blocks_queued", queued_);
    w.Write<uint8_t>("stream_ran_dry", ran_dry_ ? 1u : 0u);
    for (const Block& b : blocks_) {
        w.Write("block_va", b.va);
        w.Write("block_length", b.length);
        w.Write("block_end", b.end);
    }
    const RatedTickCount::Position at =
        streaming ? frames_.PositionAt(now) : RatedTickCount::Position{};
    w.Write("frame", at.ticks);
    w.Write("frame_phase", at.phase);
    w.Write("frame_phase_den", at.phase_den);
}

void CasioCassiopeiaEm500Audio::RestoreState(StateReader& r) {
    paced_.StopAudioOut();
    std::lock_guard<std::mutex> lk(mtx_);
    r.Read("reg_880", reg_880_);
    r.Read("reg_884", reg_884_);
    r.Read("reg_888", reg_888_);
    r.Read("reg_890", reg_890_);
    r.Read("reg_898", reg_898_);
    r.Read("reg_8A0", reg_8A0_);
    for (uint32_t& v : desc_) r.Read("desc", v);
    r.Read("reg_8C4", reg_8C4_);
    r.Read("reg_8C8", reg_8C8_);
    r.Read("reg_8CC", reg_8CC_);
    uint8_t doubler = 0;
    r.Read("rate_doubler", doubler);
    rate_doubler_ = doubler != 0;
    uint16_t status = 0;
    r.Read("status_8A8", status);
    status_8A8_.store(status, std::memory_order_release);
    uint8_t                  dry = 0;
    RatedTickCount::Position at;
    r.Read("stream_rate", rate_hz_);
    r.Read("stream_channels", channels_);
    r.Read("blocks_queued", queued_);
    r.Read("stream_ran_dry", dry);
    ran_dry_ = dry != 0u;
    for (Block& b : blocks_) {
        r.Read("block_va", b.va);
        r.Read("block_length", b.length);
        r.Read("block_end", b.end);
    }
    r.Read("frame", at.ticks);
    r.Read("frame_phase", at.phase);
    r.Read("frame_phase_den", at.phase_den);

    clock_->Disarm(event_);
    if (rate_hz_ == 0u) return;
    frames_.SetRate(clock_->ClockRate(), GuestCycleClock::Rate{rate_hz_, 1u});
    frames_.PlaceAt(clock_->Cycles(), at);
    if (queued_ == 0u) return;
    ArmBlockEndLocked();
}

void CasioCassiopeiaEm500Audio::PostRestore() {
    Block    pending[kMaxQueued] = {};
    uint32_t count = 0, rate = 0, frame_bytes = 0;
    uint64_t frame = 0;
    uint16_t channels = 0;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        count = queued_;
        if (count == 0u && !Running()) return;
        std::copy(blocks_, blocks_ + kMaxQueued, pending);
        frame       = frames_.TicksAt(clock_->Cycles());
        rate        = rate_hz_;
        channels    = channels_;
        frame_bytes = FrameBytes();
    }
    paced_.SetFormat(rate, channels, kBitsPerSample);
    paced_.BeginAudioOut({});
    if (count == 0u) return;
    const int64_t left_frames = static_cast<int64_t>(pending[0].end - frame);
    if (left_frames > 0) {
        const uint32_t left = static_cast<uint32_t>(left_frames) * frame_bytes;
        QueueHostBytes(pending[0].va + pending[0].length - left, left);
    }
    for (uint32_t i = 1; i < count; ++i) QueueHostBytes(pending[i].va, pending[i].length);
}
