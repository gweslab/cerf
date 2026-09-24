#include "casio_cassiopeia_em500_audio.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/audio_activity_widget.h"
#include "../../jit/mips/mips_mmu.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"

#include <shared_mutex>
#include <vector>

namespace {

/* Rate select bits[6:4]: loc_F62984 @0xF629CC lhu / @0xF629CE neg 0x71 /
   @0xF629D6 sw. Word RMW @0xF617DE lw / @0xF617E2 or 4 / @0xF617E4 sw, and
   loc_F62984 @0xF62A46 lw / @0xF62A4A or 4 / @0xF62A4C sw. */
constexpr uint32_t kOffCtrl880 = 0x0880u;
/* bit0 enable loc_F618CC @0xF61966 lhu / @0xF61968 or / @0xF6196A sh, cleared
   loc_F62984 @0xF62A7E-@0xF62A86; bit1 set @0xF62A34-@0xF62A3E; bit2 hardware
   BUSY, read sub_F614E4 @0xF614EE and spun loc_F61EAC @0xF61EC8-@0xF61ED2. */
constexpr uint32_t kOffEnable884 = 0x0884u;
/* loc_F61EAC @0xF61EBC sw 0 -> 0x8A0 / @0xF61EC4 addiu $s0,2180 / @0xF61EC8 lw /
   @0xF61ECA li $a0,4 / @0xF61ECC and / @0xF61ECE beqz 0xF61ED4 / @0xF61ED2 b: the
   teardown spins until bit2 clears. No ROM site ever sets it. */
constexpr uint32_t kEnableBusyBit = 0x4u;
/* bit1 MONO: loc_F618CC @0xF61910 lhu / @0xF61914 or 2 / @0xF61926 sh (stereo
   @0xF6191E lhu / @0xF61924 and 0xFFFD); sub_F616F4 @0xF6171A sh 3. */
constexpr uint32_t kOffFormat888 = 0x0888u;
/* bit1 playback enable loc_F618CC @0xF6194E (|=2), cleared loc_F61EAC
   @0xF61F0C li 3 / @0xF61F0E neg / @0xF61F10 and; bit0 capture @0xF6277E. */
constexpr uint32_t kOffChan890 = 0x0890u;
/* bit0 transfer strobe: loc_F618CC @0xF6196E sw 1; cleared loc_F61EAC @0xF61EF8
   lw / @0xF61EFA li 2 / @0xF61EFC neg / @0xF61F00 sw; re-strobed by the IST
   decode dword_F622D4 @0xF6238E. */
constexpr uint32_t kOffStrobe898 = 0x0898u;
/* bit0 set loc_F62984 @0xF62A94 li 1 / @0xF62A98 sw (last write of the start
   path), cleared sub_F614E4 @0xF614F8, loc_F61EAC @0xF61EBC, sub_F62520
   @0xF6252E; read by nk_main_kernel.exe @0x9F0388CC lw / @0x9F0388D0 andi 1. */
constexpr uint32_t kOffLatch8A0 = 0x08A0u;
/* dword_F622D4 @0xF622E4 lhu, the source status the IST decode dispatches on. */
constexpr uint32_t kOffStatus8A8 = 0x08A8u;
/* CURRENT start/end + NEXT start/end, end inclusive: sub_F615D8 @0xF615E4/
   @0xF615EE/@0xF615F8/@0xF61602 programs all four, sub_F61614 @0xF61624/
   @0xF6162E only 0x8B8/0x8BC. */
constexpr uint32_t kOffDescLo = 0x08B0u;
constexpr uint32_t kOffDescHi = 0x08BCu;
/* Service gate, sub_F614E4 @0xF61512 sw 1; read by the IST decode dword_F622D4
   @0xF622E0. */
constexpr uint32_t kOffGate8C4 = 0x08C4u;
/* Interrupt ack pair: sub_F614E4 @0xF61520 sw 0x11 / @0xF6151A sh 0x11,
   dword_F622D4 @0xF622EC/@0xF622F4 sh 0x11, sub_F62520 @0xF6259E/@0xF625A6
   sh 0x10 then @0xF625B0/@0xF625B8 sh 0x11. */
constexpr uint32_t kOffAckL8C8 = 0x08C8u;
constexpr uint32_t kOffAckR8CC = 0x08CCu;

/* loc_F62984 @0xF629CE li $a2, 0x71 / neg -> 0xFFFFFF8F, so the select is
   bits[6:4]. */
constexpr uint32_t kRateSelectMask = 0x70u;

/* Every loc_F61998 converter stores with sh into the DMA buffer whatever the
   source width: @0xF61D3A (case 0, lbu source), @0xF61C92 (case 1, lh source),
   @0xF61BD0 + @0xF61BE6 (case 2), @0xF61B04 + @0xF61B1A (case 3). */
constexpr uint16_t kBitsPerSample = 16u;

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
    paced_.Start("Em500Audio", /*rate_hz=*/0, /*channels=*/0, /*bits=*/0,
                 /*allow_resampler=*/true);
    emu.Get<AudioActivityWidget>().NotePresent();
}

void CasioCassiopeiaEm500Audio::OnShutdown() { paced_.Stop(); }

void CasioCassiopeiaEm500Audio::SetRateDoubler(bool on) {
    std::lock_guard<std::mutex> lk(mtx_);
    rate_doubler_ = on;
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
    std::lock_guard<std::mutex> lk(mtx_);
    switch (off) {
        case kOffCtrl880:   merge(reg_880_); return true;
        /* dword_F622D4 @0xF62384 lhu 0x884 / @0xF62386 or 1 / @0xF62388 sh, loc_F61D94
           @0xF61DB2-@0xF61DB8, sub_F62520 @0xF6257E-@0xF62586 and loc_F62984
           @0xF62A38-@0xF62A3E / @0xF62A7E-@0xF62A86 read-modify-write 0x0884 with no
           mask clearing bit2. */
        case kOffEnable884:
            reg_884_ = (reg_884_ & 0xFFFF0000u) |
                       (value & static_cast<uint16_t>(~kEnableBusyBit));
            return true;
        case kOffFormat888: merge(reg_888_); return true;
        case kOffAckL8C8:   merge(reg_8C8_); return true;
        case kOffAckR8CC:   merge(reg_8CC_); return true;
        default: return false;
    }
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
        {
            std::lock_guard<std::mutex> lk(mtx_);
            desc_[index] = value;
        }
        if (index == kDescNextEnd) QueueDescriptor(kDescNextStart, false);
        return true;
    }
    switch (off) {
        case kOffChan890:   OnChannelWrite(value); return true;
        case kOffLatch8A0:  OnLatchWrite(value, 0u); return true;
        default: break;
    }
    std::lock_guard<std::mutex> lk(mtx_);
    switch (off) {
        case kOffCtrl880:   reg_880_ = value; return true;
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
        case kOffFormat888: reg_888_ = value; return true;
        case kOffGate8C4:   reg_8C4_ = value; return true;
        case kOffAckL8C8:   reg_8C8_ = value; return true;
        case kOffAckR8CC:   reg_8CC_ = value; return true;
        default: return false;
    }
}

void CasioCassiopeiaEm500Audio::OnLatchWrite(uint32_t value, uint32_t keep_mask) {
    bool started = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const bool was = Running();
        reg_8A0_ = (reg_8A0_ & keep_mask) | (value & ~keep_mask);
        started = !was && Running();
    }
    if (!started) return;
    StartSink();
    StartTransfers(false);
}

void CasioCassiopeiaEm500Audio::OnChannelWrite(uint32_t value) {
    bool started = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const bool was = PlayEnabled();
        reg_890_ = value;
        started = !was && PlayEnabled() && Running();
    }
    if (!started) return;
    StartSink();
    StartTransfers(false);
}

void CasioCassiopeiaEm500Audio::StartTransfers(bool holds_snapshot) {
    QueueDescriptor(kDescCurStart, holds_snapshot);
    QueueDescriptor(kDescNextStart, holds_snapshot);
}

void CasioCassiopeiaEm500Audio::StartSink() {
    uint32_t select = 0;
    bool doubler = false;
    uint16_t channels = 0;
    uint32_t gen = 0;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        select = reg_880_ & kRateSelectMask;
        doubler = rate_doubler_;
        channels = Channels();
        queued_      = 0;
        next_queued_ = false;
        gen = ++sink_gen_;
    }
    paced_.SetFormat(RateHzFor(select, doubler), channels, kBitsPerSample);
    paced_.BeginAudioOut([this, gen] { OnBlockDone(gen); });
}

void CasioCassiopeiaEm500Audio::QueueDescriptor(uint32_t start_index,
                                                 bool holds_snapshot) {
    std::shared_lock<std::shared_mutex> frozen;
    if (!holds_snapshot) frozen = emu_->Get<EmulationFreeze>().WorkerSection();

    uint32_t start_va = 0;
    uint32_t end_va = 0;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const bool is_next = start_index == kDescNextStart;
        if (queued_ == kMaxQueued || (is_next && next_queued_)) return;
        if (!Running() || !PlayEnabled()) return;
        start_va = desc_[start_index];
        end_va = desc_[start_index + 1u];
        ++queued_;
        if (is_next) next_queued_ = true;
    }
    const uint64_t span = static_cast<uint64_t>(end_va) -
                          static_cast<uint64_t>(start_va) + 1ull;
    if (end_va < start_va || span > PacedWaveOut::kMaxBlock) {
        LOG(Caution, "EM-500 audio DMA descriptor 0x%08X..0x%08X is not a block of "
                     "at most %u bytes\n", start_va, end_va, PacedWaveOut::kMaxBlock);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint32_t length = static_cast<uint32_t>(span);
    std::vector<uint8_t> block(length);
    /* VR4102 UM ch.5 p131 "(3) kseg1": references are not mapped through TLB and the
       physical address is the virtual address minus 0xA0000000. */
    emu_->Get<EmulatedMemory>().CopyOut(MipsSeg::UnmappedPa(start_va), block.data(), length);
    if (frozen.owns_lock()) frozen.unlock();

    emu_->Get<AudioActivityWidget>().MarkTx();
    if (paced_.QueueOutput(block.data(), length)) return;
    std::lock_guard<std::mutex> lk(mtx_);
    if (queued_ == 0u) {
        LOG(Caution, "EM-500 audio rollback with no block reserved\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    --queued_;
    if (start_index == kDescNextStart) next_queued_ = false;
}

void CasioCassiopeiaEm500Audio::OnBlockDone(uint32_t sink_gen) {
    bool drained = false;
    {
        auto frozen = emu_->Get<EmulationFreeze>().WorkerSection();
        {
            std::lock_guard<std::mutex> lk(mtx_);
            if (sink_gen != sink_gen_) return;
            if (queued_ == 0u) {
                LOG(Caution, "EM-500 audio completion with no block queued\n");
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            desc_[kDescCurStart] = desc_[kDescNextStart];
            desc_[kDescCurEnd] = desc_[kDescNextEnd];
            --queued_;
            next_queued_ = false;
            /* loc_F61EAC @0xF61EBC sw 0 -> 0x08A0; @0xF61EC8 lw 0x0884 /
               @0xF61ECC and 4 / @0xF61ECE beqz / @0xF61ED2 b. */
            drained = queued_ == 0u && !Running();
        }
        status_8A8_.fetch_or(kStatusBlockDone, std::memory_order_acq_rel);
        on_irq_change_();
    }
    if (drained) paced_.StopAudioOut();
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
    queued_      = 0;
    next_queued_ = false;
    ++sink_gen_;
}

void CasioCassiopeiaEm500Audio::PostRestore() {
    bool resume = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        resume = Running() && PlayEnabled();
    }
    if (!resume) return;
    StartSink();
    StartTransfers(true);
}
