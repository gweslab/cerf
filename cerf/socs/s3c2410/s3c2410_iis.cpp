#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../host/audio_activity_widget.h"
#include "../../host/paced_wave_out.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "s3c2410_clocks.h"
#include "s3c2410_dma.h"
#include "s3c2410_iis_lrck_clock.h"
#include "s3c2410_iis_regs.h"
#include "s3c2410_iis_tx_fifo.h"
#include "s3c2410_iis_tx_transfer.h"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>

namespace {

using namespace S3C2410IisRegs;

constexpr uint32_t kBlockBytes = 2048u;
constexpr uint64_t kArmPhases  = kBlockBytes / sizeof(uint16_t);

class S3C2410Iis : public Peripheral, public S3C2410DmaRequester {
public:
    using Peripheral::Peripheral;

    void OnDmaChannelArmed() override {
        FillTxFifo();
        bool start_transmit = false;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            start_transmit = TransmitRunningLocked() && !playing_;
            LOG(SocIis, "dma armed: tx_count=%u reserved=%u playing=%d txdma=%d running=%d\n",
                fifo_.Count(), fifo_.Reserved(), playing_ ? 1 : 0,
                TxDmaArmedLocked() ? 1 : 0, TransmitRunningLocked() ? 1 : 0);
        }
        if (start_transmit) StartTransmit();
        else                Rearm();
    }
    void OnDmaAccess() override {
        bool armed = false;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            armed = TxDmaArmedLocked();
        }
        if (armed) TxAtomicTransfer();
        CatchUp(false);
    }

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::S3c2410;
    }

    void OnReady() override {
        drain_ev_ = emu_.Get<GuestCycleClock>().Add([this] { CatchUp(false); });
        emu_.Get<S3C2410Clocks>().RegisterRateListener([this] { CatchUp(true); });
        Reset();
        emu_.Get<GuestCpuReset>().RegisterResetListener(
            [this](ResetLineKind) { Reset(); });
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<S3C2410Dma>().RegisterRequester(S3C2410DmaSource::kI2sSdo, this);
        audio_out_.Start("S3C2410Iis", 0, 0, 0, true);
        emu_.Get<AudioActivityWidget>().NotePresent();
    }

    void OnShutdown() override { audio_out_.Stop(); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSpan; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;
    uint16_t ReadHalf (uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(mutex_);
        w.Write<uint32_t>("con", con_);
        w.Write<uint32_t>("mod", mod_);
        w.Write<uint32_t>("psr", psr_);
        w.Write<uint32_t>("fcon", fcon_);
        w.Write<uint8_t>("lr_index", lr_index_ ? 1u : 0u);
        fifo_.Save(w);
        lrck_.Save(w, playing_, emu_.Get<GuestCycleClock>().Cycles());
    }
    void RestoreState(StateReader& r) override;

    void PostRestore() override {
        bool start_transmit = false;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            start_transmit = TransmitRunningLocked() && !playing_;
            if (!start_transmit) lrck_.ForgetRestored();
        }
        if (start_transmit) StartTransmit();
    }

private:
    struct HostOut {
        uint8_t  block[2][kBlockBytes];
        uint32_t blocks   = 0;
        uint32_t new_rate = 0;
        bool     finished = false;
    };

    void Reset() {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            con_       = kConReset;
            mod_       = 0u;
            psr_       = 0u;
            fcon_      = 0u;
            fifo_.Reset();
            host_fill_ = 0u;
            playing_   = false;
            lr_index_  = true;
            lrck_.ForgetRestored();
        }
        emu_.Get<GuestCycleClock>().Disarm(drain_ev_);
        audio_out_.StopAudioOut();
    }

    /* qemu-neo1973 s3c_i2s_update gates the I2SSDO request on IISCON[0], [3] and [5], IISMOD[7],
       IISFCON[13] and [15]; devemu_wm653 s3c2410x_wavedev.dll 0x7B457078-0x7B457098 waits for
       CURR_TC to move before it sets IISCON[0]. */
    bool TxDmaArmedLocked() const {
        constexpr uint32_t kFconTxDma = kFconTxDmaMode | kFconTxEnable;
        return (con_ & kConTxDmaReq) != 0u && (con_ & kConTxIdle) == 0u
            && (mod_ & kModTransmit) != 0u && (fcon_ & kFconTxDma) == kFconTxDma;
    }
    bool TransmitRunningLocked() const {
        return (con_ & kConEnable) != 0u && (mod_ & kModTransmit) != 0u
            && (fcon_ & kFconTxEnable) != 0u && (con_ & kConTxIdle) == 0u;
    }

    /* S3C2410A UM printed p. 21-2 Figure 21-1, p. 21-7 IISPSR "division factor
       is N+1", p. 21-4 Table 21-1: PCLK / prescaler A = 256 or 384 fs. */
    uint64_t TransmitDivisorLocked() const {
        if ((con_ & kConPscEnable) == 0u)
            emu_.Get<Fatal>().Die("[S3C2410Iis] transmit with the IISCON prescaler "
                                  "disabled (IISCON=0x%08X)", con_);
        const uint64_t div_a = ((psr_ >> kPsrAShift) & kPsrFieldMask) + 1u;
        const uint64_t fs    = (mod_ & kMod384fs) ? kCodecClk384 : kCodecClk256;
        return div_a * fs;
    }
    uint32_t TransmitRateLocked() const {
        return static_cast<uint32_t>(emu_.Get<S3C2410Clocks>().PclkHz() /
                                     TransmitDivisorLocked());
    }
    uint64_t PhaseRateNumLocked() const {
        return emu_.Get<S3C2410Clocks>().PclkHz() * kEntriesPerFrame;
    }
    void CheckPhaseUnits(uint64_t num, uint64_t den, uint64_t cpu_hz) const {
        uint64_t step = 0, scale = 1;
        if (!S3C2410IisLrckClock::Units(num, den, cpu_hz, &step, &scale))
            emu_.Get<Fatal>().Die("[S3C2410Iis] phase rate %llu/%llu Hz against a %llu Hz "
                                  "core clock has no 32-bit phase units",
                                  static_cast<unsigned long long>(num),
                                  static_cast<unsigned long long>(den),
                                  static_cast<unsigned long long>(cpu_hz));
    }

    S3C2410DmaAtomicTransfer TxAtomicTransfer();
    bool FillTxFifo();
    void StartTransmit();
    void CatchUp(bool retime);
    void Rearm();
    void ArmLocked(uint32_t transfers_to_terminal);
    uint32_t RetimeLocked();
    void EmitLocked(uint64_t entries, HostOut& out);
    void CompleteBlockLocked(HostOut& out);
    void StopTransmitLocked(HostOut& out);
    void Deliver(const HostOut& out);

    GuestCycleClock::Event*          drain_ev_  = nullptr;
    S3C2410IisLrckClock              lrck_;
    std::array<uint8_t, kBlockBytes> host_block_{};
    uint32_t                         host_fill_ = 0;

    std::mutex       mutex_;
    uint32_t         con_     = kConReset;
    uint32_t         mod_     = 0u;
    uint32_t         psr_     = 0u;
    uint32_t         fcon_    = 0u;
    S3C2410IisTxFifo fifo_;
    bool             playing_  = false;
    bool             lr_index_ = true;
    PacedWaveOut     audio_out_;
};

void S3C2410Iis::RestoreState(StateReader& r) {
    const S3C2410DmaAtomicTransfer atomic =
        emu_.Get<S3C2410Dma>().AtomicTransfer(S3C2410DmaSource::kI2sSdo);
    {
        std::lock_guard<std::mutex> lk(mutex_);
        r.Read("con", con_);
        r.Read("mod", mod_);
        r.Read("psr", psr_);
        r.Read("fcon", fcon_);
        uint8_t lr_index = 0;
        r.Read("lr_index", lr_index);
        if (lr_index > 1u) r.Reject("IISCON L/R index %u is not 0 or 1", lr_index);
        lr_index_ = lr_index != 0u;
        if ((con_ & ~kConWritable) != kConReset || (con_ & kConRxDmaReq) != 0u)
            r.Reject("IISCON 0x%08X", con_);
        if ((mod_ & ~kModWritable) != 0u ||
            ((mod_ & kModTransmit) != 0u &&
             ((mod_ & kMod16Bit) == 0u || (mod_ & kModSlave) != 0u)))
            r.Reject("IISMOD 0x%08X", mod_);
        if ((psr_ & ~kPsrWritable) != 0u)
            r.Reject("IISPSR 0x%08X", psr_);
        if ((fcon_ & ~kFconWritable) != 0u ||
            (fcon_ & (kFconRxEnable | kFconRxDmaMode)) != 0u)
            r.Reject("IISFCON 0x%08X", fcon_);
        if (TransmitRunningLocked() && (con_ & kConPscEnable) == 0u)
            r.Reject("transmit running with the IISCON prescaler disabled (IISCON=0x%08X)",
                     con_);
        if (TxDmaArmedLocked() && !S3C2410IisModelledTxTransfer(atomic))
            r.Reject("transmit DMA armed on %u channels, an atomic transfer of %u bytes "
                     "(burst %d) to 0x%08X (fixed %d)", atomic.channels, atomic.bytes,
                     atomic.burst ? 1 : 0, atomic.dst, atomic.dst_fixed ? 1 : 0);
        fifo_.Restore(r);
        const bool     running = TransmitRunningLocked();
        const uint64_t num     = running ? PhaseRateNumLocked() : 0u;
        const uint64_t den     = running ? TransmitDivisorLocked() : 1u;
        lrck_.Restore(r, emu_.Get<GuestCycleClock>().Cycles(),
                      emu_.Get<S3C2410Clocks>().CoreClockHz(), num, den, 2u * kArmPhases);
        host_fill_ = 0u;
        playing_   = false;
    }
    emu_.Get<GuestCycleClock>().Disarm(drain_ev_);
    audio_out_.StopAudioOut();
}

uint32_t S3C2410Iis::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    CatchUp(false);
    std::lock_guard<std::mutex> lk(mutex_);
    uint32_t value = 0;
    switch (off) {
        case kOffCon:
            value = (con_ & ~(kConTxFifoRdy | kConLrIndex))
                  | (fifo_.Count() != 0u ? kConTxFifoRdy : 0u)
                  | ((playing_ ? lrck_.RightPhase() : lr_index_) ? kConLrIndex : 0u);
            break;
        case kOffMod: value = mod_; break;
        case kOffPsr: value = psr_; break;
        case kOffFcon:
            value = fcon_ | (fifo_.Count() << kFconTxCntShift);
            break;
        default:
            HaltUnsupportedAccess("ReadWord", addr, 0);
    }
#if CERF_DEV_MODE
    LOG(SocIis, "read  +0x%02X -> 0x%08X\n", off, value);
#endif
    return value;
}

void S3C2410Iis::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - kBase;
#if CERF_DEV_MODE
    LOG(SocIis, "write +0x%02X = 0x%08X\n", off, value);
#endif
    CatchUp(false);
    HostOut out;
    bool    fill_fifo      = false;
    bool    start_transmit = false;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        const bool was_playing = playing_;
        switch (off) {
            case kOffCon:
                if ((value & kConRxDmaReq) != 0u)
                    HaltUnsupportedAccess("WriteWord IISCON Rx DMA request",
                                          addr, value);
                con_ = (con_ & ~kConWritable) | (value & kConWritable);
                break;
            case kOffMod:
                if ((value & kModTransmit) != 0u) {
                    if ((value & kMod16Bit) == 0u)
                        HaltUnsupportedAccess("WriteWord IISMOD 8-bit transmit",
                                              addr, value);
                    if ((value & kModSlave) != 0u)
                        HaltUnsupportedAccess("WriteWord IISMOD slave transmit",
                                              addr, value);
                }
                mod_ = value & kModWritable;
                break;
            case kOffPsr:
                psr_ = value & kPsrWritable;
                break;
            case kOffFcon:
                if ((value & (kFconRxEnable | kFconRxDmaMode)) != 0u)
                    HaltUnsupportedAccess("WriteWord IISFCON receive FIFO",
                                          addr, value);
                if ((fcon_ & kFconTxEnable) != 0u && (value & kFconTxEnable) == 0u)
                    fifo_.Clear();
                fcon_ = value & kFconWritable;
                break;
            default:
                HaltUnsupportedAccess("WriteWord", addr, value);
        }
        if (was_playing) {
            if (TransmitRunningLocked()) out.new_rate = RetimeLocked();
            else                         StopTransmitLocked(out);
        }
        fill_fifo      = TxDmaArmedLocked();
        start_transmit = TransmitRunningLocked() && !playing_;
    }
    Deliver(out);
    if (fill_fifo) FillTxFifo();
    if (start_transmit) StartTransmit();
    else                Rearm();
}

S3C2410DmaAtomicTransfer S3C2410Iis::TxAtomicTransfer() {
    const S3C2410DmaAtomicTransfer atomic =
        emu_.Get<S3C2410Dma>().AtomicTransfer(S3C2410DmaSource::kI2sSdo);
    if (!S3C2410IisModelledTxTransfer(atomic))
        emu_.Get<Fatal>().Die("[S3C2410Iis] transmit DMA on %u channels, %u bytes (burst %d) "
                              "to 0x%08X (fixed %d)", atomic.channels, atomic.bytes,
                              atomic.burst ? 1 : 0, atomic.dst, atomic.dst_fixed ? 1 : 0);
    return atomic;
}

bool S3C2410Iis::FillTxFifo() {
    auto& dma   = emu_.Get<S3C2410Dma>();
    bool  moved = false;
    for (;;) {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (!TxDmaArmedLocked()) return moved;
        }
        const uint32_t entries = TxAtomicTransfer().bytes / sizeof(uint16_t);
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (!TxDmaArmedLocked() || !fifo_.Reserve(entries)) return moved;
        }
        const bool served = dma.ServiceRequest(S3C2410DmaSource::kI2sSdo);
        {
            std::lock_guard<std::mutex> lk(mutex_);
            fifo_.Release(entries);
        }
        if (!served) return moved;
        moved = true;
    }
}

uint16_t S3C2410Iis::ReadHalf(uint32_t addr) {
    HaltUnsupportedAccess("ReadHalf", addr, 0);
}

void S3C2410Iis::WriteHalf(uint32_t addr, uint16_t value) {
    if (addr - kBase != kOffFifo)
        HaltUnsupportedAccess("WriteHalf", addr, value);
    std::lock_guard<std::mutex> lk(mutex_);
    if (!fifo_.Push(value))
        emu_.Get<Fatal>().Die("S3C2410Iis: transmit FIFO overrun at depth %u",
                              S3C2410IisTxFifo::kDepth);
}

void S3C2410Iis::StartTransmit() {
    uint32_t rate = 0;
    uint64_t num  = 0;
    uint64_t den  = 1;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        if (playing_) return;
        rate     = TransmitRateLocked();
        num      = PhaseRateNumLocked();
        den      = TransmitDivisorLocked();
        playing_ = true;
    }
    audio_out_.SetFormat(rate, 2, 16);
    audio_out_.BeginAudioOut({});
    {
        std::lock_guard<std::mutex> lk(mutex_);
        const uint64_t hz = emu_.Get<S3C2410Clocks>().CoreClockHz();
        CheckPhaseUnits(num, den, hz);
        lrck_.Start(emu_.Get<GuestCycleClock>().Cycles(), num, den, hz);
    }
    FillTxFifo();
    Rearm();
}

/* S3C2410A UM printed p. 21-3: one word per IISLRCK phase, the DMA request "made
   by the FIFO ready flag automatically"; p. 8-11: CURR_TC per atomic transfer. */
void S3C2410Iis::CatchUp(bool retime) {
    HostOut  out;
    uint64_t due = 0;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        if (!playing_) return;
        due = lrck_.Take(emu_.Get<GuestCycleClock>().Cycles());
    }
    for (;;) {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            const uint64_t queued = std::min<uint64_t>(due, fifo_.Count());
            EmitLocked(queued, out);
            due -= queued;
        }
        const bool refilled = FillTxFifo();
        if (due == 0u) break;
        if (!refilled) {
            std::lock_guard<std::mutex> lk(mutex_);
            EmitLocked(due, out);
            break;
        }
    }
    const uint32_t to_terminal =
        emu_.Get<S3C2410Dma>().TransfersToTerminalCount(S3C2410DmaSource::kI2sSdo);
    {
        std::lock_guard<std::mutex> lk(mutex_);
        if (retime && playing_) out.new_rate = RetimeLocked();
        ArmLocked(to_terminal);
    }
    Deliver(out);
}

void S3C2410Iis::Rearm() {
    const uint32_t to_terminal =
        emu_.Get<S3C2410Dma>().TransfersToTerminalCount(S3C2410DmaSource::kI2sSdo);
    std::lock_guard<std::mutex> lk(mutex_);
    ArmLocked(to_terminal);
}

void S3C2410Iis::ArmLocked(uint32_t transfers_to_terminal) {
    auto& clock = emu_.Get<GuestCycleClock>();
    if (!playing_) {
        clock.Disarm(drain_ev_);
        return;
    }
    uint64_t phases = (kBlockBytes - host_fill_) / sizeof(uint16_t);
    if (TxDmaArmedLocked() && transfers_to_terminal != 0u)
        phases = std::min<uint64_t>(phases, transfers_to_terminal);
    clock.Arm(drain_ev_, lrck_.CycleOf(phases));
}

uint32_t S3C2410Iis::RetimeLocked() {
    const uint64_t num = PhaseRateNumLocked();
    const uint64_t den = TransmitDivisorLocked();
    const uint64_t hz  = emu_.Get<S3C2410Clocks>().CoreClockHz();
    CheckPhaseUnits(num, den, hz);
    return lrck_.Retime(num, den, hz) ? TransmitRateLocked() : 0u;
}

void S3C2410Iis::EmitLocked(uint64_t entries, HostOut& out) {
    while (entries-- != 0u) {
        const uint16_t sample = fifo_.Pop();
        std::memcpy(host_block_.data() + host_fill_, &sample, sizeof(sample));
        host_fill_ += sizeof(sample);
        if (host_fill_ == kBlockBytes) CompleteBlockLocked(out);
    }
}

void S3C2410Iis::CompleteBlockLocked(HostOut& out) {
    if (out.blocks == 2u)
        emu_.Get<Fatal>().Die("[S3C2410Iis] a third host block completed in one "
                              "catch-up (host_fill=%u)", host_fill_);
    std::memcpy(out.block[out.blocks++], host_block_.data(), kBlockBytes);
    host_fill_ = 0u;
}

void S3C2410Iis::StopTransmitLocked(HostOut& out) {
    if (host_fill_ != 0u) {
        std::memset(host_block_.data() + host_fill_, 0, kBlockBytes - host_fill_);
        host_fill_ = kBlockBytes;
        CompleteBlockLocked(out);
    }
    lr_index_    = lrck_.RightPhase();
    playing_     = false;
    out.finished = true;
}

void S3C2410Iis::Deliver(const HostOut& out) {
    for (uint32_t i = 0; i < out.blocks; ++i) {
        audio_out_.QueueOutput(out.block[i], kBlockBytes);
        emu_.Get<AudioActivityWidget>().MarkTx();
    }
    if (out.new_rate != 0u) audio_out_.SetFormat(out.new_rate, 2, 16);
    if (out.finished) audio_out_.FinishAudioOut();
}

}

REGISTER_SERVICE(S3C2410Iis);
