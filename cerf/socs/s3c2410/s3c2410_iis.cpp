#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../host/audio_activity_widget.h"
#include "../../host/paced_wave_out.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "s3c2410_clocks.h"
#include "s3c2410_dma.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>

namespace {

/* S3C2410A User Manual, printed pp. 21-5..21-8 "IIS-BUS INTERFACE SPECIAL
   REGISTERS": IISCON at 0x55000000, IISMOD 0x55000004, IISPSR 0x55000008,
   IISFCON 0x5500000C, IISFIFO 0x55000010. */
constexpr uint32_t kBase = 0x55000000u;
constexpr uint32_t kSpan = 0x14u;

constexpr uint32_t kOffCon  = 0x00u;
constexpr uint32_t kOffMod  = 0x04u;
constexpr uint32_t kOffPsr  = 0x08u;
constexpr uint32_t kOffFcon = 0x0Cu;
constexpr uint32_t kOffFifo = 0x10u;

/* S3C2410A User Manual, printed p. 21-5 IISCON. */
constexpr uint32_t kConWritable  = 0x0000003Fu;
constexpr uint32_t kConReset     = 0x00000100u;
constexpr uint32_t kConTxFifoRdy = 1u << 7;
constexpr uint32_t kConTxDmaReq  = 1u << 5;
constexpr uint32_t kConRxDmaReq  = 1u << 4;
constexpr uint32_t kConTxIdle    = 1u << 3;
constexpr uint32_t kConPscEnable = 1u << 1;
constexpr uint32_t kConEnable    = 1u << 0;

/* S3C2410A User Manual, printed p. 21-6 IISMOD. */
constexpr uint32_t kModWritable = 0x000001FFu;
constexpr uint32_t kModSlave    = 1u << 8;
constexpr uint32_t kModTransmit = 1u << 7;
constexpr uint32_t kMod16Bit    = 1u << 3;
constexpr uint32_t kMod384fs    = 1u << 2;

/* S3C2410A User Manual, printed p. 21-7 IISPSR and Figure 21-1 printed p. 21-2. */
constexpr uint32_t kPsrWritable = 0x000003FFu;
constexpr uint32_t kPsrAShift   = 5u;
constexpr uint32_t kPsrFieldMask = 0x1Fu;

/* S3C2410A User Manual, printed p. 21-8 IISFCON. */
constexpr uint32_t kFconWritable   = 0x0000F000u;
constexpr uint32_t kFconTxDmaMode  = 1u << 15;
constexpr uint32_t kFconRxDmaMode  = 1u << 14;
constexpr uint32_t kFconTxEnable   = 1u << 13;
constexpr uint32_t kFconRxEnable   = 1u << 12;
constexpr uint32_t kFconTxCntShift = 6u;

/* S3C2410A User Manual, printed p. 21-8: "two 64-byte FIFO ... 16-width and
   32-depth". */
constexpr uint32_t kTxFifoDepth = 32u;

/* S3C2410A User Manual, printed p. 21-4, Table 21-1 "CODEC clock (CODECLK = 256
   or 384fs)". */
constexpr uint32_t kCodecClk256 = 256u;
constexpr uint32_t kCodecClk384 = 384u;

constexpr uint32_t kBlockBytes = 2048u;

class S3C2410Iis : public Peripheral, public S3C2410DmaRequester {
public:
    using Peripheral::Peripheral;

    void OnDmaChannelArmed() override {
        FillTxFifo();
        bool start_transmit = false;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            start_transmit = TransmitRunningLocked() && !playing_;
        }
        if (start_transmit) StartTransmit();
    }

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::S3c2410;
    }

    void OnReady() override {
        Reset();
        emu_.Get<GuestCpuReset>().RegisterResetListener(
            [this](ResetLineKind) { Reset(); });
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<S3C2410Dma>().RegisterRequester(S3C2410DmaSource::kI2sSdo,
                                                 this);
        audio_out_.Start("S3C2410Iis", /*rate_hz=*/0, 0, 0,
                         /*allow_resampler=*/true);
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
        w.Write<uint32_t>("tx_count", tx_count_);
        w.Write<uint32_t>("tx_head", tx_head_);
        w.WriteBytes("tx_fifo", tx_fifo_.data(), sizeof(tx_fifo_));
    }
    void RestoreState(StateReader& r) override {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            r.Read("con", con_);
            r.Read("mod", mod_);
            r.Read("psr", psr_);
            r.Read("fcon", fcon_);
            r.Read("tx_count", tx_count_);
            r.Read("tx_head", tx_head_);
            r.ReadBytes("tx_fifo", tx_fifo_.data(), sizeof(tx_fifo_));
            playing_ = false;
        }
        audio_out_.StopAudioOut();
    }

    void PostRestore() override {
        bool start_transmit = false;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            start_transmit = TransmitRunningLocked() && !playing_;
        }
        if (start_transmit) StartTransmit();
    }

private:
    void Reset() {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            con_      = kConReset;
            mod_      = 0u;
            psr_      = 0u;
            fcon_     = 0u;
            tx_head_  = 0u;
            tx_count_ = 0u;
            tx_fifo_.fill(0u);
            playing_ = false;
        }
        audio_out_.StopAudioOut();
    }

    /* Linux 2.6.25 sound/soc/s3c24xx/s3c24xx-i2s.c s3c24xx_snd_txctrl and
       s3c24xx-pcm.c s3c24xx_pcm_prepare: the transmit path is armed by IISFCON
       TXDMA|TXENABLE with IISCON TXDMAEN, IISFIFO is written only by the DMA
       channel, and IISCON[7] is never read - the request follows FIFO room. */
    bool TxDmaArmedLocked() const {
        constexpr uint32_t kFconTxDma = kFconTxDmaMode | kFconTxEnable;
        return (con_ & kConTxDmaReq) != 0u && (fcon_ & kFconTxDma) == kFconTxDma;
    }
    /* Linux 2.6.25 sound/soc/s3c24xx/s3c24xx-i2s.c s3c24xx_snd_txctrl clears
       IISCON TXIDLE to start the transmit channel and sets it to stop. */
    bool TransmitRunningLocked() const {
        return (con_ & kConEnable) != 0u && (mod_ & kModTransmit) != 0u
            && (fcon_ & kFconTxEnable) != 0u && (con_ & kConTxIdle) == 0u;
    }

    uint32_t SampleRateHzLocked() const {
        const uint32_t div_a = ((psr_ >> kPsrAShift) & kPsrFieldMask) + 1u;
        const uint32_t fs    = (mod_ & kMod384fs) ? kCodecClk384 : kCodecClk256;
        return static_cast<uint32_t>(emu_.Get<S3C2410Clocks>().PclkHz() / div_a / fs);
    }

    /* S3C2410A User Manual, printed p. 8-10 SERVMODE 0: "after each atomic
       transfer (single or burst of length four) DMA stops and waits for
       another DMA request". */
    static constexpr uint32_t kMaxBurstSamples = 4u;

    bool ReserveTxPullLocked() {
        if (tx_count_ + tx_reserved_ + kMaxBurstSamples > kTxFifoDepth)
            return false;
        tx_reserved_ += kMaxBurstSamples;
        return true;
    }
    void ReleaseTxPull() {
        std::lock_guard<std::mutex> lk(mutex_);
        tx_reserved_ -= kMaxBurstSamples;
    }

    void PushTxSample(uint16_t sample);
    void FillTxFifo();
    void StartTransmit();
    void PumpBlock();

    std::mutex                             mutex_;
    uint32_t                               con_      = kConReset;
    uint32_t                               mod_      = 0u;
    uint32_t                               psr_      = 0u;
    uint32_t                               fcon_     = 0u;
    std::array<uint16_t, kTxFifoDepth>     tx_fifo_{};
    uint32_t                               tx_head_  = 0u;
    uint32_t                               tx_count_ = 0u;
    uint32_t                               tx_reserved_ = 0u;
    bool                                   playing_  = false;
    PacedWaveOut                           audio_out_;
};

uint32_t S3C2410Iis::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    std::lock_guard<std::mutex> lk(mutex_);
    uint32_t value = 0;
    switch (off) {
        case kOffCon:
            value = (con_ & ~kConTxFifoRdy)
                  | (tx_count_ != 0u ? kConTxFifoRdy : 0u);
            break;
        case kOffMod: value = mod_; break;
        case kOffPsr: value = psr_; break;
        case kOffFcon:
            value = fcon_ | (tx_count_ << kFconTxCntShift);
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
    bool fill_fifo      = false;
    bool start_transmit = false;
    {
        std::lock_guard<std::mutex> lk(mutex_);
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
                fcon_ = value & kFconWritable;
                break;
            default:
                HaltUnsupportedAccess("WriteWord", addr, value);
        }
        fill_fifo      = TxDmaArmedLocked();
        start_transmit = TransmitRunningLocked() && !playing_;
    }
    if (fill_fifo)      FillTxFifo();
    if (start_transmit) StartTransmit();
}

void S3C2410Iis::FillTxFifo() {
    for (;;) {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (!TxDmaArmedLocked() || !ReserveTxPullLocked()) return;
        }
        const bool moved =
            emu_.Get<S3C2410Dma>().ServiceRequest(S3C2410DmaSource::kI2sSdo);
        ReleaseTxPull();
        if (!moved) return;
    }
}

uint16_t S3C2410Iis::ReadHalf(uint32_t addr) {
    HaltUnsupportedAccess("ReadHalf", addr, 0);
}

void S3C2410Iis::WriteHalf(uint32_t addr, uint16_t value) {
    if (addr - kBase != kOffFifo)
        HaltUnsupportedAccess("WriteHalf", addr, value);
    PushTxSample(value);
}

void S3C2410Iis::PushTxSample(uint16_t sample) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (tx_count_ >= kTxFifoDepth)
        emu_.Get<Fatal>().Die("S3C2410Iis: transmit FIFO overrun at depth %u",
                              kTxFifoDepth);
    tx_fifo_[(tx_head_ + tx_count_) % kTxFifoDepth] = sample;
    ++tx_count_;
}

void S3C2410Iis::StartTransmit() {
    uint32_t rate = 0;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        if (playing_) return;
        if ((con_ & kConPscEnable) == 0u)
            emu_.Get<Fatal>().Die("[S3C2410Iis] transmit started with IISCON "
                                  "prescaler disabled; sample rate ungrounded");
        playing_ = true;
        rate = SampleRateHzLocked();
    }
    audio_out_.SetFormat(rate, 2, 16);
    audio_out_.BeginAudioOut([this] {
        auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
        PumpBlock();
    });
    PumpBlock();
    PumpBlock();
}

void S3C2410Iis::PumpBlock() {
    uint8_t  block[kBlockBytes];
    uint32_t filled = 0;
    for (;;) {
        bool want_more = false;
        {
            std::lock_guard<std::mutex> lk(mutex_);
            if (!playing_ || !TransmitRunningLocked()) { playing_ = false; return; }
            while (filled + sizeof(uint16_t) <= kBlockBytes && tx_count_ != 0u) {
                const uint16_t sample = tx_fifo_[tx_head_];
                tx_head_ = (tx_head_ + 1u) % kTxFifoDepth;
                --tx_count_;
                std::memcpy(block + filled, &sample, sizeof(sample));
                filled += sizeof(sample);
            }
            want_more = filled < kBlockBytes && TxDmaArmedLocked()
                     && ReserveTxPullLocked();
        }
        if (!want_more) break;
        const bool moved =
            emu_.Get<S3C2410Dma>().ServiceRequest(S3C2410DmaSource::kI2sSdo);
        ReleaseTxPull();
        if (!moved) break;
    }
    if (filled == 0u) {
        {
            std::lock_guard<std::mutex> lk(mutex_);
            playing_ = false;
        }
        LOG(SocIis, "transmit underrun: FIFO empty with no DMA data; playback "
                    "stops until the channel is armed again\n");
        return;
    }
    audio_out_.QueueOutput(block, filled);
    emu_.Get<AudioActivityWidget>().MarkTx();
}

}  /* namespace */

REGISTER_SERVICE(S3C2410Iis);
