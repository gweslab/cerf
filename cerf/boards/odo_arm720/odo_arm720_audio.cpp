#define NOMINMAX

#include "odo_arm720_audio_player.h"
#include "odo_arm720_touch_sound.h"
#include "odo_arm720_board_intc.h"

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "odo_id.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/audio_activity_widget.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"
#include "../../socs/irq_controller.h"

#include <cstdint>
#include <cstring>
#include <mutex>

namespace {

constexpr uint32_t kRecordDmaPa    = 0x10040810u;
constexpr uint32_t kPlaybackDmaPa  = 0x10050810u;
constexpr uint32_t kDmaPairSize    = 0x08u;
constexpr uint32_t kSlotDmaLow     = 0x00u;
constexpr uint32_t kSlotDmaHigh    = 0x04u;

constexpr uint32_t kDramPaBase     = 0x0C000000u;

constexpr uint16_t kIoSoundStrPlaybackIntr    = (1u << 13);
constexpr uint16_t kIoSoundStrPlaybackEndIntr = (1u << 12);

constexpr UINT kMsgStartPlayback = WM_USER + 0x1u;
constexpr UINT kMsgStopPlayback  = WM_USER + 0x2u;

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
        uint16_t value;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            if      (off == kSlotDmaLow)  value = dma_low_;
            else if (off == kSlotDmaHigh) value = dma_high_;
            else                          HaltUnsupportedAccess("ReadHalf", addr, 0);
        }
#if CERF_DEV_MODE
        LOG(Periph, "Odo %s read  +0x%02X -> 0x%04X\n",
            PortName(), off, value);
#endif
        return value;
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

}  /* namespace */

REGISTER_SERVICE(OdoArm720AudioRecordDma);
REGISTER_SERVICE(OdoArm720AudioPlaybackDma);
REGISTER_SERVICE(OdoArm720AudioPlayer);


bool OdoArm720AudioPlayer::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Odo;
}

void OdoArm720AudioPlayer::OnShutdown() { sink_.Stop(); }

void OdoArm720AudioPlayer::OnReady() {
    for (uint32_t i = 0; i < kPagesPerBuffer; ++i) {
        pages_[i].hdr.lpData         = reinterpret_cast<LPSTR>(pages_[i].bytes);
        pages_[i].hdr.dwBufferLength = kPageSize;
        pages_[i].hdr.dwUser         = i;
    }
    sink_.Start(
        [this] {
            sink_.EnsureFormat(kSampleRate, kChannels, kBitsPerSample,
                               /*allow_resampler=*/false, /*busy=*/false);
        },
        [this](const MSG& msg) { OnThreadMessage(msg); },
        "OdoArm720Audio");
    emu_.Get<AudioActivityWidget>().NotePresent();
}

void OdoArm720AudioPlayer::OnThreadMessage(const MSG& msg) {
    if (msg.message == kMsgStartPlayback) {
        playback_enabled_.store(true, std::memory_order_release);
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            current_page_index_ = 0;
            submitted_pages_    = 0;
        }
        for (uint32_t i = 0; i < kPagesPerBuffer; ++i) {
            SubmitNextPage();
        }
        return;
    }
    if (msg.message == kMsgStopPlayback) {
        playback_enabled_.store(false, std::memory_order_release);
        sink_.Reset();
        return;
    }
    if (msg.message == MM_WOM_DONE) {
        auto* hdr = reinterpret_cast<LPWAVEHDR>(msg.lParam);
        if (hdr) sink_.Unprepare(hdr);
        uint32_t done_page = hdr ? hdr->dwUser : 0;

        uint16_t bits = kIoSoundStrPlaybackIntr;
        if (done_page == kPagesPerBuffer - 1) {
            bits |= kIoSoundStrPlaybackEndIntr;
        }
        bool already_set;
        {
            auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
            already_set = emu_.Get<OdoArm720TouchSound>().RaiseSoundStrBits(bits);
            if (already_set) {
                emu_.Get<IrqController>().DeAssertIrq(kSourceTouchAudioAdcIntr);
            } else if (emu_.Get<OdoArm720TouchSound>().SoundIntrEnabled()) {
                emu_.Get<IrqController>().AssertIrq(kSourceTouchAudioAdcIntr);
            }
        }

        if (already_set) {
            playback_enabled_.store(false, std::memory_order_release);
            std::lock_guard<std::mutex> lk(state_mutex_);
            if (submitted_pages_ > 0) --submitted_pages_;
            return;
        }

        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            if (submitted_pages_ > 0) --submitted_pages_;
        }
        if (playback_enabled_.load(std::memory_order_acquire)) {
            SubmitNextPage();
        }
    }
}

void OdoArm720AudioPlayer::SubmitNextPage() {
    auto&          dma     = emu_.Get<OdoArm720AudioPlaybackDma>();
    auto&          mem     = emu_.Get<EmulatedMemory>();
    const uint32_t base_pa = dma.GetEffectivePa();

    uint32_t  page_index;
    PageSlot* slot;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (submitted_pages_ >= kPagesPerBuffer) return;
        page_index = current_page_index_;
        slot       = &pages_[page_index];
        current_page_index_ = (current_page_index_ + 1) % kPagesPerBuffer;
        ++submitted_pages_;
    }

    const uint32_t pa = base_pa + page_index * kPageSize;
    {
        auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
        for (uint32_t i = 0; i < kPageSize; ++i) {
            slot->bytes[i] = mem.ReadByte(pa + i);
        }
    }

    std::memset(&slot->hdr, 0, sizeof(slot->hdr));
    slot->hdr.lpData         = reinterpret_cast<LPSTR>(slot->bytes);
    slot->hdr.dwBufferLength = kPageSize;
    slot->hdr.dwUser         = page_index;

    if (!sink_.Play(&slot->hdr)) {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (submitted_pages_ > 0) --submitted_pages_;
        return;
    }
    emu_.Get<AudioActivityWidget>().MarkTx();
}

void OdoArm720AudioPlayer::SetPlaybackEnabled(bool enabled) {
    sink_.Post(enabled ? kMsgStartPlayback : kMsgStopPlayback, 0, 0);
}
