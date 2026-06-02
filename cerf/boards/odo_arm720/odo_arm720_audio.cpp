#define NOMINMAX

#include "odo_arm720_audio_player.h"
#include "odo_arm720_touch_sound.h"
#include "odo_arm720_board_intc.h"

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../cpu/emulated_memory.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../socs/irq_controller.h"

#include <cstdint>
#include <cstring>
#include <mutex>

namespace {

/* P2.H:356-364 (ARM branch). */
constexpr uint32_t kRecordDmaPa    = 0x10040810u;
constexpr uint32_t kPlaybackDmaPa  = 0x10050810u;
constexpr uint32_t kDmaPairSize    = 0x08u;
constexpr uint32_t kSlotDmaLow     = 0x00u;
constexpr uint32_t kSlotDmaHigh    = 0x04u;

/* DRAM PA base from MAP720.H line 39. */
constexpr uint32_t kDramPaBase     = 0x0C000000u;

/* TCHAUD.H:103-106 — playback intr bits. */
constexpr uint16_t kIoSoundStrPlaybackIntr    = (1u << 13);
constexpr uint16_t kIoSoundStrPlaybackEndIntr = (1u << 12);

constexpr UINT kMsgStartPlayback = WM_USER + 0x1u;
constexpr UINT kMsgStopPlayback  = WM_USER + 0x2u;

class AudioDmaPair : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OdoArm720;
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

    /* DEBUG.C:38-39: chip strips bits 31:26 on DMA-reg writes. */
    uint32_t GetEffectivePa() {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const uint32_t chip_addr =
            (static_cast<uint32_t>(dma_high_ & 0xFFu) << 16) |
            static_cast<uint32_t>(dma_low_);
        return kDramPaBase + chip_addr;
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
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetBoard() == Board::OdoArm720;
}

OdoArm720AudioPlayer::~OdoArm720AudioPlayer() {
    shutdown_.store(true, std::memory_order_release);
    if (audio_thread_id_) PostThreadMessageW(audio_thread_id_, WM_QUIT, 0, 0);
    if (audio_thread_.joinable()) audio_thread_.join();
    if (out_device_) waveOutClose(out_device_);
    if (thread_ready_event_) CloseHandle(thread_ready_event_);
}

void OdoArm720AudioPlayer::OnReady() {
    for (uint32_t i = 0; i < kPagesPerBuffer; ++i) {
        pages_[i].hdr.lpData         = reinterpret_cast<LPSTR>(pages_[i].bytes);
        pages_[i].hdr.dwBufferLength = kPageSize;
        pages_[i].hdr.dwUser         = i;
    }

    thread_ready_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    audio_thread_ = std::thread([this] { AudioThreadMain(); });
    WaitForSingleObject(thread_ready_event_, INFINITE);
}

void OdoArm720AudioPlayer::AudioThreadMain() {
    audio_thread_id_ = GetCurrentThreadId();

    /* Force-create the message queue so PostThreadMessage from
       SetPlaybackEnabled lands before our GetMessage call. */
    MSG msg;
    PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
    SetEvent(thread_ready_event_);

    WAVEFORMATEX fmt{};
    fmt.wFormatTag      = WAVE_FORMAT_PCM;
    fmt.nChannels       = kChannels;
    fmt.nSamplesPerSec  = kSampleRate;
    fmt.wBitsPerSample  = kBitsPerSample;
    fmt.nBlockAlign     = static_cast<uint16_t>(
                            (fmt.wBitsPerSample / 8) * fmt.nChannels);
    fmt.nAvgBytesPerSec = fmt.nSamplesPerSec * fmt.nBlockAlign;
    fmt.cbSize          = 0;

    const MMRESULT r = waveOutOpen(&out_device_, WAVE_MAPPER, &fmt,
                                   audio_thread_id_, 0,
                                   CALLBACK_THREAD | WAVE_FORMAT_DIRECT);
    if (r != MMSYSERR_NOERROR) {
        LOG(Caution, "OdoArm720AudioPlayer: waveOutOpen failed "
                "(mmresult=%u) — silent-mode boot (IRQ delivery "
                "still works, kernel just won't hear playback)\n", r);
        out_device_ = nullptr;
    }

    while (!shutdown_.load(std::memory_order_acquire) &&
           GetMessageW(&msg, nullptr, 0, 0) > 0) {
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
            continue;
        }
        if (msg.message == kMsgStopPlayback) {
            playback_enabled_.store(false, std::memory_order_release);
            if (out_device_) waveOutReset(out_device_);
            continue;
        }
        if (msg.message == MM_WOM_DONE) {
            auto* hdr = reinterpret_cast<LPWAVEHDR>(msg.lParam);
            if (out_device_ && hdr) {
                waveOutUnprepareHeader(out_device_, hdr, sizeof(WAVEHDR));
            }
            uint32_t done_page = hdr ? hdr->dwUser : 0;

            uint16_t bits = kIoSoundStrPlaybackIntr;
            if (done_page == kPagesPerBuffer - 1) {
                bits |= kIoSoundStrPlaybackEndIntr;
            }
            const bool already_set =
                emu_.Get<OdoArm720TouchSound>().RaiseSoundStrBits(bits);

            /* DeAssertIrq required: kernel leaves PlaybackIntr
               set on end-of-data (WAVEPDD.C:246-253); cpuMr
               pulse (ARMINT.C:318-320) re-triggers IRQ in a
               tight loop without source de-assert. */
            if (already_set) {
                playback_enabled_.store(false, std::memory_order_release);
                emu_.Get<IrqController>().DeAssertIrq(kSourceTouchAudioAdcIntr);
                std::lock_guard<std::mutex> lk(state_mutex_);
                if (submitted_pages_ > 0) --submitted_pages_;
                continue;
            }

            /* Skipping this gate → ARMINT.C:203 falls to
               SYSINTR_NOP while sound is masked; cpuMr pulse
               re-triggers the same NOP, keybIntr at
               ARMINT.C:237 never runs. */
            if (emu_.Get<OdoArm720TouchSound>().SoundIntrEnabled()) {
                emu_.Get<IrqController>().AssertIrq(
                    kSourceTouchAudioAdcIntr);
            }

            {
                std::lock_guard<std::mutex> lk(state_mutex_);
                if (submitted_pages_ > 0) --submitted_pages_;
            }
            if (playback_enabled_.load(std::memory_order_acquire)) {
                SubmitNextPage();
            }
            continue;
        }
    }
}

void OdoArm720AudioPlayer::SubmitNextPage() {
    if (!out_device_) return;

    auto&         dma = emu_.Get<OdoArm720AudioPlaybackDma>();
    auto&         mem = emu_.Get<EmulatedMemory>();
    const uint32_t base_pa = dma.GetEffectivePa();

    uint32_t page_index;
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
    for (uint32_t i = 0; i < kPageSize; ++i) {
        slot->bytes[i] = mem.ReadByte(pa + i);
    }

    std::memset(&slot->hdr, 0, sizeof(slot->hdr));
    slot->hdr.lpData         = reinterpret_cast<LPSTR>(slot->bytes);
    slot->hdr.dwBufferLength = kPageSize;
    slot->hdr.dwUser         = page_index;

    MMRESULT r = waveOutPrepareHeader(out_device_, &slot->hdr,
                                      sizeof(WAVEHDR));
    if (r != MMSYSERR_NOERROR) {
        LOG(Caution, "OdoArm720AudioPlayer: waveOutPrepareHeader "
                "failed (mmresult=%u) — dropping page %u\n",
                r, page_index);
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (submitted_pages_ > 0) --submitted_pages_;
        return;
    }
    r = waveOutWrite(out_device_, &slot->hdr, sizeof(WAVEHDR));
    if (r != MMSYSERR_NOERROR) {
        LOG(Caution, "OdoArm720AudioPlayer: waveOutWrite failed "
                "(mmresult=%u) — dropping page %u\n",
                r, page_index);
        waveOutUnprepareHeader(out_device_, &slot->hdr, sizeof(WAVEHDR));
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (submitted_pages_ > 0) --submitted_pages_;
    }
}

void OdoArm720AudioPlayer::SetPlaybackEnabled(bool enabled) {
    if (!audio_thread_id_) return;
    PostThreadMessageW(audio_thread_id_,
                       enabled ? kMsgStartPlayback : kMsgStopPlayback,
                       0, 0);
}
