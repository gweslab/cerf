#define NOMINMAX

#include "s3c2410_iis.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../irq_controller.h"

#include <cstring>

REGISTER_SERVICE(S3C2410Iis);

namespace {

constexpr uint32_t kRegIISCON  = 0x00u;
constexpr uint32_t kRegIISMOD  = 0x04u;
constexpr uint32_t kRegIISPSR  = 0x08u;
constexpr uint32_t kRegIISFCON = 0x0Cu;
constexpr uint32_t kRegIISFIFO = 0x10u;

constexpr uint32_t kIisconTxFifoReady = 0x80u;
constexpr uint32_t kIisconRxFifoReady = 0x40u;

/* INT_DMA2 = SRCPND bit 19 — wavedev's ISR target. */
constexpr int kIrqDma2 = 19;

/* Custom thread message — see BSP IOIIS::SetOutputDMA. Sent on DMA
   enable to mark the threshold past which MM_WOM_DONE generates an
   interrupt; messages posted before this don't (DMA was off when
   they were queued). */
constexpr UINT kMsgOutDmaEnable = 0xC001u;

}  /* namespace */

bool S3C2410Iis::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetSoc() == SocFamily::S3C2410;
}

S3C2410Iis::~S3C2410Iis() {
    shutdown_.store(true, std::memory_order_release);
    if (audio_thread_id_) PostThreadMessageW(audio_thread_id_, WM_QUIT, 0, 0);
    if (audio_thread_.joinable()) audio_thread_.join();
    if (out_device_) waveOutClose(out_device_);
    if (thread_ready_event_) CloseHandle(thread_ready_event_);
}

void S3C2410Iis::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);

    /* Init both WAVEHDR slots' buffers up front. The buffer base
       never changes; each Reset only zeroes the WAVEHDR fields. */
    out_headers_[0].lpData = reinterpret_cast<LPSTR>(&out_buffer_[0]);
    out_headers_[1].lpData = reinterpret_cast<LPSTR>(&out_buffer_[kBufferBytes]);
    curr_out_header_ = &out_headers_[0];

    thread_ready_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    audio_thread_ = std::thread([this] { AudioThreadMain(); });
    WaitForSingleObject(thread_ready_event_, INFINITE);
}

void S3C2410Iis::AudioThreadMain() {
    audio_thread_id_ = GetCurrentThreadId();

    /* Force-create the message queue so PostThreadMessage from
       waveOut callbacks (and from QueueOutput) lands before our
       GetMessage call. */
    MSG msg;
    PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
    SetEvent(thread_ready_event_);

    /* Open the wave output device after the message queue exists.
       Format hardcoded to 44100/16/2 per BSP InitAudio — the
       on-chip IIS rate is computed from IISMOD+IISPSR but matches
       this in practice for WM5 system sounds. */
    WAVEFORMATEX fmt{};
    fmt.wFormatTag      = WAVE_FORMAT_PCM;
    fmt.nChannels       = kChannels;
    fmt.nSamplesPerSec  = kSampleRate;
    fmt.wBitsPerSample  = kBitsPerSamp;
    fmt.nBlockAlign     = (uint16_t)((fmt.wBitsPerSample / 8) * fmt.nChannels);
    fmt.nAvgBytesPerSec = fmt.nSamplesPerSec * fmt.nBlockAlign;
    fmt.cbSize          = 0;

    const MMRESULT r = waveOutOpen(&out_device_, WAVE_MAPPER, &fmt,
                                   audio_thread_id_, 0,
                                   CALLBACK_THREAD | WAVE_FORMAT_DIRECT);
    if (r != MMSYSERR_NOERROR) {
        LOG(Caution, "S3C2410Iis: waveOutOpen failed (mmresult=%u) — "
                "silent-mode boot (IRQ delivery still works)\n", r);
        out_device_ = nullptr;
    }

    while (!shutdown_.load(std::memory_order_acquire) &&
           GetMessageW(&msg, nullptr, 0, 0) > 0) {
        if (msg.message == kMsgOutDmaEnable) {
            output_dma_enabled_.store(true, std::memory_order_release);
            continue;
        }
        if (msg.message == MM_WOM_DONE) {
            auto* hdr = reinterpret_cast<LPWAVEHDR>(msg.lParam);
            if (msg.wParam != 0 && out_device_ != nullptr && hdr != nullptr) {
                waveOutUnprepareHeader(out_device_, hdr, sizeof(WAVEHDR));
            }
            const bool manual_post = (msg.wParam == 0);
            const bool switching   = switch_out_queue_.load(std::memory_order_acquire);
            if (output_dma_enabled_.load(std::memory_order_acquire) &&
                (manual_post || switching)) {
                emu_.Get<IrqController>().AssertIrq(kIrqDma2);
            }
        }
    }
}

bool S3C2410Iis::QueueSwitchPossible() const {
    const WAVEHDR* other = (curr_out_header_ == &out_headers_[0])
                           ? &out_headers_[1] : &out_headers_[0];
    return (other->dwFlags & WHDR_PREPARED) == 0;
}

void S3C2410Iis::SwitchQueue() {
    if (QueueSwitchPossible()) {
        curr_out_header_ = (curr_out_header_ == &out_headers_[0])
                           ? &out_headers_[1] : &out_headers_[0];
        ResetCurrentQueue();
    } else {
        switch_out_queue_.store(true, std::memory_order_release);
        curr_out_header_ = (curr_out_header_ == &out_headers_[0])
                           ? &out_headers_[1] : &out_headers_[0];
    }
}

void S3C2410Iis::ResetCurrentQueue() {
    /* BSP zeroes everything except dwUser. We don't use dwUser; just
       zero everything and re-pin lpData. */
    WAVEHDR* hdr   = curr_out_header_;
    uint8_t* buf   = (hdr == &out_headers_[0]) ? &out_buffer_[0]
                                               : &out_buffer_[kBufferBytes];
    std::memset(hdr, 0, sizeof(*hdr));
    hdr->lpData = reinterpret_cast<LPSTR>(buf);
}

void S3C2410Iis::PlayCurrentQueue() {
    if (!out_device_) return;
    MMRESULT r = waveOutPrepareHeader(out_device_, curr_out_header_,
                                      sizeof(WAVEHDR));
    if (r != MMSYSERR_NOERROR) {
        LOG(Caution, "S3C2410Iis: waveOutPrepareHeader failed (%u)\n", r);
        return;
    }
    r = waveOutWrite(out_device_, curr_out_header_, sizeof(WAVEHDR));
    if (r != MMSYSERR_NOERROR) {
        LOG(Caution, "S3C2410Iis: waveOutWrite failed (%u)\n", r);
        waveOutUnprepareHeader(out_device_, curr_out_header_, sizeof(WAVEHDR));
    }
}

void S3C2410Iis::QueueOutput(const void* host_bytes, size_t length) {
    if (length != kBlockSize) {
        LOG(Caution, "S3C2410Iis::QueueOutput: length %zu != BLOCK_SIZE "
                "%u — BSP requires single-block writes\n",
                length, kBlockSize);
        return;
    }

    bool post_done = false;
    LPWAVEHDR done_hdr = nullptr;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        WAVEHDR* hdr = curr_out_header_;

        if (out_device_ != nullptr) {
            if (switch_out_queue_.load(std::memory_order_acquire)) {
                if ((hdr->dwFlags & WHDR_PREPARED) == 0) {
                    ResetCurrentQueue();
                    switch_out_queue_.store(false, std::memory_order_release);
                } else {
                    /* Drop the packet — CE got ahead of us, matches
                       BSP's "we drop the packet" branch. */
                    LOG(Periph, "[IIS] dropping audio packet — CE "
                            "outran host audio\n");
                    return;
                }
            }
            std::memcpy(reinterpret_cast<char*>(hdr->lpData) + hdr->dwBufferLength,
                        host_bytes, kBlockSize);
            hdr->dwBufferLength += kBlockSize;

            if (hdr->dwBufferLength == kBufferBytes) {
                PlayCurrentQueue();
                SwitchQueue();
            }

            if (!switch_out_queue_.load(std::memory_order_acquire)) {
                post_done = true;
                done_hdr  = hdr;
            }
        } else {
            /* Silent mode: still post MM_WOM_DONE so wavedev's ISR
               progresses — BSP same branch. */
            post_done = true;
            done_hdr  = hdr;
        }
    }

    if (post_done && audio_thread_id_) {
        PostThreadMessageW(audio_thread_id_, MM_WOM_DONE, 0,
                           reinterpret_cast<LPARAM>(done_hdr));
    }
}

void S3C2410Iis::SetOutputDMA(bool on) {
    if (on) {
        if (audio_thread_id_) {
            PostThreadMessageW(audio_thread_id_, kMsgOutDmaEnable, 0, 0);
        }
    } else {
        output_dma_enabled_.store(false, std::memory_order_release);
    }
}

uint32_t S3C2410Iis::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t value = 0;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        switch (off) {
            case kRegIISCON:
                /* FIFO-ready bits synthesised per BSP read path so
                   driver polling loops don't hang. */
                value = iiscon_ | kIisconTxFifoReady | kIisconRxFifoReady;
                break;
            case kRegIISMOD:  value = iismod_;  break;
            case kRegIISPSR:  value = iispsr_;  break;
            case kRegIISFCON: value = iisfcon_; break;
            case kRegIISFIFO: value = iisfifo_; break;
            default:
                HaltUnsupportedAccess("ReadWord", addr, 0);  /* noreturn */
        }
    }
    return value;
}

void S3C2410Iis::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    std::lock_guard<std::mutex> lk(state_mutex_);
    switch (off) {
        case kRegIISCON:  iiscon_  = value; break;
        case kRegIISMOD:  iismod_  = value; break;
        case kRegIISPSR:  iispsr_  = value; break;
        case kRegIISFCON: iisfcon_ = value; break;
        case kRegIISFIFO: iisfifo_ = value; break;
        default:
            HaltUnsupportedAccess("WriteWord", addr, value);  /* noreturn */
    }
}
