#define NOMINMAX

#include "omap3530_audio_player.h"

#include "../../boards/board_context.h"
#include "omap3530_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/audio_activity_widget.h"
#include "../../state/emulation_freeze.h"
#include "twl4030.h"

#include <cstring>

namespace {
constexpr UINT    kMsgStart     = WM_USER + 0x20u;
constexpr UINT    kMsgStop      = WM_USER + 0x21u;
constexpr uint8_t kCodecModeSub = 0x01u;   /* TWL_CODEC_MODE = 0x00490001. */
}  /* namespace */

bool Omap3530AudioPlayer::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Omap3530;
}

void Omap3530AudioPlayer::OnReady() {
    sink_.Start(nullptr,
                [this](const MSG& m) { OnThreadMessage(m); },
                "OMAP3530-Audio");
    emu_.Get<Omap3530Sdma>().RegisterChannelSink(
        [this](const Omap3530SdmaBase::ChannelStart& s) { return OnChannelClaim(s); },
        [this](int ch) { OnChannelStop(ch); });
    emu_.Get<AudioActivityWidget>().NotePresent();
}

void Omap3530AudioPlayer::OnShutdown() {
    sink_.Stop();
}

bool Omap3530AudioPlayer::OnChannelClaim(const Omap3530SdmaBase::ChannelStart& s) {
    if (s.sync_source != kMcbsp2TxSync || s.dst_pa != kMcbsp2DxrPa) return false;
    if (s.elem_count == 0u || s.frame_count == 0u || s.element_size == 0u) return false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        channel_    = s.channel;
        src_pa_     = s.src_pa;
        page_bytes_ = s.elem_count * s.element_size;
        page_count_ = s.frame_count;
        active_     = true;
    }
    LOG(Periph, "[OMAP3530-Audio] claim ch%d src=0x%08X page=%u x%u es=%u\n",
        s.channel, s.src_pa, s.elem_count * s.element_size, s.frame_count,
        s.element_size);
    /* Output is fixed 16-bit interleaved stereo. That byte layout matches an
       I2S S16 element and the EVM's S32 word packing [L:16][R:16] (McBSP2
       XCR1=0xA0 => 32-bit single-phase word); element sizes other than 2 or 4
       carry a layout the 16-bit mapping cannot represent. */
    if (s.element_size != 2u && s.element_size != 4u) {
        LOG(Caution, "[OMAP3530-Audio] element size %u not 2/4; 16-bit stereo "
            "output will be wrong for this format\n", s.element_size);
    }
    sink_.Post(kMsgStart);
    return true;
}

void Omap3530AudioPlayer::OnChannelStop(int channel) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (channel != channel_) return;
        active_ = false;
    }
    sink_.Post(kMsgStop);
}

void Omap3530AudioPlayer::OnThreadMessage(const MSG& msg) {
    switch (msg.message) {
    case kMsgStart:   StartStream(); break;
    case kMsgStop:    StopStream();  break;
    case MM_WOM_DONE: OnPageDone(reinterpret_cast<WAVEHDR*>(msg.lParam)); break;
    default: break;
    }
}

void Omap3530AudioPlayer::StartStream() {
    uint32_t pages;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        seq_  = 0;
        pages = page_count_;
    }
    for (auto& s : slots_) s.in_flight = false;
    sink_.EnsureFormat(SampleRateHz(), 2, 16, /*allow_resampler=*/true, /*busy=*/false);

    const uint32_t prime = pages < static_cast<uint32_t>(kSlots)
                               ? pages : static_cast<uint32_t>(kSlots);
    for (uint32_t i = 0; i < prime; ++i) {
        if (!QueuePage()) break;
    }
}

void Omap3530AudioPlayer::StopStream() {
    sink_.Reset();
    for (auto& s : slots_) s.in_flight = false;
}

Omap3530AudioPlayer::Slot* Omap3530AudioPlayer::AllocSlot() {
    for (auto& s : slots_) if (!s.in_flight) return &s;
    return nullptr;
}

bool Omap3530AudioPlayer::QueuePage() {
    Slot* slot = AllocSlot();
    if (!slot) return false;

    uint32_t src, pb, pc, seq;
    int      ch;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!active_ || page_count_ == 0u) return false;
        src = src_pa_; pb = page_bytes_; pc = page_count_;
        ch  = channel_; seq = seq_++;
    }

    const uint32_t phys_page = seq % pc;
    const uint32_t page_pa   = src + phys_page * pb;
    const bool     block     = (phys_page == pc - 1u);
    const uint32_t csac      = src + ((phys_page + 1u) % pc) * pb;
    slot->bytes.resize(pb);

    {
        auto  frozen = emu_.Get<EmulationFreeze>().WorkerSection();
        auto& mem    = emu_.Get<EmulatedMemory>();
        if (uint8_t* host = mem.TryTranslate(page_pa)) {
            std::memcpy(slot->bytes.data(), host, pb);
        } else {
            for (uint32_t i = 0; i < pb; ++i) slot->bytes[i] = mem.ReadByte(page_pa + i);
        }
        /* The DMA reads this frame into the McBSP FIFO now: advance CSAC past it to
           the next page and raise the frame interrupt (BLOCK|LAST at the last page
           of the circular block). The driver then refills this page for the round
           after next, which is why the snapshot above is already up to date. */
        emu_.Get<Omap3530Sdma>().SignalChannelFrame(ch, block, csac);
    }

    slot->seq = seq;
    std::memset(&slot->hdr, 0, sizeof(slot->hdr));
    slot->hdr.lpData         = reinterpret_cast<LPSTR>(slot->bytes.data());
    slot->hdr.dwBufferLength = pb;
    slot->hdr.dwUser         = reinterpret_cast<DWORD_PTR>(slot);
    slot->in_flight          = true;

    sink_.Play(&slot->hdr);
    emu_.Get<AudioActivityWidget>().MarkTx();
    return true;
}

void Omap3530AudioPlayer::OnPageDone(WAVEHDR* hdr) {
    if (!hdr) return;
    Slot* slot = reinterpret_cast<Slot*>(hdr->dwUser);
    sink_.Unprepare(&slot->hdr);
    slot->in_flight = false;

    bool active;
    { std::lock_guard<std::mutex> lk(mtx_); active = active_; }
    if (active) QueuePage();
}

uint32_t Omap3530AudioPlayer::SampleRateHz() const {
    auto* codec = emu_.TryGet<Twl4030>();
    const uint8_t mode = codec ? codec->AudioReg(kCodecModeSub) : 0u;
    switch ((mode >> 4) & 0xFu) {   /* CODEC_MODE.APLL_RATE - TPS65950 TRM. */
    case 0x0: return 8000;
    case 0x1: return 11025;
    case 0x2: return 12000;
    case 0x4: return 16000;
    case 0x5: return 22050;
    case 0x6: return 24000;
    case 0x8: return 32000;
    case 0x9: return 44100;
    case 0xA: return 48000;
    case 0xE: return 96000;
    default:  return 44100;
    }
}

REGISTER_SERVICE(Omap3530AudioPlayer);
