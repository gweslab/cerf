#define NOMINMAX

#include "imx31_audio_player.h"

#include "../../boards/board_context.h"
#include "imx31_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/audio_activity_widget.h"
#include "../../state/emulation_freeze.h"
#include "imx31_ccm.h"
#include "imx31_ssi2.h"

#include <cstring>

namespace {

constexpr UINT kMsgStart = WM_USER + 0x30u;
constexpr UINT kMsgStop  = WM_USER + 0x31u;

/* MCIMX31RM Table 2-5 (SDMA Events Summary): SSI2 transmit 2 = 23,
   SSI2 transmit 1 = 25. */
constexpr int kEvtSsi2Tx2 = 23;
constexpr int kEvtSsi2Tx1 = 25;

constexpr uint32_t kBdDone = 1u << 16;
constexpr uint32_t kBdWrap = 1u << 17;

}  /* namespace */

bool Imx31AudioPlayer::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Imx31;
}

void Imx31AudioPlayer::OnReady() {
    sink_.Start(nullptr,
                [this](const MSG& m) { OnThreadMessage(m); },
                "iMX31-Audio");
    emu_.Get<Imx31Sdma>().RegisterChannelSink(
        [this](const Imx31Sdma::ChannelStart& s) { return OnChannelClaim(s); },
        [this](uint32_t ch) { OnChannelStop(ch); });
    emu_.Get<AudioActivityWidget>().NotePresent();
}

void Imx31AudioPlayer::OnShutdown() {
    sink_.Stop();
}

uint32_t Imx31AudioPlayer::SsiForTxEvent(int event) {
    return (event == kEvtSsi2Tx1 || event == kEvtSsi2Tx2) ? 2u : 0u;
}

bool Imx31AudioPlayer::OnChannelClaim(const Imx31Sdma::ChannelStart& s) {
    const uint32_t ssi = SsiForTxEvent(s.event);
    if (ssi == 0u) return false;

    /* The guest re-arms the running channel every buffer; keep the stream and the
       ring cursor, or playback restarts mid-track. */
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (active_ && channel_ == s.channel) return true;
    }

    /* Walk the BD ring the guest armed; W marks its last descriptor
       (MCIMX51RM Table 52-96, same SDMA IP). */
    auto& mem = emu_.Get<EmulatedMemory>();
    std::vector<uint32_t> bds;
    uint32_t bd_pa = s.base_bd_pa;
    for (uint32_t i = 0; i < kMaxBds; ++i) {
        uint8_t* bd = mem.TryTranslateWrite(bd_pa);
        if (bd == nullptr) return false;
        const uint32_t w0 = *reinterpret_cast<uint32_t*>(bd);
        bds.push_back(bd_pa);
        if (w0 & kBdWrap) break;
        bd_pa += s.stride;
    }
    if (bds.empty()) return false;

    auto& ssi2 = emu_.Get<Imx31Ssi2>();
    const uint32_t clk  = emu_.Get<Imx31Ccm>().SsiClockHz(ssi);
    const uint32_t rate = ssi2.TxFrameRateHz(clk);
    if (rate == 0u) return false;

    {
        std::lock_guard<std::mutex> lk(mtx_);
        channel_  = s.channel;
        ssi_      = ssi;
        rate_hz_  = rate;
        bd_pas_   = bds;
        next_bd_  = 0;
        active_   = true;
    }
    LOG(Periph, "[iMX31-Audio] claim ch%u ev=%d bds=%u ssi%u_clk=%u Hz rate=%u Hz "
        "%ux%u-bit\n", s.channel, s.event, static_cast<uint32_t>(bds.size()), ssi,
        clk, rate, ssi2.TxWordsPerFrame(), ssi2.TxWordLengthBits());
    sink_.Post(kMsgStart);
    return true;
}

void Imx31AudioPlayer::OnChannelStop(uint32_t channel) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (channel != channel_ || !active_) return;
        active_ = false;
    }
    sink_.Post(kMsgStop);
}

void Imx31AudioPlayer::OnThreadMessage(const MSG& msg) {
    switch (msg.message) {
    case kMsgStart:   StartStream(); break;
    case kMsgStop:    StopStream();  break;
    case MM_WOM_DONE: OnPageDone(reinterpret_cast<WAVEHDR*>(msg.lParam)); break;
    default: break;
    }
}

void Imx31AudioPlayer::StartStream() {
    uint32_t rate;
    { std::lock_guard<std::mutex> lk(mtx_); rate = rate_hz_; }
    for (auto& s : slots_) s.in_flight = false;
    sink_.EnsureFormat(rate, 2, 16, /*allow_resampler=*/true, /*busy=*/false);
    for (int i = 0; i < kSlots; ++i) {
        if (!QueuePage()) break;
    }
}

void Imx31AudioPlayer::StopStream() {
    sink_.Reset();
    for (auto& s : slots_) s.in_flight = false;
}

Imx31AudioPlayer::Slot* Imx31AudioPlayer::AllocSlot() {
    for (auto& s : slots_) if (!s.in_flight) return &s;
    return nullptr;
}

bool Imx31AudioPlayer::QueuePage() {
    Slot* slot = AllocSlot();
    if (!slot) return false;

    uint32_t bd_pa;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!active_ || bd_pas_.empty()) return false;
        bd_pa = bd_pas_[next_bd_];
        next_bd_ = (next_bd_ + 1u) % static_cast<uint32_t>(bd_pas_.size());
    }

    uint32_t count = 0, buf_pa = 0;
    bool owned = false;
    {
        auto  frozen = emu_.Get<EmulationFreeze>().WorkerSection();
        auto& mem    = emu_.Get<EmulatedMemory>();
        uint8_t* bd  = mem.TryTranslateWrite(bd_pa);
        if (bd == nullptr) return false;
        const uint32_t* word = reinterpret_cast<uint32_t*>(bd);
        owned  = (*word & kBdDone) != 0;
        count  = *word & 0xFFFFu;
        buf_pa = word[1];

        if (owned && count != 0) {
            slot->bytes.resize(count);
            if (uint8_t* host = mem.TryTranslate(buf_pa)) {
                std::memcpy(slot->bytes.data(), host, count);
            } else {
                for (uint32_t i = 0; i < count; ++i)
                    slot->bytes[i] = mem.ReadByte(buf_pa + i);
            }
        } else {
            /* The AP owns this descriptor: the transmitter has no data for the
               frame, which is a TX underrun on the wire, not silence upstream. */
            emu_.Get<Imx31Ssi2>().NoteTxUnderrun();
            slot->bytes.assign(count ? count : 4096u, 0u);
        }
    }

    slot->bd_pa  = bd_pa;
    slot->retire = owned && count != 0;
    std::memset(&slot->hdr, 0, sizeof(slot->hdr));
    slot->hdr.lpData         = reinterpret_cast<LPSTR>(slot->bytes.data());
    slot->hdr.dwBufferLength = static_cast<DWORD>(slot->bytes.size());
    slot->hdr.dwUser         = reinterpret_cast<DWORD_PTR>(slot);
    slot->in_flight          = true;

    sink_.Play(&slot->hdr);
    if (slot->retire) emu_.Get<AudioActivityWidget>().MarkTx();
    return true;
}

void Imx31AudioPlayer::OnPageDone(WAVEHDR* hdr) {
    if (!hdr) return;
    Slot* slot = reinterpret_cast<Slot*>(hdr->dwUser);
    sink_.Unprepare(&slot->hdr);
    slot->in_flight = false;

    uint32_t ch;
    bool active;
    { std::lock_guard<std::mutex> lk(mtx_); active = active_; ch = channel_; }
    if (!active) return;

    /* The page has now been transmitted: hand the descriptor back to the AP and
       raise its completion interrupt, which paces the guest's refill to playback. */
    if (slot->retire) {
        auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
        emu_.Get<Imx31Sdma>().SignalChannelBdDone(ch, slot->bd_pa);
    }
    QueuePage();
}

REGISTER_SERVICE(Imx31AudioPlayer);
