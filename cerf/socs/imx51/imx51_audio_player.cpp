#define NOMINMAX

#include "imx51_audio_player.h"

#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/audio_activity_widget.h"
#include "../../state/emulation_freeze.h"
#include "imx51_ssi1.h"
#include "imx51_ssi2.h"
#include "imx51_ssi3.h"

#include <cstring>

namespace {

constexpr UINT kMsgStart = WM_USER + 0x32u;
constexpr UINT kMsgStop  = WM_USER + 0x33u;

/* MCIMX51RM Table 3-3 (SDMA Event Mapping), confirmed against the guest's own
   OpenChan prints: SSI1 TX=29/27, SSI2 TX=25/23, SSI3 TX=47/37. */
bool TxEventToSsi(int event, uint32_t& ssi) {
    switch (event) {
        case 29: case 27: ssi = 1u; return true;
        case 25: case 23: ssi = 2u; return true;
        case 47: case 37: ssi = 3u; return true;
    }
    return false;
}

constexpr uint32_t kBdDone = 1u << 16;
constexpr uint32_t kBdWrap = 1u << 17;

/* ford_sync_2 wavedev2_cs42448.dll FUN_c1676630 builds one shared
   WAVEFORMATEX-style object via FUN_c1670fc0 -> FUN_c1670e44(this, 2, 48000,
   16) and passes it into all six SSI channel constructors (FUN_c16744f8,
   dir x ssi_idx) - every channel this driver opens is 48 kHz stereo 16-bit. */
constexpr uint32_t kNativeRateHz = 48000u;

}  /* namespace */

bool Imx51AudioPlayer::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Imx51;
}

void Imx51AudioPlayer::OnReady() {
    sink_.Start(nullptr,
                [this](const MSG& m) { OnThreadMessage(m); },
                "iMX51-Audio");
    emu_.Get<Imx51Sdma>().RegisterChannelSink(
        [this](const Imx51Sdma::ChannelStart& s) { return OnChannelClaim(s); },
        [this](uint32_t ch) { OnChannelStop(ch); });
    emu_.Get<AudioActivityWidget>().NotePresent();
}

void Imx51AudioPlayer::OnShutdown() {
    sink_.Stop();
}

bool Imx51AudioPlayer::OnChannelClaim(const Imx51Sdma::ChannelStart& s) {
    uint32_t ssi = 0;
    if (!TxEventToSsi(s.event, ssi)) return false;

    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (active_ && channel_ == s.channel) return true;
    }

    /* Walk the BD ring the guest armed; W marks its last descriptor
       (MCIMX51RM Table 52-96). */
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

    {
        std::lock_guard<std::mutex> lk(mtx_);
        channel_ = s.channel;
        ssi_     = ssi;
        rate_hz_ = kNativeRateHz;
        bd_pas_  = bds;
        next_bd_ = 0u;
        active_  = true;
    }
    LOG(Periph, "[iMX51-Audio] claim SSI%u stream (ch%u ev=%d bds=%u rate=%u Hz)\n",
        ssi, s.channel, s.event, static_cast<uint32_t>(bds.size()), kNativeRateHz);
    sink_.Post(kMsgStart);
    return true;
}

void Imx51AudioPlayer::OnChannelStop(uint32_t channel) {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (channel != channel_ || !active_) return;
        active_ = false;
    }
    sink_.Post(kMsgStop);
}

void Imx51AudioPlayer::OnThreadMessage(const MSG& msg) {
    switch (msg.message) {
    case kMsgStart:   StartStream(); break;
    case kMsgStop:    StopStream();  break;
    case MM_WOM_DONE: OnPageDone(reinterpret_cast<WAVEHDR*>(msg.lParam)); break;
    default: break;
    }
}

void Imx51AudioPlayer::StartStream() {
    uint32_t rate;
    { std::lock_guard<std::mutex> lk(mtx_); rate = rate_hz_; }
    for (auto& s : slots_) s.in_flight = false;
    sink_.EnsureFormat(rate, 2, 16, /*allow_resampler=*/true, /*busy=*/false);
    for (int i = 0; i < kSlots; ++i) {
        if (!QueuePage()) break;
    }
}

void Imx51AudioPlayer::StopStream() {
    sink_.Reset();
    for (auto& s : slots_) s.in_flight = false;
}

Imx51AudioPlayer::Slot* Imx51AudioPlayer::AllocSlot() {
    for (auto& s : slots_) if (!s.in_flight) return &s;
    return nullptr;
}

bool Imx51AudioPlayer::QueuePage() {
    Slot* slot = AllocSlot();
    if (!slot) return false;

    uint32_t bd_pa;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!active_ || bd_pas_.empty()) return false;
        bd_pa = bd_pas_[next_bd_];
        next_bd_ = (next_bd_ + 1u) % static_cast<uint32_t>(bd_pas_.size());
    }

    uint32_t count = 0, buf_pa = 0, ssi = 0;
    bool owned = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        ssi = ssi_;
    }
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
            if      (ssi == 1u) emu_.Get<Imx51Ssi1>().NoteTxUnderrun();
            else if (ssi == 2u) emu_.Get<Imx51Ssi2>().NoteTxUnderrun();
            else if (ssi == 3u) emu_.Get<Imx51Ssi3>().NoteTxUnderrun();
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

void Imx51AudioPlayer::OnPageDone(WAVEHDR* hdr) {
    if (!hdr) return;
    Slot* slot = reinterpret_cast<Slot*>(hdr->dwUser);
    sink_.Unprepare(&slot->hdr);
    slot->in_flight = false;

    uint32_t ch;
    bool active;
    { std::lock_guard<std::mutex> lk(mtx_); active = active_; ch = channel_; }
    if (!active) return;

    if (slot->retire) {
        auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
        emu_.Get<Imx51Sdma>().SignalChannelBdDone(ch, slot->bd_pa);
    }
    QueuePage();
}

REGISTER_SERVICE(Imx51AudioPlayer);
