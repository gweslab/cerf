#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../cpu/physical_bus.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"
#include "audio_out_sink.h"
#include "pxa255_ac97.h"
#include "pxa255_i2s.h"
#include "../irq_controller.h"

#include <cstdint>
#include <functional>
#include <mutex>

namespace {

/* Intel PXA255 DMA Controller (dev manual 278693-002 Ch.5, base 0x40000000).
   A channel whose descriptor targets the AC'97 PCM-out FIFO is handed to
   Pxa255Ac97 to pace each buffer-complete IRQ via AudioTick - blasting that
   ring synchronously deadlocks the guest audio thread and the UI. */
class Pxa255Dma : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return 0x40000000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint8_t ReadByte(uint32_t addr) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        return static_cast<uint8_t>(ReadRegLocked(addr & ~0x3u) >> ((addr & 0x3u) * 8u));
    }
    uint32_t ReadWord(uint32_t addr) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        return ReadRegLocked(addr);
    }
    void WriteByte(uint32_t addr, uint8_t value) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const uint32_t base = addr & ~0x3u, shift = (addr & 0x3u) * 8u;
        WriteRegLocked(base, (ReadRegLocked(base) & ~(0xFFu << shift))
                             | (static_cast<uint32_t>(value) << shift));
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        WriteRegLocked(addr, value);
    }

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        w.WriteBytes(dcsr_,  sizeof(dcsr_));
        w.WriteBytes(ddadr_, sizeof(ddadr_));
        w.WriteBytes(dsadr_, sizeof(dsadr_));
        w.WriteBytes(dtadr_, sizeof(dtadr_));
        w.WriteBytes(dcmd_,  sizeof(dcmd_));
        w.WriteBytes(drcmr_, sizeof(drcmr_));
        w.WriteBytes(audio_active_, sizeof(audio_active_));
        w.WriteBytes(touch_active_, sizeof(touch_active_));
    }

    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        r.ReadBytes(dcsr_,  sizeof(dcsr_));
        r.ReadBytes(ddadr_, sizeof(ddadr_));
        r.ReadBytes(dsadr_, sizeof(dsadr_));
        r.ReadBytes(dtadr_, sizeof(dtadr_));
        r.ReadBytes(dcmd_,  sizeof(dcmd_));
        r.ReadBytes(drcmr_, sizeof(drcmr_));
        r.ReadBytes(audio_active_, sizeof(audio_active_));
        r.ReadBytes(touch_active_, sizeof(touch_active_));
        for (uint32_t ch = 0; ch < kNumChannels; ++ch) {
            audio_active_[ch] = false;
            touch_active_[ch] = false;
            audio_sink_[ch]   = nullptr;
        }
    }

    void PostRestore() override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        for (uint32_t ch = 0; ch < kNumChannels; ++ch)
            if (dcsr_[ch] & RUN) StartChannelLocked(ch);
        UpdateIrqLocked();
    }

private:
    /* DCSRx bit fields (Table 5-7). */
    static constexpr uint32_t RUN = 1u << 31, NODESCFETCH = 1u << 30,
                              STOPIRQEN = 1u << 29, REQPEND = 1u << 8,
                              STOPSTATE = 1u << 3, ENDINTR = 1u << 2,
                              STARTINTR = 1u << 1, BUSERRINTR = 1u << 0;
    /* DCMDx bit fields (Table 5-12). */
    static constexpr uint32_t INCSRCADDR = 1u << 31, INCTRGADDR = 1u << 30,
                              STARTIRQEN = 1u << 22, ENDIRQEN = 1u << 21;
    static constexpr uint32_t kDcmdWidthShift = 14, kDcmdWidthMask = 0x3u;
    static constexpr uint32_t kDcmdLengthMask = 0x1FFFu;   /* [12:0], max 8K-1. */
    static constexpr uint32_t DDADR_STOP = 1u << 0;        /* end-of-chain sentinel. */
    static constexpr uint32_t kIntcDmaBit = 25u;           /* manual p.5-3. */
    static constexpr uint32_t kNumChannels = 16, kNumDrcmr = 40;
    static constexpr uint32_t kMaxDescriptors = 4096;      /* runaway-chain backstop. */
    static constexpr uint32_t kAc97Base = 0x40500000u, kAc97End = 0x40501000u;
    /* Modem-in FIFO data register: a channel sourcing from here carries WM9705
       touch slot-5 samples (Linux pxa2xx-ac97-regs.h MODR). */
    static constexpr uint32_t kAc97Modr = 0x40500140u;
    static constexpr uint32_t kI2sSadr  = 0x40400080u;  /* I2S Tx data reg (SADR, Ch.14). */

    std::mutex state_mutex_;   /* channel state is touched by the JIT thread (reg
                                  access) and the AC'97 audio thread (AudioTick). */
    uint32_t dcsr_[kNumChannels] = {}, ddadr_[kNumChannels] = {},
             dsadr_[kNumChannels] = {}, dtadr_[kNumChannels] = {},
             dcmd_[kNumChannels] = {}, drcmr_[kNumDrcmr] = {};
    bool          audio_active_[kNumChannels] = {};
    bool          touch_active_[kNumChannels] = {};
    AudioOutSink* audio_sink_[kNumChannels]   = {};   /* sink for an active audio-out channel. */

    uint32_t ReadRegLocked(uint32_t addr) {
        const uint32_t off = addr - MmioBase();
        if (off < 0x40u) return dcsr_[off / 4u];
        if (off == 0xF0u) return Dint();
        if (off >= 0x100u && off < 0x1A0u) return drcmr_[(off - 0x100u) / 4u];
        if (off >= 0x200u && off < 0x300u) {
            const uint32_t ch = (off - 0x200u) / 0x10u;
            switch (off & 0xFu) {
                case 0x0u: return ddadr_[ch];
                case 0x4u: return dsadr_[ch];
                case 0x8u: return dtadr_[ch];
                case 0xCu: return dcmd_[ch];
            }
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteRegLocked(uint32_t addr, uint32_t value) {
        const uint32_t off = addr - MmioBase();
        if (off < 0x40u) { WriteDcsrLocked(off / 4u, value); return; }
        if (off == 0xF0u) return;   /* DINT is read-only (status aggregate). */
        if (off >= 0x100u && off < 0x1A0u) {
            const uint32_t idx = (off - 0x100u) / 4u;
            drcmr_[idx] = value;
            LOG(SocDma, "DRCMR%u <= 0x%08X (mapvld=%u ch=%u)\n", idx, value,
                (value >> 7) & 1u, value & 0x1Fu);
            return;
        }
        if (off >= 0x200u && off < 0x300u) {
            const uint32_t ch = (off - 0x200u) / 0x10u;
            switch (off & 0xFu) {
                case 0x0u: ddadr_[ch] = value; return;
                case 0x4u: dsadr_[ch] = value; return;
                case 0x8u: dtadr_[ch] = value; return;
                case 0xCu: dcmd_[ch]  = value; return;
            }
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    void WriteDcsrLocked(uint32_t ch, uint32_t value) {
        uint32_t cur = dcsr_[ch];
        cur &= ~(value & (BUSERRINTR | STARTINTR | ENDINTR));   /* W1C status bits. */
        const uint32_t rw = RUN | NODESCFETCH | STOPIRQEN;
        const bool was_run = (dcsr_[ch] & RUN) != 0;
        cur = (cur & ~rw) | (value & rw);
        const bool now_run = (cur & RUN) != 0;
        dcsr_[ch] = cur;
        if (!was_run && now_run)                         StartChannelLocked(ch);
        else if (was_run && !now_run && audio_active_[ch]) StopAudioLocked(ch);
        else if (was_run && !now_run && touch_active_[ch]) StopTouchLocked(ch);
        UpdateIrqLocked();
    }

    uint32_t Dint() const {
        uint32_t d = 0;
        for (uint32_t ch = 0; ch < kNumChannels; ++ch)
            if (ChannelIrq(ch)) d |= (1u << ch);
        return d;
    }
    bool ChannelIrq(uint32_t ch) const {
        const uint32_t d = dcsr_[ch];
        if (d & (BUSERRINTR | STARTINTR | ENDINTR)) return true;
        return (d & STOPSTATE) && (d & STOPIRQEN);
    }
    void UpdateIrqLocked() {
        bool any = false;
        for (uint32_t ch = 0; ch < kNumChannels && !any; ++ch) any = ChannelIrq(ch);
        auto& intc = emu_.Get<IrqController>();
        if (any) intc.AssertIrq  (static_cast<int>(kIntcDmaBit));
        else     intc.DeAssertIrq(static_cast<int>(kIntcDmaBit));
    }

    static bool IsAc97Target(uint32_t pa) { return pa >= kAc97Base && pa < kAc97End; }

    /* Paced audio-out sink for a channel whose first descriptor targets an audio Tx
       FIFO (AC'97 PCM-out or I2S SADR); null for a non-audio channel. */
    AudioOutSink* AudioSinkForChannelLocked(uint32_t ch) {
        if (dcsr_[ch] & NODESCFETCH) return nullptr;
        if (ddadr_[ch] & DDADR_STOP) return nullptr;
        uint32_t dtadr = 0;
        if (!ReadPhys32((ddadr_[ch] & ~0xFu) + 8u, &dtadr)) return nullptr;
        if (IsAc97Target(dtadr)) return &emu_.Get<Pxa255Ac97>();
        if (dtadr == kI2sSadr)   return &emu_.Get<Pxa255I2s>();
        return nullptr;
    }

    /* True iff the channel's first descriptor sources from the modem-in FIFO
       (MODR) - the WM9705 touch slot-5 stream. */
    bool PeekTouchInLocked(uint32_t ch) {
        if (dcsr_[ch] & NODESCFETCH) return false;
        if (ddadr_[ch] & DDADR_STOP) return false;
        uint32_t dsadr = 0;
        if (!ReadPhys32((ddadr_[ch] & ~0xFu) + 4u, &dsadr)) return false;
        return dsadr == kAc97Modr;
    }

    void StartChannelLocked(uint32_t ch) {
        dcsr_[ch] &= ~STOPSTATE;
        LOG(SocDma, "ch%u RUN DDADR=0x%08X DCSR=0x%08X nodesc=%u\n", ch, ddadr_[ch],
            dcsr_[ch], (dcsr_[ch] & NODESCFETCH) ? 1u : 0u);
        if (AudioOutSink* sink = AudioSinkForChannelLocked(ch)) {
            audio_active_[ch] = true;
            audio_sink_[ch]   = sink;
            sink->BeginAudioOut([this, ch] { AudioTick(ch); });
            LOG(SocDma, "ch%u -> paced audio-out\n", ch);
            if (!DeliverNextAudioBlockLocked(ch)) StopAudioLocked(ch);
            return;
        }
        if (PeekTouchInLocked(ch)) {
            touch_active_[ch] = true;
            emu_.Get<Pxa255Ac97>().BeginTouchCapture([this, ch] { TouchTick(ch); });
            LOG(SocDma, "ch%u -> AC'97 touch-in (paced capture)\n", ch);
            return;   /* paced: each pushed pen sample delivers one descriptor. */
        }
        RunChannelSyncLocked(ch);
    }

    /* Fetch the current descriptor and hand its source buffer to the AC'97 for
       playback; advance the ring. Returns false at end-of-chain / bad address. */
    bool DeliverNextAudioBlockLocked(uint32_t ch) {
        if (!(dcsr_[ch] & RUN) || (ddadr_[ch] & DDADR_STOP)) return false;
        const uint32_t desc = ddadr_[ch] & ~0xFu;
        uint32_t next = 0;
        if (!ReadPhys32(desc, &next) || !ReadPhys32(desc + 4u, &dsadr_[ch]) ||
            !ReadPhys32(desc + 8u, &dtadr_[ch]) || !ReadPhys32(desc + 0xCu, &dcmd_[ch])) {
            dcsr_[ch] |= BUSERRINTR; return false;
        }
        ddadr_[ch] = next;
        if (dcmd_[ch] & STARTIRQEN) dcsr_[ch] |= STARTINTR;
        const uint32_t len  = dcmd_[ch] & kDcmdLengthMask;
        const uint8_t* src = emu_.Get<EmulatedMemory>().TryTranslate(dsadr_[ch]);
        if (!src) { dcsr_[ch] |= BUSERRINTR; return false; }
        audio_sink_[ch]->QueueOutput(src, len);
        return true;
    }

    /* Invoked by the AC'97 audio thread when a played buffer completes: raise
       the buffer-complete IRQ and pump the next block (paces the ring). */
    void AudioTick(uint32_t ch) {
        auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (!audio_active_[ch]) return;
        if (!(dcsr_[ch] & RUN)) { StopAudioLocked(ch); UpdateIrqLocked(); return; }
        if (dcmd_[ch] & ENDIRQEN) dcsr_[ch] |= ENDINTR;
        if (!DeliverNextAudioBlockLocked(ch)) StopAudioLocked(ch);
        UpdateIrqLocked();
    }

    void StopAudioLocked(uint32_t ch) {
        if (!audio_active_[ch]) return;
        audio_active_[ch] = false;
        dcsr_[ch] = (dcsr_[ch] & ~RUN) | STOPSTATE;
        if (audio_sink_[ch]) { audio_sink_[ch]->StopAudioOut(); audio_sink_[ch] = nullptr; }
        LOG(SocDma, "ch%u audio-out stop DCSR=0x%08X\n", ch, dcsr_[ch]);
    }

    /* touch.dll sub_18E2194 median-filters four entries across both touch ring
       buffers: draining fewer than the whole pushed burst leaves one buffer
       stale and the filter rejects a moving coordinate as an outlier, sticking
       touch at the old position. */
    void TouchTick(uint32_t ch) {
        auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (!touch_active_[ch]) return;
        if (!(dcsr_[ch] & RUN)) { StopTouchLocked(ch); UpdateIrqLocked(); return; }

        bool end_irq = false;
        for (uint32_t guard = 0; guard < 2u * kNumChannels; ++guard) {
            if (!(dcsr_[ch] & RUN) || (ddadr_[ch] & DDADR_STOP)) break;
            const uint32_t desc = ddadr_[ch] & ~0xFu;
            uint32_t next = 0, dsadr = 0, dtadr = 0, dcmd = 0;
            if (!ReadPhys32(desc, &next) || !ReadPhys32(desc + 4u, &dsadr) ||
                !ReadPhys32(desc + 8u, &dtadr) || !ReadPhys32(desc + 0xCu, &dcmd)) {
                dcsr_[ch] |= BUSERRINTR; break;
            }
            const uint32_t width = UnitWidth(dcmd);
            const uint32_t words = width ? ((dcmd & kDcmdLengthMask) / width) : 0u;
            if (words == 0u || emu_.Get<Pxa255Ac97>().TouchFifoCount() < words) break;
            dsadr_[ch] = dsadr; dtadr_[ch] = dtadr; dcmd_[ch] = dcmd;
            ddadr_[ch] = next;
            if (dcmd & STARTIRQEN) dcsr_[ch] |= STARTINTR;
            if (!RunTransfer(ch)) { dcsr_[ch] |= BUSERRINTR; break; }   /* reads MODR -> buffer. */
            dcmd_[ch] &= ~kDcmdLengthMask;
            if (dcmd & ENDIRQEN) end_irq = true;
        }
        if (end_irq) dcsr_[ch] |= ENDINTR;
        UpdateIrqLocked();
    }

    void StopTouchLocked(uint32_t ch) {
        if (!touch_active_[ch]) return;
        touch_active_[ch] = false;
        dcsr_[ch] = (dcsr_[ch] & ~RUN) | STOPSTATE;
        emu_.Get<Pxa255Ac97>().StopTouchCapture();
        LOG(SocDma, "ch%u AC'97 touch-in stop DCSR=0x%08X\n", ch, dcsr_[ch]);
    }

    void RunChannelSyncLocked(uint32_t ch) {
        uint32_t n = 0;
        for (; n < kMaxDescriptors; ++n) {
            if (!(dcsr_[ch] & RUN)) break;
            if (!(dcsr_[ch] & NODESCFETCH)) {
                if (ddadr_[ch] & DDADR_STOP) break;        /* end of chain. */
                const uint32_t desc = ddadr_[ch] & ~0xFu;
                uint32_t next = 0;
                if (!ReadPhys32(desc, &next) || !ReadPhys32(desc + 4u, &dsadr_[ch]) ||
                    !ReadPhys32(desc + 8u, &dtadr_[ch]) || !ReadPhys32(desc + 0xCu, &dcmd_[ch])) {
                    dcsr_[ch] |= BUSERRINTR; break;
                }
                ddadr_[ch] = next;
                if (dcmd_[ch] & STARTIRQEN) dcsr_[ch] |= STARTINTR;
            }
            if (!RunTransfer(ch)) { dcsr_[ch] |= BUSERRINTR; break; }
            dcmd_[ch] &= ~kDcmdLengthMask;                 /* LENGTH consumed. */
            if (dcmd_[ch] & ENDIRQEN) dcsr_[ch] |= ENDINTR;
            if (dcsr_[ch] & NODESCFETCH) break;            /* single transfer. */
        }
        if (n == kMaxDescriptors)
            LOG(Caution, "Pxa255Dma: ch%u chain exceeded %u descriptors (last DSADR=0x%08X "
                "DTADR=0x%08X DCMD=0x%08X DDADR=0x%08X) - stopping\n", ch, kMaxDescriptors,
                dsadr_[ch], dtadr_[ch], dcmd_[ch], ddadr_[ch]);
        dcsr_[ch] = (dcsr_[ch] & ~RUN) | STOPSTATE;
    }

    static uint32_t UnitWidth(uint32_t dcmd) {
        switch ((dcmd >> kDcmdWidthShift) & kDcmdWidthMask) {
            case 0x1u: return 1u;
            case 0x2u: return 2u;
            default:   return 4u;   /* 11 = word; 00 (mem-to-mem) -> word units. */
        }
    }

    bool RunTransfer(uint32_t ch) {
        const uint32_t len = dcmd_[ch] & kDcmdLengthMask;
        if (len == 0) return true;
        const uint32_t sa = dsadr_[ch], da = dtadr_[ch];
        const bool inc_s = (dcmd_[ch] & INCSRCADDR) != 0;
        const bool inc_t = (dcmd_[ch] & INCTRGADDR) != 0;
        const uint32_t w = UnitWidth(dcmd_[ch]);
        const BusWidth bw = (w == 1u) ? BusWidth::Byte
                          : (w == 2u) ? BusWidth::Half
                                      : BusWidth::Word;
        auto& bus = emu_.Get<PhysicalBus>();
        for (uint32_t off = 0; off < len; off += w) {
            const uint32_t s = inc_s ? sa + off : sa;
            const uint32_t t = inc_t ? da + off : da;
            uint32_t unit = 0;
            if (!bus.Read(s, bw, &unit) || !bus.Write(t, bw, unit)) return false;
        }
        return true;
    }

    bool ReadPhys32(uint32_t pa, uint32_t* out) {
        return emu_.Get<PhysicalBus>().Read(pa, BusWidth::Word, out);
    }
};

}  /* namespace */

REGISTER_SERVICE(Pxa255Dma);
