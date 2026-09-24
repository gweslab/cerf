#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "pr31x00_intc.h"
#include "pr31x00_sib_audio.h"
#include "pr31x00_sib_codec.h"

#include <cstdint>

namespace {

/* Philips PR31x00 Serial Interface Bus, TMPR3911/3912 ch.13. Subframe 0 carries a
   register command to an external codec; sound and telecom frames are separate. */
constexpr uint32_t kBase = 0x10C00060u;

constexpr uint32_t kOffCtl     = 0x14u;   /* $074 */
constexpr uint32_t kOffSndTx   = 0x18u;   /* $078 write-only, $078 reads SNDRXHOLD */
constexpr uint32_t kOffTelTx   = 0x1Cu;   /* $07C write-only, $07C reads TELRXHOLD */
constexpr uint32_t kOffSf0Aux  = 0x20u;   /* $080 */
constexpr uint32_t kOffSf1Aux  = 0x24u;   /* $084 */
constexpr uint32_t kOffSf0Stat = 0x28u;   /* $088 read-only */
constexpr uint32_t kOffDmaCtl  = 0x30u;   /* $090 */

/* SF0AUX (tx39sibreg.h:145-166): REGADDR[3:0]<30:27> WRITE<26> SNDVALID<17>
   TELVALID<16> REGDATA[15:0]<15:0>. */
constexpr uint32_t kSf0RegAddrShift = 27;
constexpr uint32_t kSf0RegAddrMask  = 0xFu;
constexpr uint32_t kSf0Write        = 1u << 26;
constexpr uint32_t kSf0SndValid     = 1u << 17;
constexpr uint32_t kSf0TelValid     = 1u << 16;
constexpr uint32_t kSf0RegDataMask  = 0xFFFFu;

constexpr uint32_t kCtlEnSib = 1u << 0;
constexpr uint32_t kCtlEnSf0 = 1u << 1;
constexpr uint32_t kCtlEnSnd = 1u << 4;

/* Interrupt Status 1 bit 8 SIBSF0INT and bit 7 SIBSF1INT (§8.3.1). */
constexpr uint32_t kSibSf0Int = 1u << 8;
constexpr uint32_t kSibSf1Int = 1u << 7;

/* SNDFSDIV[6:0]<14:8> (§13.6.6). */
constexpr uint32_t kCtlSndFsShift = 8;
constexpr uint32_t kCtlSndFsMask  = 0x7Fu;

/* SIBSCLK is fixed at 9.216 MHz (§13.3.4, Tables 13.3.1/13.3.2). */
constexpr uint32_t kSibSclkHz = 9216000u;

constexpr uint32_t kOffSize     = 0x00u;   /* $060 write-only */
constexpr uint32_t kOffSndRxSt  = 0x04u;   /* $064 write-only */
constexpr uint32_t kOffSndTxSt  = 0x08u;   /* $068 write-only */
constexpr uint32_t kOffTelRxSt  = 0x0Cu;   /* $06C write-only */
constexpr uint32_t kOffTelTxSt  = 0x10u;   /* $070 write-only */

/* SIB Size (§13.6.1): SNDSIZE[13:2]<29:18> TELSIZE[13:2]<13:2>; 31-30, 17-14 and
   1-0 reserved. The four Start registers (§13.6.2-§13.6.5) each carry a buffer's
   physical address in [31:2] and reserve 1-0. */
constexpr uint32_t kSizeReserved  = 0xC003C003u;
constexpr uint32_t kStartReserved = 0x00000003u;

/* Sound TX DMA buffer: SNDSIZE[13:2]<29:18> (§13.6.1), byte length (SNDSIZE+1)*4;
   SNDTXSTART[31:2] (§13.6.3). */
constexpr uint32_t kSizeSndShift   = 18;
constexpr uint32_t kSizeSndMask    = 0xFFFu;
constexpr uint32_t kSndTxStartMask = 0xFFFFFFFCu;

/* SIB Control (§13.6.6): SIBIRQ<31>(R) reports the SIBIRQ input pin, which the
   TC35143 drives active-high; ENSIB<0>, ENSF0<1>, ENSF1<2>, SIBLOOP<3>, ENSND<4>,
   ENTEL<5> and the two test bits all reset to 0, and the frame-rate fields reset
   undefined and feed no enabled subframe. */
constexpr uint32_t kCtlReset = 0;

constexpr uint32_t kCtlWritable = 0x7FFFFFFFu;   /* SIBIRQ<31> is read-only */
constexpr uint32_t kCtlSibIrq   = 1u << 31;      /* SIBIRQ input-pin level (§13.6.6) */

/* ENCNTTEST<30> and ENDMATEST<29> "should not be set" (§13.6.6). ENTEL<5> and
   SIBLOOP<3> start telecom or loopback traffic against the codec and the SIB DMA
   engine; ENSF1<2> opens subframe 1 onto a second codec. */
constexpr uint32_t kCtlTest    = 0x60000000u;
constexpr uint32_t kCtlRunning = 0x0000002Cu;   /* ENTEL<5>, SIBLOOP<3>, ENSF1<2> */

/* SIB DMA Control (§13.6.15): SNDBUFF1TIME<31> SNDDMALOOP<30> SNDDMAPTR[13:2]<29:18>(R)
   ENDMARXSND<17> ENDMATXSND<16> TELBUFF1TIME<15> TELDMALOOP<14> TELDMAPTR[13:2]<13:2>(R)
   ENDMARXTEL<1> ENDMATXTEL<0>. */
constexpr uint32_t kDmaEnTxSnd     = 1u << 16;   /* ENDMATXSND */
constexpr uint32_t kDmaCtlReadOnly = 0x3FFC3FFCu;
/* SNDDMALOOP<30> excluded from the armed set: §13.6.15 makes it only the full-duplex
   RX/TX DMA request ordering (RX-first vs TX-first), inert when just ENDMATXSND (TX)
   is armed, so wavedev's continuous TX sound DMA is accepted. Still armed (no modeled
   path): SNDBUFF1TIME<31> one-shot, ENDMARXSND<17> RX, telecom<15,14,1,0>. */
constexpr uint32_t kDmaCtlArmed    = 0x8002C003u;

class Pr31x00Sib : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd) return false;
        const std::string_view soc = bd->GetSocId();
        return soc == SocId::Pr31500 || soc == SocId::Pr31700;
    }

    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return 0x34u; }   /* $060-$093 */

    /* OEMIdle polls ENSIB<0> here before stopping the CPU (nino_300 nk.exe
       sub_9F411310 tests MEMORY[0xB0C00074] & 1 ahead of POWER_CTL STOPCPU), so
       this read must answer. SIBIRQ<31> reports the codec IRQ input pin, active-high
       (§13.6.6): reflect the modelled codec's pending interrupt. */
    uint32_t ReadWord(uint32_t addr) override {
        if (addr - kBase == kOffCtl) {
            uint32_t v = ctl_;
            auto* codec = emu_.TryGet<Pr31x00SibCodec>();
            if (codec && codec->IrqAsserted()) v |= kCtlSibIrq;
            return v;
        }
        /* SF0AUX holds the subframe-0 control word and is R/W (§13.6.11); serial.dll's
           UCB register handler sub_1EBACE8 reads it to save and restore it around a
           transaction. */
        if (addr - kBase == kOffSf0Aux) return sf0_aux_;
        if (addr - kBase == kOffSf0Stat) return sf0_stat_;
        /* SNDDMAPTR[13:2]<29:18>(R) is not modelled and reads 0 (§13.6.15); the guest
           reads DMACTL only to read-modify-write ENDMATXSND. */
        if (addr - kBase == kOffDmaCtl) return dma_ctl_;
        HaltUnsupportedAccess("PR31x00 SIB ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        if (addr - kBase == kOffDmaCtl) {
            WriteDmaCtl(addr, value);
            return;
        }
        /* SF0AUX and SF1AUX hold the control word transmitted during their subframe,
           re-sent every frame until rewritten (§13.6.11, §13.6.12). SNDTXHOLD and
           TELTXHOLD hold the next sound and telecom sample (§13.6.7, §13.6.9). */
        if (addr - kBase == kOffSize) {
            if (value & kSizeReserved) {
                HaltUnsupportedAccess("PR31x00 SIB SIZE reserved", addr, value);
            }
            snd_size_ = (value >> kSizeSndShift) & kSizeSndMask;
            return;
        }
        if (addr - kBase == kOffSndTxSt) {
            if (value & kStartReserved) {
                HaltUnsupportedAccess("PR31x00 SIB DMA start reserved", addr, value);
            }
            snd_tx_start_ = value & kSndTxStartMask;
            return;
        }
        if (addr - kBase == kOffSndRxSt || addr - kBase == kOffTelRxSt ||
            addr - kBase == kOffTelTxSt) {
            if (value & kStartReserved) {
                HaltUnsupportedAccess("PR31x00 SIB DMA start reserved", addr, value);
            }
            return;
        }
        if (addr - kBase == kOffSf0Aux) { WriteSf0Aux(addr, value); return; }
        if (addr - kBase == kOffSf1Aux) { sf1_aux_ = value; return; }
        if (addr - kBase == kOffSndTx)  { snd_tx_hold_ = value; return; }
        if (addr - kBase == kOffTelTx)  { tel_tx_hold_ = value; return; }
        if (addr - kBase != kOffCtl) {
            HaltUnsupportedAccess("PR31x00 SIB WriteWord", addr, value);
        }
        if (value & kCtlTest) {
            HaltUnsupportedAccess("PR31x00 SIB CTL IC-test bit", addr, value);
        }
        if (value & kCtlRunning) {
            HaltUnsupportedAccess("PR31x00 SIB CTL starts a telecom or loopback frame "
                                  "with no codec modelled", addr, value);
        }
        ctl_ = value & kCtlWritable;
        UpdateSound();
        UpdateSibFrameInts();
    }

    /* SNDVALID and TELVALID mark the accompanying sound and telecom samples in the
       same subframe; neither channel is enabled, so a set bit carries a sample the
       SIB would have to move. */
    void WriteSf0Aux(uint32_t addr, uint32_t value) {
        if (value & (kSf0SndValid | kSf0TelValid)) {
            HaltUnsupportedAccess("PR31x00 SIB SF0AUX carries a sound or telecom sample",
                                  addr, value);
        }
        sf0_aux_ = value;

        auto* codec = emu_.TryGet<Pr31x00SibCodec>();
        if (!codec) {
            HaltUnsupportedAccess("PR31x00 SIB subframe 0 with no codec modelled", addr, value);
        }

        const uint8_t  reg  = static_cast<uint8_t>((value >> kSf0RegAddrShift) & kSf0RegAddrMask);
        const uint16_t data = static_cast<uint16_t>(value & kSf0RegDataMask);
        if (value & kSf0Write) codec->WriteReg(reg, data);
        else                   sf0_stat_ = codec->ReadReg(reg);
    }

    void WriteDmaCtl(uint32_t addr, uint32_t value) {
        if (value & kDmaCtlReadOnly) {
            HaltUnsupportedAccess("PR31x00 SIB DMACTL write to a DMA pointer field",
                                  addr, value);
        }
        if (value & kDmaCtlArmed) {
            HaltUnsupportedAccess("PR31x00 SIB DMACTL arms a telecom or RX DMA channel "
                                  "with no codec modelled", addr, value);
        }
        dma_ctl_ = value;
        UpdateSound();
    }

    void SaveState(StateWriter& w) override {
        w.Write("ctl", ctl_); w.Write("dma_ctl", dma_ctl_); w.Write("sf0_aux", sf0_aux_); w.Write("sf1_aux", sf1_aux_);
        w.Write("snd_tx_hold", snd_tx_hold_); w.Write("tel_tx_hold", tel_tx_hold_); w.Write("sf0_stat", sf0_stat_);
        w.Write("snd_tx_start", snd_tx_start_); w.Write("snd_size", snd_size_);
        if (auto* codec = emu_.TryGet<Pr31x00SibCodec>()) codec->SaveState(w);
    }
    void RestoreState(StateReader& r) override {
        r.Read("ctl", ctl_); r.Read("dma_ctl", dma_ctl_); r.Read("sf0_aux", sf0_aux_); r.Read("sf1_aux", sf1_aux_);
        r.Read("snd_tx_hold", snd_tx_hold_); r.Read("tel_tx_hold", tel_tx_hold_); r.Read("sf0_stat", sf0_stat_);
        r.Read("snd_tx_start", snd_tx_start_); r.Read("snd_size", snd_size_);
        if (auto* codec = emu_.TryGet<Pr31x00SibCodec>()) codec->RestoreState(r);
    }
    void PostRestore() override {
        sound_active_ = false;
        UpdateSound();
        if (auto* codec = emu_.TryGet<Pr31x00SibCodec>()) codec->PostRestore();
    }

private:
    bool SoundArmed() const {
        return (ctl_ & kCtlEnSib) && (ctl_ & kCtlEnSnd) && (dma_ctl_ & kDmaEnTxSnd);
    }
    uint32_t SoundRateHz() const {
        const uint32_t fsdiv = (ctl_ >> kCtlSndFsShift) & kCtlSndFsMask;
        return (kSibSclkHz * 2u) / ((fsdiv + 1u) * 64u);
    }
    uint32_t SoundBytes() const { return (snd_size_ + 1u) << 2; }

    void UpdateSound() {
        auto* sink = emu_.TryGet<Pr31x00SibAudioSink>();
        if (SoundArmed()) {
            if (!sink) {
                HaltUnsupportedAccess("PR31x00 SIB sound TX DMA with no audio sink",
                                      MmioBase(), ctl_);
            }
            if (!sound_active_) {
                sink->StartSoundTx(snd_tx_start_, SoundBytes(), SoundRateHz());
                sound_active_ = true;
            }
        } else if (sound_active_) {
            if (sink) sink->StopSoundTx();
            sound_active_ = false;
        }
    }

    /* Every SIB frame carries both subframe 0 and subframe 1 (§13.3.1 Fig 13.3.1), so
       SIBSF0INT and SIBSF1INT both re-issue each frame while it runs; §8.3.1: SF1INT
       gates the CPU read of SF0STAT that the codec-register read protocol waits on. */
    void UpdateSibFrameInts() {
        const bool active = (ctl_ & (kCtlEnSib | kCtlEnSf0)) == (kCtlEnSib | kCtlEnSf0);
        emu_.Get<Pr31x00Intc>().SetSourceFreeRunning(0, kSibSf0Int | kSibSf1Int, active);
    }

    uint32_t ctl_     = kCtlReset;
    uint32_t dma_ctl_ = 0;
    uint32_t sf0_aux_ = 0;
    uint32_t sf1_aux_ = 0;
    uint32_t snd_tx_hold_ = 0;
    uint32_t tel_tx_hold_ = 0;
    uint32_t sf0_stat_    = 0;
    uint32_t snd_tx_start_ = 0;
    uint32_t snd_size_     = 0;
    bool     sound_active_ = false;
};

}  /* namespace */

REGISTER_SERVICE(Pr31x00Sib);
