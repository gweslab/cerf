#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/ac97_codec.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../pxa2xx/pxa2xx_ac97_link.h"
#include "../pxa2xx/pxa2xx_ac97_modem.h"
#include "../pxa2xx/pxa2xx_ac97_pcm.h"
#include "../pxa2xx/pxa2xx_ac97_pcm_in.h"
#include "../pxa2xx/pxa2xx_dma.h"
#include "pxa270_id.h"
#include "pxa27x_clock_manager.h"

#include <cstdint>

namespace {

/* Intel PXA27x Developer's Manual Table 13-10 (page 13-26) POCR, Table 13-11 PCMICR, Table 13-16
   MCCR, Table 13-19 MOCR, Table 13-20 MICR: FEIE bit 3, FSRIE bit 1. */
constexpr uint32_t kCtrlIrqEnables = (1u << 3) | (1u << 1);
/* Intel PXA27x Developer's Manual Table 13-17 (page 13-33) MCSR and Table 13-22 (page 13-38) MISR:
   FIFOE 4, EOC 3, FSR 2; Table 13-21 (page 13-37) MOSR: FIFOE 4, FSR 2. */
constexpr uint32_t kFifoe = 1u << 4, kEoc = 1u << 3, kFsr = 1u << 2;
/* Intel PXA27x Developer's Manual Table 13-8 (pages 13-21, 13-22) GCR. */
constexpr uint32_t kGcrNdmaen = 1u << 24;
constexpr uint32_t kGcrIrqEnables = (1u << 19) | (1u << 18) | (1u << 9) | (1u << 8) | (1u << 5) |
                                    (1u << 4) | (1u << 0);
constexpr uint32_t kGcrAcoff = 1u << 3, kGcrWrst = 1u << 2, kGcrNcrst = 1u << 1;
/* Intel PXA27x Developer's Manual Table 13-9 (pages 13-23 to 13-25) GSR. */
constexpr uint32_t kGsrCdone = 1u << 19, kGsrSdone = 1u << 18, kGsrPcrdy = 1u << 8;
constexpr uint32_t kGsrPoint = 1u << 6, kGsrPiint = 1u << 5;
constexpr uint32_t kGsrAcoffd = 1u << 3, kGsrMoint = 1u << 2, kGsrMiint = 1u << 1;
constexpr uint32_t kCaip = 1u << 0;
/* Intel PXA27x Developer's Manual Table 3-33 (page 3-98): CKEN[2] "AC '97 Controller Clock Enable";
   Table 13-7 (page 13-13): CKEN[31] 0 with CKEN[2] 1, "AC97_BITCLK enabled and is externally provided". */
constexpr uint32_t kCkenAc97 = 2u, kCkenAc97Config = 31u;

class Pxa27xAc97 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Pxa270;
    }

    /* Intel PXA27x Developer's Manual Table 3-2 (page 3-12): "Any module not listed takes the reset
       value for all of its registers". */
    void OnReady() override {
        clock_  = &emu_.Get<GuestCycleClock>();
        clocks_ = &emu_.Get<Pxa27xClockManager>();
        clocks_->RegisterClockEnableListener([this](uint32_t old_cken) { OnUnitClock(old_cken); });
        link_  = &emu_.Get<Pxa2xxAc97Link>();
        pcm_    = &emu_.Get<Pxa2xxAc97Pcm>();
        pcm_in_ = &emu_.Get<Pxa2xxAc97PcmIn>();
        modem_  = &emu_.Get<Pxa2xxAc97Modem>();
        dma_   = &emu_.Get<Pxa2xxDma>();
        codec_ = emu_.TryGet<Ac97Codec>();
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) { ResetLine(); });
    }

    uint32_t MmioBase() const override { return 0x40500000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;
    uint16_t ReadHalf(uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

private:
    enum : uint32_t {
        kPOCR = 0x000u, kPCMICR = 0x004u, kMCCR = 0x008u, kGCR = 0x00Cu, kPOSR = 0x010u,
        kPCMISR = 0x014u, kMCSR = 0x018u, kGSR = 0x01Cu, kCAR = 0x020u, kPCDR = 0x040u,
        kMCDR = 0x060u, kMOCR = 0x100u, kMICR = 0x108u, kMOSR = 0x110u, kMISR = 0x118u,
        kMODR = 0x140u,
    };

    bool     InColdReset() const { return (gcr_ & kGcrNcrst) == 0u; }
    uint32_t ModemOutStatus() const;
    void     RequireUnitClock(uint32_t off);
    void     OnUnitClock(uint32_t old_cken);
    void     RequireExternalBitclk(uint32_t gcr);
    void     RequireOutOfReset(uint32_t off);
    uint32_t ReadGsr(uint64_t now);
    void     WriteGcr(uint64_t now, uint32_t value);
    void     WriteControl(uint32_t& reg, uint32_t value, const char* name);
    void     ClearRegisters();
    void     ResetLine();

    GuestCycleClock*    clock_  = nullptr;
    Pxa27xClockManager* clocks_ = nullptr;
    Pxa2xxAc97Link*  link_  = nullptr;
    Pxa2xxAc97Pcm*   pcm_    = nullptr;
    Pxa2xxAc97PcmIn* pcm_in_ = nullptr;
    Pxa2xxAc97Modem* modem_  = nullptr;
    Pxa2xxDma*       dma_   = nullptr;
    Ac97Codec*       codec_ = nullptr;

    uint32_t gcr_ = 0, pocr_ = 0, pcmicr_ = 0, mccr_ = 0, mocr_ = 0, micr_ = 0;
    bool     shut_down_ = false;
};

void Pxa27xAc97::ClearRegisters() {
    pocr_ = pcmicr_ = mccr_ = mocr_ = micr_ = 0u;
    shut_down_ = false;
}

/* Intel PXA27x Developer's Manual Table 13-21 (page 13-37) MOSR FSR: "1 = FIFO needs servicing",
   "This bit is updated independently of the value of its interrupt enable, FSRIE"; FIFOE is set on
   a transmit underrun or a programmed-I/O overrun. */
uint32_t Pxa27xAc97::ModemOutStatus() const { return link_->RequestsEnabled() ? kFsr : 0u; }

/* Intel PXA27x Developer's Manual Table 13-8 (page 13-22) nCRST: "The value of this bit is retained after
   suspends"; Table 24-2 (pages 24-7, 24-8): AC97_RESET_n is the output of GPIO 95 or GPIO 113. */
void Pxa27xAc97::ResetLine() {
    if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume() && (gcr_ & kGcrNcrst) != 0u) {
        emu_.Get<Fatal>().Die("Pxa27xAc97: sleep exit with GCR nCRST set; the codec reset across the sleep follows "
                              "the sleep level of the GPIO that carries AC97_RESET_n; not modelled");
    }
    gcr_ = 0u;
    ClearRegisters();
    link_->ResetLine();
}

void Pxa27xAc97::RequireUnitClock(uint32_t off) {
    if (clocks_->ClockEnabled(kCkenAc97)) return;
    emu_.Get<Fatal>().Die("Pxa27xAc97: access at offset 0x%03X with CKEN[2] clear; not modelled", off);
}

/* Intel PXA27x Developer's Manual Table 13-7 (page 13-13): "Software must not set or clear CKEN[31] and
   CKEN[2] at the same time"; CKEN[31] 1 with CKEN[2] 0: "AC97_RESET_n signal is asserted". */
void Pxa27xAc97::OnUnitClock(uint32_t old_cken) {
    const uint32_t old31 = (old_cken >> kCkenAc97Config) & 1u, old2 = (old_cken >> kCkenAc97) & 1u;
    const uint32_t new31 = clocks_->ClockEnabled(kCkenAc97Config) ? 1u : 0u;
    const uint32_t new2  = clocks_->ClockEnabled(kCkenAc97) ? 1u : 0u;
    if ((old31 == new31 && old2 == new2) || InColdReset()) return;
    emu_.Get<Fatal>().Die("Pxa27xAc97: CKEN[31] / CKEN[2] %u / %u -> %u / %u with GCR nCRST set; not modelled",
                          old31, old2, new31, new2);
}

void Pxa27xAc97::RequireExternalBitclk(uint32_t gcr) {
    if (!clocks_->ClockEnabled(kCkenAc97Config) && clocks_->ClockEnabled(kCkenAc97)) return;
    emu_.Get<Fatal>().Die("Pxa27xAc97: GCR 0x%08X releases the cold reset with CKEN[31] %u and CKEN[2] %u; "
                          "not modelled", gcr, clocks_->ClockEnabled(kCkenAc97Config) ? 1u : 0u,
                          clocks_->ClockEnabled(kCkenAc97) ? 1u : 0u);
}

void Pxa27xAc97::RequireOutOfReset(uint32_t off) {
    if (!InColdReset()) return;
    emu_.Get<Fatal>().Die("Pxa27xAc97: codec window access at offset 0x%03X while GCR nCRST holds "
                          "the AC-link in cold reset; not modelled", off);
}

/* Intel PXA27x Developer's Manual section 13.6.1 (page 13-16): "When GCR[nCRST] is 0b0, all other
   registers are in their reset state." */
uint32_t Pxa27xAc97::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    const uint64_t now = clock_->Cycles();
    RequireUnitClock(off);
    if (Pxa2xxAc97Link::InCodecWindow(off)) {
        RequireOutOfReset(off);
        return link_->CodecWindowRead(now, off);
    }
    /* Intel PXA27x Developer's Manual Table 13-8 (page 13-22) WRST: "It remains set until the reset completes
       and AC97_BITCLK is seen on the AC-link, after which it clears itself." */
    if (off == kGCR) return gcr_ | (link_->WarmResetPending() ? kGcrWrst : 0u);
    switch (off) {
    case kPOCR: case kPCMICR: case kMCCR: case kPOSR: case kPCMISR: case kMCSR: case kGSR:
    case kCAR: case kPCDR: case kMCDR: case kMOCR: case kMICR: case kMOSR: case kMISR: case kMODR:
        if (InColdReset()) return 0u;
        break;
    default:
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }
    switch (off) {
    case kPOCR:   return pocr_;
    case kPCMICR: return pcmicr_;
    case kMCCR:   return mccr_;
    case kMOCR:   return mocr_;
    case kMICR:   return micr_;
    case kPOSR:   return pcm_->OutStatus(now) & (kFifoe | kFsr);
    case kPCMISR: return pcm_in_->Status(now) & (kFifoe | kEoc | kFsr);
    /* Intel PXA27x Developer's Manual section 13.4.2.7 (page 13-11): slot 6 carries the microphone
       record data; Cirrus Logic WM9713L Rev 4.0 Table 10 (page 32): ADC data reaches slot 6 only
       with ASS 10. */
    case kMCSR:   return 0u;
    case kMOSR:   return ModemOutStatus();
    case kMISR:   return modem_->Status(now);
    case kGSR:    return ReadGsr(now);
    case kCAR:    return link_->ReadCar(now) ? kCaip : 0u;
    case kPCDR:   return pcm_in_->ReadData(now, "PCDR");
    case kMCDR:
        emu_.Get<Fatal>().Die("Pxa27xAc97: MCDR read; the mic-in receive FIFO is not modelled");
    default:      return modem_->ReadData(now, "MODR");
    }
}

void Pxa27xAc97::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    const uint64_t now = clock_->Cycles();
    RequireUnitClock(off);
    if (Pxa2xxAc97Link::InCodecWindow(off)) {
        RequireOutOfReset(off);
        link_->CodecWindowWrite(now, off, static_cast<uint16_t>(value));
        return;
    }
    if (off == kGCR) {
        WriteGcr(now, value);
        return;
    }
    switch (off) {
    case kPOCR: case kPCMICR: case kMCCR: case kPOSR: case kPCMISR: case kMCSR: case kGSR:
    case kCAR: case kPCDR: case kMCDR: case kMOCR: case kMICR: case kMOSR: case kMISR: case kMODR:
        if (InColdReset()) return;
        break;
    default:
        HaltUnsupportedAccess("WriteWord", addr, value);
    }
    switch (off) {
    case kPOCR:   WriteControl(pocr_, value, "POCR"); return;
    case kPCMICR: WriteControl(pcmicr_, value, "PCMICR"); return;
    case kMCCR:   WriteControl(mccr_, value, "MCCR"); return;
    case kMOCR:   WriteControl(mocr_, value, "MOCR"); return;
    case kMICR:   WriteControl(micr_, value, "MICR"); return;
    case kPOSR:   pcm_->ClearOutStatus(now, value & kFifoe); return;
    case kPCMISR: pcm_in_->ClearStatus(now, value & (kFifoe | kEoc)); return;
    case kMCSR:   return;
    case kMOSR:   return;
    case kMISR:   modem_->ClearStatus(now, value & (kFifoe | kEoc)); return;
    case kGSR:    link_->ClearDone(now, (value & kGsrCdone) != 0u, (value & kGsrSdone) != 0u); return;
    /* Intel PXA27x Developer's Manual Table 13-14 (page 13-30) CAIP: "Software can also clear this
       bit by writing 0b0 to this bit location". */
    case kCAR:
        if ((value & kCaip) != 0u) {
            emu_.Get<Fatal>().Die("Pxa27xAc97: CAR write 0x%08X sets CAIP; not modelled", value);
        }
        link_->ClearCar(now);
        return;
    case kPCDR: pcm_->WriteData(now, value); return;
    /* Intel PXA27x Developer's Manual Table 13-18 (page 13-34) MCDR: "This is a read-only register.
       A write to this register has no effect." */
    case kMCDR: return;
    default:
        emu_.Get<Fatal>().Die("Pxa27xAc97: MODR write 0x%08X; the modem transmit FIFO is not modelled",
                              value);
    }
}

uint16_t Pxa27xAc97::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    RequireUnitClock(off);
    if (!Pxa2xxAc97Link::InCodecWindow(off)) HaltUnsupportedAccess("ReadHalf", addr, 0);
    RequireOutOfReset(off);
    return static_cast<uint16_t>(link_->CodecWindowRead(clock_->Cycles(), off));
}

void Pxa27xAc97::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - MmioBase();
    RequireUnitClock(off);
    if (!Pxa2xxAc97Link::InCodecWindow(off)) HaltUnsupportedAccess("WriteHalf", addr, value);
    RequireOutOfReset(off);
    link_->CodecWindowWrite(clock_->Cycles(), off, value);
}

void Pxa27xAc97::WriteControl(uint32_t& reg, uint32_t value, const char* name) {
    if ((value & kCtrlIrqEnables) != 0u) {
        emu_.Get<Fatal>().Die("Pxa27xAc97: %s 0x%08X enables an AC'97 FIFO interrupt; not modelled",
                              name, value);
    }
    reg = 0u;
}

/* Intel PXA27x Developer's Manual Table 13-9 (page 13-24): POINT "Is set to 0b1 if either
   POSR[FIFOE] or POSR[FSR] is 0b1", PIINT and MCINT also on EOC; ACOFFD "Is 0b1 if the AC-link has
   been cleanly shutdown ... It is cleared when GCR[ACOFF] is cleared". */
uint32_t Pxa27xAc97::ReadGsr(uint64_t now) {
    uint32_t v = 0u;
    if (link_->CommandDone(now)) v |= kGsrCdone;
    if (link_->StatusDone(now)) v |= kGsrSdone;
    if (link_->CodecReady(now)) v |= kGsrPcrdy;
    if (pcm_->OutStatus(now) != 0u) v |= kGsrPoint;
    if (pcm_in_->Status(now) != 0u) v |= kGsrPiint;
    if (ModemOutStatus() != 0u) v |= kGsrMoint;
    if (modem_->Status(now) != 0u) v |= kGsrMiint;
    if (shut_down_) v |= kGsrAcoffd;
    return v;
}

/* Intel PXA27x Developer's Manual section 13.6.2 (page 13-17): "Setting GCR[ACOFF] cleanly shuts down
   the AC '97 controller"; "The GCR[nCRST] bit supersedes the GCR[ACOFF] bit and therefore prevents a
   clean shutdown if set during or before the shutdown sequence." */
void Pxa27xAc97::WriteGcr(uint64_t now, uint32_t value) {
    if ((value & (kGcrIrqEnables | kGcrNdmaen)) != 0u) {
        emu_.Get<Fatal>().Die("Pxa27xAc97: GCR 0x%08X enables an AC'97 interrupt or programmed-I/O "
                              "FIFO service; not modelled", value);
    }
    const uint32_t old       = gcr_;
    const bool     cold      = (value & kGcrNcrst) == 0u;
    const bool     acoff_on  = (old & kGcrAcoff) == 0u && (value & kGcrAcoff) != 0u;
    const bool     acoff_off = (old & kGcrAcoff) != 0u && (value & kGcrAcoff) == 0u;
    gcr_ = value & (kGcrNcrst | kGcrAcoff);
    if (cold) {
        ClearRegisters();
        link_->SetColdReset(now, true);
        dma_->OnPortChange();
        return;
    }
    if (acoff_on && (old & kGcrNcrst) == 0u) {
        emu_.Get<Fatal>().Die("Pxa27xAc97: GCR 0x%08X releases the cold reset and sets ACOFF in one "
                              "write; not modelled", value);
    }
    if (acoff_off && shut_down_) {
        emu_.Get<Fatal>().Die("Pxa27xAc97: GCR 0x%08X clears ACOFF after a clean shutdown; not modelled",
                              value);
    }
    if ((old & kGcrNcrst) == 0u) RequireExternalBitclk(value);
    link_->SetColdReset(now, false);
    if ((value & kGcrWrst) != 0u) link_->WarmReset(now);
    if (acoff_on) {
        link_->SetLinkOff(now, true, true);
        shut_down_ = true;
    }
    dma_->OnPortChange();
}

void Pxa27xAc97::SaveState(StateWriter& w) {
    w.Write("gcr", gcr_);
    w.Write<uint8_t>("shut_down", shut_down_ ? 1u : 0u);
    link_->Save(w);
    pcm_->Save(w);
    pcm_in_->Save(w);
    modem_->Save(w);
    if (codec_ != nullptr) codec_->SaveState(w);
}

void Pxa27xAc97::RestoreState(StateReader& r) {
    uint8_t shut_down = 0;
    r.Read("gcr", gcr_);
    r.Read("shut_down", shut_down);
    shut_down_ = shut_down != 0u;
    link_->Restore(r);
    pcm_->Restore(r);
    pcm_in_->Restore(r);
    modem_->Restore(r);
    if (codec_ != nullptr) codec_->RestoreState(r);
}

void Pxa27xAc97::PostRestore() {
    link_->PostRestore();
    if (codec_ != nullptr) codec_->PostRestore();
}

}  // namespace

REGISTER_SERVICE(Pxa27xAc97);
