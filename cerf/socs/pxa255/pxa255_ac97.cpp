#include "pxa255_ac97.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/ac97_codec.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../pxa2xx/pxa2xx_ac97_link.h"
#include "../pxa2xx/pxa2xx_ac97_modem.h"
#include "../pxa2xx/pxa2xx_ac97_pcm.h"
#include "../pxa2xx/pxa2xx_ac97_pcm_in.h"
#include "../pxa2xx/pxa2xx_dma.h"
#include "pxa255_clock_manager.h"
#include "pxa255_id.h"

REGISTER_SERVICE(Pxa255Ac97);

namespace {

/* Intel PXA255 Developer's Manual Table 13-7 (pages 13-20, 13-21) GCR: CDONE_IE 19, SDONE_IE 18,
   SECRDY_IEN 9, PRIRDY_IEN 8, SECRES_IEN 5, PRIRES_IEN 4, ACLINK_OFF 3, WARM_RST 2, COLD_RST 1, GIE 0. */
constexpr uint32_t kGcrColdRst  = 1u << 1;
constexpr uint32_t kGcrWarmRst  = 1u << 2;
constexpr uint32_t kGcrLinkOff  = 1u << 3;
constexpr uint32_t kGcrIrqEnables = (1u << 19) | (1u << 18) | (1u << 9) | (1u << 8) | (1u << 5) |
                                    (1u << 4) | (1u << 0);
/* Intel PXA255 Developer's Manual Table 13-8 (pages 13-22, 13-23) GSR: CDONE 19, SDONE 18, PCR 8,
   POINT 6, PIINT 5, MIINT 1. */
constexpr uint32_t kGsrCdone = 1u << 19;
constexpr uint32_t kGsrSdone = 1u << 18;
constexpr uint32_t kGsrPcr   = 1u << 8;
constexpr uint32_t kGsrPoint = 1u << 6;
constexpr uint32_t kGsrPiint = 1u << 5;
constexpr uint32_t kGsrMiint = 1u << 1;
/* Intel PXA255 Developer's Manual Tables 13-9 and 13-10 (pages 13-23, 13-24), 13-15 (page 13-27),
   13-18 (page 13-29) and 13-19 (page 13-30): FEIE bit 3; Table 13-13 (page 13-26): CAIP bit 0. */
constexpr uint32_t kFeie = 1u << 3;
constexpr uint32_t kCaip = 1u << 0;
/* Intel PXA255 Developer's Manual Table 3-21 (page 3-37): CKEN2 "AC97 Unit Clock Enable". */
constexpr uint32_t kCkenAc97 = 2u;

}  // namespace

bool Pxa255Ac97::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Pxa255;
}

void Pxa255Ac97::OnReady() {
    clock_  = &emu_.Get<GuestCycleClock>();
    clocks_ = &emu_.Get<Pxa255ClockManager>();
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

/* Intel PXA255 Developer's Manual section 3.4.2 (page 3-7) and section 3.4.3 (page 3-8): the
   watchdog and GPIO resets reset every unit outside the RTC, the Clocks and Power Manager and the
   Memory Controller. */
/* Intel PXA255 Developer's Manual Table 13-7 (page 13-21) COLD_RST: "The value of this bit is retained after
   suspends"; Table 2-6 (page 2-15): nACRESET is "Driven Low" in the sleep state. */
void Pxa255Ac97::ResetLine() {
    const bool released = emu_.Get<GuestCpuReset>().DeliveredResetWasResume() && (gcr_ & kGcrColdRst) != 0u;
    pocr_ = picr_ = mccr_ = mocr_ = micr_ = 0u;
    gcr_  = released ? kGcrColdRst : 0u;
    link_->ResetLine();
    if (released) link_->SetColdReset(clock_->Cycles(), false);
}

bool Pxa255Ac97::IsRegister(uint32_t off) {
    switch (off) {
    case kPOCR: case kPICR: case kMCCR: case kGCR: case kPOSR: case kPISR: case kGSR: case kCAR:
    case kPCDR: case kMOCR: case kMICR: case kMISR: case kMODR:
        return true;
    default:
        return false;
    }
}

void Pxa255Ac97::OnUnitClock(uint32_t old_cken) {
    const bool was_on = ((old_cken >> kCkenAc97) & 1u) != 0u;
    const bool is_on  = clocks_->ClockEnabled(kCkenAc97);
    if (was_on == is_on || (!link_->Running() && !link_->ClockStartPending())) return;
    emu_.Get<Fatal>().Die("Pxa255Ac97: CKEN2 %s with the AC-link %s; not modelled", is_on ? "set" : "cleared",
                          link_->Running() ? "running" : "starting BITCLK");
}

void Pxa255Ac97::RequireOutOfReset(uint32_t off) {
    if ((gcr_ & kGcrColdRst) != 0u) return;
    emu_.Get<Fatal>().Die("Pxa255Ac97: codec window access at offset 0x%03X while GCR COLD_RST holds "
                          "the AC-link in cold reset; not modelled", off);
}

/* Intel PXA255 Developer's Manual section 13.6.1 (page 13-15): until COLD_RST is set "all other
   registers remain in a reset state". */
uint32_t Pxa255Ac97::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    const uint64_t now = clock_->Cycles();
    if (Pxa2xxAc97Link::InCodecWindow(off)) {
        RequireOutOfReset(off);
        return link_->CodecWindowRead(now, off);
    }
    if (!IsRegister(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    /* Intel PXA255 Developer's Manual Table 13-7 (page 13-21) WARM_RST: "it remains set until the reset
       completes and BITCLK is seen on the AC-link after which it clears itself". */
    if (off == kGCR) return gcr_ | (link_->WarmResetPending() ? kGcrWarmRst : 0u);
    if ((gcr_ & kGcrColdRst) == 0u) return 0u;
    switch (off) {
    case kPOCR: return pocr_;
    case kPICR: return picr_;
    case kMCCR: return mccr_;
    case kMOCR: return mocr_;
    case kMICR: return micr_;
    case kPOSR: return pcm_->OutStatus(now) & Pxa2xxAc97Pcm::kFifoe;
    case kPISR: return pcm_in_->Status(now) & Pxa2xxAc97InFifo::kFifoe;
    case kGSR: {
        uint32_t v = 0u;
        if (link_->CommandDone(now)) v |= kGsrCdone;
        if (link_->StatusDone(now)) v |= kGsrSdone;
        if (link_->CodecReady(now)) v |= kGsrPcr;
        if ((pcm_->OutStatus(now) & Pxa2xxAc97Pcm::kFifoe) != 0u) v |= kGsrPoint;
        if ((pcm_in_->Status(now) & Pxa2xxAc97InFifo::kFifoe) != 0u) v |= kGsrPiint;
        if ((modem_->Status(now) & Pxa2xxAc97InFifo::kFifoe) != 0u) v |= kGsrMiint;
        return v;
    }
    case kCAR: return link_->ReadCar(now) ? kCaip : 0u;
    /* Intel PXA255 Developer's Manual Table 13-21 (page 13-31) MISR: FIFOE "is set if a receive
       FIFO overrun occurs"; bits 3:0 reserved. */
    case kMISR: return modem_->Status(now) & Pxa2xxAc97InFifo::kFifoe;
    /* Intel PXA255 Developer's Manual section 13.6 (page 13-15): "programmed I/O must not be
       used in place of DMA requests". */
    case kMODR:
        emu_.Get<Fatal>().Die("Pxa255Ac97: MODR read by programmed I/O; not modelled");
    default:
        emu_.Get<Fatal>().Die("Pxa255Ac97: PCDR read by programmed I/O; not modelled");
    }
}

void Pxa255Ac97::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    const uint64_t now = clock_->Cycles();
    if (Pxa2xxAc97Link::InCodecWindow(off)) {
        RequireOutOfReset(off);
        link_->CodecWindowWrite(now, off, static_cast<uint16_t>(value));
        return;
    }
    if (!IsRegister(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    if (off == kGCR) {
        WriteGcr(now, value);
        return;
    }
    if ((gcr_ & kGcrColdRst) == 0u) return;
    switch (off) {
    case kPOCR: WriteControl(pocr_, value, "POCR"); return;
    case kPICR: WriteControl(picr_, value, "PICR"); return;
    case kMCCR: WriteControl(mccr_, value, "MCCR"); return;
    case kMOCR: WriteControl(mocr_, value, "MOCR"); return;
    case kMICR: WriteControl(micr_, value, "MICR"); return;
    case kGSR:  link_->ClearDone(now, (value & kGsrCdone) != 0u, (value & kGsrSdone) != 0u); return;
    case kPOSR: pcm_->ClearOutStatus(now, value & Pxa2xxAc97Pcm::kFifoe); return;
    case kPISR: pcm_in_->ClearStatus(now, value & Pxa2xxAc97InFifo::kFifoe); return;
    case kCAR:
        /* Table 13-13 (page 13-26) CAIP: "Software can clear this bit by writing a '0' to this bit
           location". */
        if ((value & kCaip) != 0u) {
            emu_.Get<Fatal>().Die("Pxa255Ac97: CAR write 0x%08X sets CAIP; not modelled", value);
        }
        link_->ClearCar(now);
        return;
    case kMISR: modem_->ClearStatus(now, value & Pxa2xxAc97InFifo::kFifoe); return;
    case kPCDR:
        emu_.Get<Fatal>().Die("Pxa255Ac97: PCDR write 0x%08X by programmed I/O; not modelled", value);
    default:
        emu_.Get<Fatal>().Die("Pxa255Ac97: MODR write 0x%08X; the modem transmit FIFO is not modelled",
                              value);
    }
}

uint16_t Pxa255Ac97::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!Pxa2xxAc97Link::InCodecWindow(off)) HaltUnsupportedAccess("ReadHalf", addr, 0);
    RequireOutOfReset(off);
    return static_cast<uint16_t>(link_->CodecWindowRead(clock_->Cycles(), off));
}

void Pxa255Ac97::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - MmioBase();
    if (!Pxa2xxAc97Link::InCodecWindow(off)) HaltUnsupportedAccess("WriteHalf", addr, value);
    RequireOutOfReset(off);
    link_->CodecWindowWrite(clock_->Cycles(), off, value);
}

void Pxa255Ac97::WriteControl(uint32_t& reg, uint32_t value, const char* name) {
    if ((value & kFeie) != 0u) {
        emu_.Get<Fatal>().Die("Pxa255Ac97: %s 0x%08X enables the FIFO error interrupt; not modelled",
                              name, value);
    }
    reg = 0u;
}

/* Intel PXA255 Developer's Manual Table 13-7 (page 13-21) COLD_RST: "0 = Causes a cold reset to occur
   throughout the AC'97 circuitry. All data in the ACUNIT and the CODEC will be lost"; WARM_RST
   "is self clearing"; ACLINK_OFF "0 = If the AC-link was off, turns it back on". */
void Pxa255Ac97::WriteGcr(uint64_t now, uint32_t value) {
    if ((value & kGcrIrqEnables) != 0u) {
        emu_.Get<Fatal>().Die("Pxa255Ac97: GCR 0x%08X enables an AC'97 interrupt; not modelled", value);
    }
    const bool cold = (value & kGcrColdRst) == 0u;
    if (cold) pocr_ = picr_ = mccr_ = mocr_ = micr_ = 0u;
    gcr_ = value & (kGcrColdRst | kGcrLinkOff);
    link_->SetColdReset(now, cold);
    if ((value & kGcrWarmRst) != 0u) link_->WarmReset(now);
    link_->SetLinkOff(now, (value & kGcrLinkOff) != 0u, false);
    dma_->OnPortChange();
}

void Pxa255Ac97::SaveState(StateWriter& w) {
    w.Write("pocr", pocr_);
    w.Write("picr", picr_);
    w.Write("mccr", mccr_);
    w.Write("gcr", gcr_);
    w.Write("mocr", mocr_);
    w.Write("micr", micr_);
    link_->Save(w);
    pcm_->Save(w);
    pcm_in_->Save(w);
    modem_->Save(w);
    if (codec_ != nullptr) codec_->SaveState(w);
}

void Pxa255Ac97::RestoreState(StateReader& r) {
    r.Read("pocr", pocr_);
    r.Read("picr", picr_);
    r.Read("mccr", mccr_);
    r.Read("gcr", gcr_);
    r.Read("mocr", mocr_);
    r.Read("micr", micr_);
    link_->Restore(r);
    pcm_->Restore(r);
    pcm_in_->Restore(r);
    modem_->Restore(r);
    if (codec_ != nullptr) codec_->RestoreState(r);
}

void Pxa255Ac97::PostRestore() {
    link_->PostRestore();
    if (codec_ != nullptr) codec_->PostRestore();
}
