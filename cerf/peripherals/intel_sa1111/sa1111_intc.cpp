#include "sa1111_intc.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../../socs/sa11xx/sa11xx_gpio.h"
#include "../../state/state_stream.h"
#include "sa1111_sbi.h"
#include "sa1111_system_controller.h"

namespace {

/* SA-1111 Developer's Manual Table 3-3 note 1: "All reserved bits are read back as zero."
   Table 11-1: sources 27:31 and 55:63 reserved; §11.5.5 INTTSTSEL bits 1:0. */
constexpr uint32_t kSources0   = 0x07FFFFFFu;
constexpr uint32_t kSources1   = 0x007FFFFFu;
constexpr uint32_t kTstselBits = 0x3u;

}

bool Sa1111Intc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Jornada720;
}

/* SA-1111 Developer's Manual §2.3: "Unless indicated otherwise, all register bits are set to
   zero during reset." */
void Sa1111Intc::OnChipReset(bool held) {
    if (!held) return;
    std::lock_guard<std::mutex> lk(mtx_);
    asleep_    = false;
    inttest0_  = inttest1_  = 0u;
    enable0_   = enable1_   = 0u;
    polarity0_ = polarity1_ = 0u;
    tstsel_    = 0u;
    status0_   = status1_   = 0u;
    wake_en0_  = wake_en1_  = 0u;
    wake_pol0_ = wake_pol1_ = 0u;
    detect0_   = raw0_;
    detect1_   = raw1_;
    DriveCascadeOutput(false);
}

void Sa1111Intc::OnUnitReady() {
    const auto& sbi = emu_.Get<Sa1111Sbi>();
    emu_.Get<Sa1111SystemController>().RegisterClockListener([this, &sbi] {
        std::lock_guard<std::mutex> lk(mtx_);
        SetAsleep(sbi.SleepRequested());
    });
}

/* SA-1111 Developer's Manual §11.3.2 (printed 11-4): "Wake-up interrupts are only active when
   the Sleep state has been initiated by software"; "When an enabled wake-up signal is detected,
   the logical OR of all potential sources is output on the INT pin." */
void Sa1111Intc::SetAsleep(bool asleep) {
    if (asleep && !asleep_ && OutputAsserted()) {
        emu_.Get<Fatal>().Die("Sa1111Intc: SKCR Sleep set with INT asserted (status0 0x%08X, "
                              "status1 0x%08X) is not modelled", status0_, status1_);
    }
    asleep_ = asleep;
}

void Sa1111Intc::RequireAwake(uint8_t source) const {
    if (!asleep_) return;
    emu_.Get<Fatal>().Die("Sa1111Intc: source %u changed with SKCR Sleep set (the wake-up path) "
                          "is not modelled", source);
}

void Sa1111Intc::RegisterSampler(uint64_t sources, std::function<void()> sample) {
    std::lock_guard<std::mutex> lk(mtx_);
    sampled0_ |= static_cast<uint32_t>(sources);
    sampled1_ |= static_cast<uint32_t>(sources >> 32);
    samplers_.push_back(std::move(sample));
}

void Sa1111Intc::SampleSources() {
    for (auto& fn : samplers_) fn();
}

/* SA-1111 Developer's Manual §11.5.3 INTEN: "Writing a zero disables that status bit from
   generating an interrupt and writing a one enables its effect." */
void Sa1111Intc::RequireUnsampled(uint32_t bank, uint32_t enable) const {
    const uint32_t sampled = (bank != 0u ? sampled1_ : sampled0_) & enable;
    if (sampled == 0u) return;
    emu_.Get<Fatal>().Die("Sa1111Intc: INTEN%u 0x%08X enables source bits 0x%08X, whose "
                          "interrupt timing is not modelled", bank, enable, sampled);
}

/* §2.3: "When nRESET is asserted, all on-chip activity halts". */
void Sa1111Intc::SetSourceLevel(uint8_t source, bool level) {
    std::lock_guard<std::mutex> lk(mtx_);
    const bool     bank1 = source >= 32u;
    const uint32_t bit   = 1u << (source & 31u);
    uint32_t& raw = bank1 ? raw1_ : raw0_;
    raw = level ? (raw | bit) : (raw & ~bit);
    if (ChipHeld()) {
        (bank1 ? detect1_ : detect0_) = raw ^ (bank1 ? polarity1_ : polarity0_);
        return;
    }
    RequireAwake(source);
    LatchEdges(bank1);
    DriveCascadeOutput(false);
}

/* Offsets within the 0x40001600 block, Developer's Manual Table 11-2. */
uint32_t Sa1111Intc::UnitReadWord(uint32_t addr) {
    SampleSources();
    std::lock_guard<std::mutex> lk(mtx_);
    const uint32_t off = addr - MmioBase();
    switch (off) {
        /* §11.5.2 INTTEST: "On read, only bit 0 is significant indicating the logical OR of
           all the interrupt bits"; §11.5.7 INTSET: "When read, this register returns the value
           of the interrupt before it has been synchronized". */
        case 0x00: case 0x04: case 0x24: case 0x28:
            emu_.Get<Fatal>().Die("Sa1111Intc: %s read at +0x%02X is not modelled",
                                  off <= 0x04u ? "INTTEST" : "INTSET", off);
        case 0x08: return enable0_;
        case 0x0C: return enable1_;
        case 0x10: return polarity0_;
        case 0x14: return polarity1_;
        case 0x18: return tstsel_;
        case 0x1C: return status0_;     /* INTSTATCLR0 read = pending. */
        case 0x20: return status1_;
        case 0x2C: return wake_en0_;
        case 0x30: return wake_en1_;
        case 0x34: return wake_pol0_;
        case 0x38: return wake_pol1_;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Sa1111Intc::UnitWriteWord(uint32_t addr, uint32_t value) {
    SampleSources();
    std::lock_guard<std::mutex> lk(mtx_);
    const uint32_t off = addr - MmioBase();
    switch (off) {
        case 0x00: inttest0_  = value & kSources0; return;
        case 0x04: inttest1_  = value & kSources1; return;
        case 0x08: RequireUnsampled(0u, value & kSources0);
                   enable0_   = value & kSources0; DriveCascadeOutput(false); return;
        case 0x0C: RequireUnsampled(1u, value & kSources1);
                   enable1_   = value & kSources1; DriveCascadeOutput(false); return;
        case 0x10: polarity0_ = value & kSources0; LatchEdges(false);
                   DriveCascadeOutput(false); return;
        case 0x14: polarity1_ = value & kSources1; LatchEdges(true);
                   DriveCascadeOutput(false); return;
        /* §11.5.5 INTTSTSEL: bit 0 selects "the interrupt test register (Inttest) as the raw
           input", bit 1 "sets the mode as wake-up". */
        case 0x18:
            if ((value & kTstselBits) != 0u) {
                emu_.Get<Fatal>().Die("Sa1111Intc: INTTSTSEL 0x%08X (test source or wake-up "
                                      "mode) is not modelled", value);
            }
            tstsel_ = 0u;
            return;
        case 0x1C: status0_  &= ~value;           /* INTSTATCLR0 W1C. */
                   DriveCascadeOutput(true); return;
        case 0x20: status1_  &= ~value;
                   DriveCascadeOutput(true); return;
        /* §11.5.7 INTSET: "These registers allow the interrupt sources to be set. Writing a one
           will set the interrupt value, writing a zero will do nothing." */
        case 0x24: case 0x28:
            if ((value & (off == 0x24u ? kSources0 : kSources1)) != 0u) {
                emu_.Get<Fatal>().Die("Sa1111Intc: INTSET write 0x%08X at +0x%02X is not "
                                      "modelled", value, off);
            }
            return;
        case 0x2C: wake_en0_  = value & kSources0; return;
        case 0x30: wake_en1_  = value & kSources1; return;
        case 0x34: wake_pol0_ = value & kSources0; return;
        case 0x38: wake_pol1_ = value & kSources1; return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

/* INT output -> SA-1110 GPIO 1 (Linux jornada720.c: IRQ_GPIO1), rising-edge
   sensed. §11.1.1: a status clear pulses INT low and back high while sources
   remain pending - without that pulse_low_first re-edge on INTSTATCLR the
   guest ISR services one source and every later one hangs undelivered. */
void Sa1111Intc::DriveCascadeOutput(bool pulse_low_first) {
    auto& gpio = emu_.Get<Sa11xxGpio>();
    if (pulse_low_first) gpio.DriveInputPin(1, false);
    gpio.DriveInputPin(1, OutputAsserted());
}

/* Per-source edge latch (Dev Manual Fig 11-1): IntLatched sets on the rising
   edge of (IntRaw ^ IntPol). MUST run on INTPOL writes too, not just raw
   changes - sa1111_retrigger_*irq toggles INTPOL while the raw line is held
   to manufacture the re-edge; skip it and that retrigger silently fails. */
void Sa1111Intc::LatchEdges(bool bank1) {
    if (bank1) {
        const uint32_t detect = raw1_ ^ polarity1_;
        status1_ |= detect & ~detect1_;
        detect1_  = detect;
    } else {
        const uint32_t detect = raw0_ ^ polarity0_;
        status0_ |= detect & ~detect0_;
        detect0_  = detect;
    }
}

void Sa1111Intc::RaiseInterrupt(uint8_t source) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (source < 32) raw0_ |= 1u << source;
    else             raw1_ |= 1u << (source - 32);
    if (ChipHeld()) {
        detect0_ = raw0_ ^ polarity0_;
        detect1_ = raw1_ ^ polarity1_;
        return;
    }
    RequireAwake(source);
    if (source < 32) { LatchEdges(false); status0_ |= 1u << source; }
    else             { LatchEdges(true);  status1_ |= 1u << (source - 32); }
    DriveCascadeOutput(false);
}

void Sa1111Intc::LowerInterrupt(uint8_t source) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (source < 32) raw0_ &= ~(1u << source);
    else             raw1_ &= ~(1u << (source - 32));
    if (ChipHeld()) {
        detect0_ = raw0_ ^ polarity0_;
        detect1_ = raw1_ ^ polarity1_;
        return;
    }
    RequireAwake(source);
    LatchEdges(source >= 32);
    DriveCascadeOutput(false);
}

void Sa1111Intc::SaveState(StateWriter& w) {
    SampleSources();
    std::lock_guard<std::mutex> lk(mtx_);
    w.Write("raw0", raw0_);      w.Write("raw1", raw1_);
    w.Write("detect0", detect0_);   w.Write("detect1", detect1_);
    w.Write("inttest0", inttest0_);  w.Write("inttest1", inttest1_);
    w.Write("enable0", enable0_);   w.Write("enable1", enable1_);
    w.Write("polarity0", polarity0_); w.Write("polarity1", polarity1_);
    w.Write("tstsel", tstsel_);
    w.Write("status0", status0_);   w.Write("status1", status1_);
    w.Write("wake_en0", wake_en0_);  w.Write("wake_en1", wake_en1_);
    w.Write("wake_pol0", wake_pol0_); w.Write("wake_pol1", wake_pol1_);
}

void Sa1111Intc::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    r.Read("raw0", raw0_);      r.Read("raw1", raw1_);
    r.Read("detect0", detect0_);   r.Read("detect1", detect1_);
    r.Read("inttest0", inttest0_);  r.Read("inttest1", inttest1_);
    r.Read("enable0", enable0_);   r.Read("enable1", enable1_);
    r.Read("polarity0", polarity0_); r.Read("polarity1", polarity1_);
    r.Read("tstsel", tstsel_);
    r.Read("status0", status0_);   r.Read("status1", status1_);
    r.Read("wake_en0", wake_en0_);  r.Read("wake_en1", wake_en1_);
    r.Read("wake_pol0", wake_pol0_); r.Read("wake_pol1", wake_pol1_);
}

void Sa1111Intc::PostRestore() {
    const bool asleep = emu_.Get<Sa1111Sbi>().SleepRequested();
    std::lock_guard<std::mutex> lk(mtx_);
    asleep_ = asleep;
    DriveCascadeOutput(false);
}

REGISTER_SERVICE(Sa1111Intc);
