#include "sa1111_intc.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../../socs/sa11xx/sa11xx_gpio.h"
#include "../peripheral_dispatcher.h"
#include "../../state/state_stream.h"

bool Sa1111Intc::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Jornada720;
}

void Sa1111Intc::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

/* Offsets within the 0x40001600 block, Developer's Manual Table 11-2. */
uint32_t Sa1111Intc::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
        case 0x00: return inttest0_;
        case 0x04: return inttest1_;
        case 0x08: return enable0_;
        case 0x0C: return enable1_;
        case 0x10: return polarity0_;
        case 0x14: return polarity1_;
        case 0x18: return tstsel_;
        case 0x1C: return status0_;     /* INTSTATCLR0 read = pending. */
        case 0x20: return status1_;
        case 0x24: return 0;            /* INTSET0 write-1-to-set; read unspecified. */
        case 0x28: return 0;            /* INTSET1. */
        case 0x2C: return wake_en0_;
        case 0x30: return wake_en1_;
        case 0x34: return wake_pol0_;
        case 0x38: return wake_pol1_;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Sa1111Intc::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
        case 0x00: inttest0_  = value; return;
        case 0x04: inttest1_  = value; return;
        case 0x08: enable0_   = value; DriveCascadeOutput(false); return;
        case 0x0C: enable1_   = value; DriveCascadeOutput(false); return;
        case 0x10: polarity0_ = value; LatchEdges(false);
                   DriveCascadeOutput(false); return;
        case 0x14: polarity1_ = value; LatchEdges(true);
                   DriveCascadeOutput(false); return;
        case 0x18: tstsel_    = value; return;
        case 0x1C: status0_  &= ~value;           /* INTSTATCLR0 W1C. */
                   DriveCascadeOutput(true); return;
        case 0x20: status1_  &= ~value;
                   DriveCascadeOutput(true); return;
        case 0x24: status0_  |= value;            /* INTSET0 software-set. */
                   DriveCascadeOutput(false); return;
        case 0x28: status1_  |= value;
                   DriveCascadeOutput(false); return;
        case 0x2C: wake_en0_  = value; return;
        case 0x30: wake_en1_  = value; return;
        case 0x34: wake_pol0_ = value; return;
        case 0x38: wake_pol1_ = value; return;
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
    if (source < 32) { raw0_ |= 1u << source;        LatchEdges(false);
                       status0_ |= 1u << source; }
    else             { raw1_ |= 1u << (source - 32); LatchEdges(true);
                       status1_ |= 1u << (source - 32); }
    DriveCascadeOutput(false);
}

void Sa1111Intc::LowerInterrupt(uint8_t source) {
    if (source < 32) { raw0_ &= ~(1u << source);        LatchEdges(false); }
    else             { raw1_ &= ~(1u << (source - 32)); LatchEdges(true);  }
    DriveCascadeOutput(false);
}

/* Whole register/latch image - every member is a guest-observable
   integer (raw lines, edge-detect latches, enable/polarity/test/status/
   wake registers). Order mirrors the field declaration order in the .h. */
void Sa1111Intc::SaveState(StateWriter& w) {
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
    /* Re-drive the cascade line to the SA-1110 GPIO from the restored status,
       which RestoreState alone leaves stale. */
    DriveCascadeOutput(false);
}

REGISTER_SERVICE(Sa1111Intc);
