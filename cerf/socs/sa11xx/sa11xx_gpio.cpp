#include "sa11xx_gpio.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "sa11xx_intc.h"

bool Sa11xxGpio::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
}

void Sa11xxGpio::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void Sa11xxGpio::DriveInputPin(uint32_t pin, bool level) {
    const uint32_t bit = 1u << pin;
    std::unique_lock<std::mutex> lk(mtx_);
    const uint32_t old = input_state_;
    input_state_ = level ? (input_state_ | bit) : (input_state_ & ~bit);
    if (old == input_state_) return;

    /* §9.1.1.5: an edge matching GRER/GFER latches the GEDR bit. Edge
       detect applies to the pin state regardless of direction; CERF only
       drives input pins here. */
    const bool rising = level;
    const bool latched =
        (rising && (grer_ & bit)) || (!rising && (gfer_ & bit));
    if (latched) {
        gedr_ |= bit;
        PublishEdgeSourcesLocked();
    }
}

/* ICPR sources 0..10 follow GEDR bits 0..10; source 11 is the OR of GEDR
   27..11 (§9.2.1.1). GEDR is the latch, so the ICPR view is a level. */
void Sa11xxGpio::PublishEdgeSourcesLocked() {
    const uint32_t gedr = gedr_;
    auto& intc = emu_.Get<Sa11xxIntc>();
    intc.SetSourceLevel(0x7FFu, gedr & 0x7FFu);
    intc.SetSourceLevel(1u << 11,
                        (gedr & 0x0FFFF800u) ? (1u << 11) : 0u);
}

uint32_t Sa11xxGpio::ReadReg(uint32_t off) {
    std::unique_lock<std::mutex> lk(mtx_);
    switch (off) {
        case 0x00: return ReadGplrLocked();                    /* GPLR R-O */
        case 0x04: return gpdr_ & kPinMask;                    /* GPDR R/W */
        case 0x08: return 0;                                   /* GPSR W-O, read unpredictable */
        case 0x0C: return 0;                                   /* GPCR W-O, read unpredictable */
        case 0x10: return grer_ & kPinMask;                    /* GRER R/W */
        case 0x14: return gfer_ & kPinMask;                    /* GFER R/W */
        case 0x18: return gedr_ & kPinMask;                    /* GEDR R/W (W1C) */
        case 0x1C: return gafr_ & kPinMask;                    /* GAFR R/W */
        default:   return 0;
    }
}

void Sa11xxGpio::WriteReg(uint32_t off, uint32_t value) {
    const uint32_t v = value & kPinMask;
    std::unique_lock<std::mutex> lk(mtx_);
    switch (off) {
        case 0x00: break;                                      /* GPLR R-O, writes ignored */
        case 0x04: gpdr_ = v; break;
        case 0x08: output_state_ = (output_state_ | (v & gpdr_)) & kPinMask; break;
        case 0x0C: output_state_ &= ~(v & gpdr_); break;
        case 0x10: grer_ = v; break;
        case 0x14: gfer_ = v; break;
        case 0x18: gedr_ &= ~v; PublishEdgeSourcesLocked(); break;  /* W1C */
        case 0x1C: gafr_ = v; break;
        default:   break;
    }
}

uint8_t Sa11xxGpio::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (base > 0x1C) HaltUnsupportedAccess("ReadByte", addr, 0);
    return static_cast<uint8_t>((ReadReg(base) >> shift) & 0xFFu);
}

uint32_t Sa11xxGpio::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off > 0x1C || (off & 0x3u) != 0) HaltUnsupportedAccess("ReadWord", addr, 0);
    return ReadReg(off);
}

void Sa11xxGpio::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (base > 0x1C) HaltUnsupportedAccess("WriteByte", addr, value);
    const uint32_t cur     = ReadReg(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    WriteReg(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Sa11xxGpio::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off > 0x1C || (off & 0x3u) != 0) HaltUnsupportedAccess("WriteWord", addr, value);
    WriteReg(off, value);
}

void Sa11xxGpio::SaveState(StateWriter& w) {
    std::unique_lock<std::mutex> lk(mtx_);
    w.Write("output_state", output_state_);
    w.Write("input_state", input_state_);
    w.Write("gpdr", gpdr_);
    w.Write("grer", grer_);
    w.Write("gfer", gfer_);
    w.Write("gedr", gedr_);
    w.Write("gafr", gafr_);
}

void Sa11xxGpio::RestoreState(StateReader& r) {
    std::unique_lock<std::mutex> lk(mtx_);
    r.Read("output_state", output_state_);
    r.Read("input_state", input_state_);
    r.Read("gpdr", gpdr_);
    r.Read("grer", grer_);
    r.Read("gfer", gfer_);
    r.Read("gedr", gedr_);
    r.Read("gafr", gafr_);
}

void Sa11xxGpio::PostRestore() {
    /* Re-establish the GEDR->ICPR source levels into the INTC, which the
       INTC's own RestoreState can't know about. */
    std::unique_lock<std::mutex> lk(mtx_);
    PublishEdgeSourcesLocked();
}

REGISTER_SERVICE(Sa11xxGpio);
