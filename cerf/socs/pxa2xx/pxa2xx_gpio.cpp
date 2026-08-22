#include "pxa2xx_gpio.h"

#include "pxa2xx_intc.h"

#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

void Pxa2xxGpio::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

Pxa2xxGpio::Reg Pxa2xxGpio::Decode(uint32_t off, uint32_t* index) const {
    static constexpr struct { uint32_t base; Reg reg; } kInline[] = {
        {0x00u, Reg::kGplr}, {0x0Cu, Reg::kGpdr}, {0x18u, Reg::kGpsr},
        {0x24u, Reg::kGpcr}, {0x30u, Reg::kGrer}, {0x3Cu, Reg::kGfer},
        {0x48u, Reg::kGedr},
    };
    for (const auto& e : kInline) {
        if (off >= e.base && off < e.base + 0x0Cu) {
            *index = (off - e.base) / 4u;
            return e.reg;
        }
    }
    if (off >= 0x54u && off < 0x54u + 4u * GafrCount()) {
        *index = (off - 0x54u) / 4u;
        return Reg::kGafr;
    }
    return Reg::kNone;
}

void Pxa2xxGpio::UpdateIntcLocked() {
    /* Intel PXA27x Developer's Manual 280000-001 Table 25-2 (page 25-5):
       "IP[8] GPIO GPIO<0> detects an edge 8", "IP[9] GPIO GPIO<1> detects an
       edge 9", "IP[10] GPIO GPIO_x 'OR' of the GPIO edge detect (except 0 and
       1) 10". */
    uint32_t level = 0;
    if (gedr_[0] & 0x1u) level |= (1u << 8);
    if (gedr_[0] & 0x2u) level |= (1u << 9);
    uint32_t coll = 0;
    for (uint32_t b = 0; b < BankCount(); ++b) coll |= gedr_[b] & CollectiveMask(b);
    if (coll) level |= (1u << 10);
    static_cast<Pxa2xxIntc&>(emu_.Get<IrqController>())
        .SetSourceLevel((1u << 8) | (1u << 9) | (1u << 10), level);
}

void Pxa2xxGpio::ApplyEdgesLocked(const uint32_t* before) {
    /* Table 24-17 (page 24-19) GRER0 0x40E0_0030: "1 = Sets corresponding GEDR
       status bit when a rising edge is detected on the GPIO pin." Table 24-21
       (page 24-21) GFER0 0x40E0_003C: "1 = Sets corresponding GEDR status bit
       when a falling edge is detected on the GPIO pin." */
    for (uint32_t b = 0; b < BankCount(); ++b) {
        const uint32_t now  = PinLevelLocked(b);
        const uint32_t rose = now & ~before[b] & grer_[b];
        const uint32_t fell = ~now & before[b] & gfer_[b];
        gedr_[b] |= (rose | fell);
    }
    UpdateIntcLocked();
}

void Pxa2xxGpio::SetInputLevel(uint32_t gpio, bool high) {
    const uint32_t bank = gpio / 32u;
    if (bank >= BankCount()) return;
    const uint32_t bit = 1u << (gpio % 32u);
    std::lock_guard<std::mutex> g(mtx_);
    uint32_t before[kMaxBanks] = {};
    for (uint32_t b = 0; b < BankCount(); ++b) before[b] = PinLevelLocked(b);
    if (high) in_[bank] |= bit;
    else      in_[bank] &= ~bit;
    ApplyEdgesLocked(before);
}

uint32_t Pxa2xxGpio::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if ((off & 3u) != 0u) HaltUnsupportedAccess("ReadWord", addr, 0);
    uint32_t i = 0;
    const Reg reg = Decode(off, &i);
    std::lock_guard<std::mutex> g(mtx_);
    switch (reg) {
    case Reg::kGplr: {
        uint32_t v = PinLevelLocked(i);
        if (serial_slave_) v |= serial_slave_->DriveGplr(i);
        return v;
    }
    case Reg::kGpdr: return gpdr_[i];
    /* Section 24.5.2 (page 24-14): "The GPIO Pin-Output Set registers
       (GPSR0/1/2/3) and GPIO Pin-Output Clear registers (GPCR0/1/2/3) are
       write-only registers. Reads return unpredictable values." */
    case Reg::kGpsr:
    case Reg::kGpcr: return 0u;
    case Reg::kGrer: return grer_[i];
    case Reg::kGfer: return gfer_[i];
    case Reg::kGedr: return gedr_[i];
    case Reg::kGafr: return gafr_[i];
    case Reg::kNone: break;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa2xxGpio::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if ((off & 3u) != 0u) HaltUnsupportedAccess("WriteWord", addr, value);
    uint32_t i = 0;
    const Reg reg = Decode(off, &i);
    std::lock_guard<std::mutex> g(mtx_);
    switch (reg) {
    /* Table 24-33 (page 24-29) GPLR0 0x40E0_0000, "<31:9> R PL x": "This
       read-only field indicates the current value of each GPIO." */
    case Reg::kGplr: return;
    case Reg::kGrer: grer_[i] = value; return;
    case Reg::kGfer: gfer_[i] = value; return;
    /* Section 24.5.6 (page 24-30): "Once a GEDR bit is set by an edge event, the
       bit remains set until it is cleared by writing a one to the status bit.
       Writing a zero to a GEDR status bit has no effect." Table 24-37 (page
       24-31) GEDR0 0x40E0_0048. */
    case Reg::kGedr:
        gedr_[i] &= ~value;
        UpdateIntcLocked();
        return;
    case Reg::kGafr: gafr_[i] = value; return;
    /* Table 24-9 (page 24-14) GPSR0 0x40E0_0018: "1 = If pin configured as an
       output, set pin level high (one)." Section 24.5.2 (page 24-14): "Writing
       0b0 to any of the GPSR or GPCR bits has no effect on the state of the
       pin." */
    case Reg::kGpdr:
    case Reg::kGpsr:
    case Reg::kGpcr: {
        uint32_t before[kMaxBanks] = {};
        for (uint32_t b = 0; b < BankCount(); ++b) before[b] = PinLevelLocked(b);
        if      (reg == Reg::kGpdr) gpdr_[i] = value;
        else if (reg == Reg::kGpsr) out_[i] |= value;
        else                        out_[i] &= ~value;
        ApplyEdgesLocked(before);
        if (serial_slave_) serial_slave_->OnGuestWrite(off, value);
        return;
    }
    case Reg::kNone: break;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Pxa2xxGpio::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> g(mtx_);
    const size_t nb = BankCount() * sizeof(uint32_t);
    w.WriteBytes(in_,   nb);
    w.WriteBytes(out_,  nb);
    w.WriteBytes(gpdr_, nb);
    w.WriteBytes(grer_, nb);
    w.WriteBytes(gfer_, nb);
    w.WriteBytes(gedr_, nb);
    w.WriteBytes(gafr_, GafrCount() * sizeof(uint32_t));
    if (serial_slave_) serial_slave_->SaveState(w);
}

void Pxa2xxGpio::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> g(mtx_);
    const size_t nb = BankCount() * sizeof(uint32_t);
    r.ReadBytes(in_,   nb);
    r.ReadBytes(out_,  nb);
    r.ReadBytes(gpdr_, nb);
    r.ReadBytes(grer_, nb);
    r.ReadBytes(gfer_, nb);
    r.ReadBytes(gedr_, nb);
    r.ReadBytes(gafr_, GafrCount() * sizeof(uint32_t));
    if (serial_slave_) serial_slave_->RestoreState(r);
}
