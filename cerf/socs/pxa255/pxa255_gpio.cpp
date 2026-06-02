#include "pxa255_gpio.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

bool Pxa255Gpio::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetSoc() == SocFamily::PXA25x;
}

void Pxa255Gpio::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void Pxa255Gpio::SetInputLevel(uint32_t gpio, bool high) {
    const uint32_t bank = gpio / 32u;
    const uint32_t bit  = 1u << (gpio % 32u);
    if (bank >= 3u) return;
    if (high) in_[bank] |= bit;
    else      in_[bank] &= ~bit;
}

uint32_t Pxa255Gpio::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if ((off & 3u) != 0u) HaltUnsupportedAccess("ReadWord", addr, 0);
    if (off <= 0x08) {                                                 /* GPLR (§4.1.3.1). */
        const uint32_t i = off / 4u;
        return (out_[i] & gpdr_[i]) | (in_[i] & ~gpdr_[i]);            /* output latch | input level. */
    }
    if (off >= 0x0C && off <= 0x14) return gpdr_[(off - 0x0C) / 4u];   /* GPDR. */
    if (off >= 0x18 && off <= 0x2C) return 0u;                         /* GPSR/GPCR write-only. */
    if (off >= 0x30 && off <= 0x38) return grer_[(off - 0x30) / 4u];   /* GRER. */
    if (off >= 0x3C && off <= 0x44) return gfer_[(off - 0x3C) / 4u];   /* GFER. */
    if (off >= 0x48 && off <= 0x50) return 0u;                         /* GEDR: no edges generated. */
    if (off >= 0x54 && off <= 0x68) return gafr_[(off - 0x54) / 4u];   /* GAFR. */
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Pxa255Gpio::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if ((off & 3u) != 0u) HaltUnsupportedAccess("WriteWord", addr, value);
    if (off <= 0x08) return;                                           /* GPLR read-only. */
    if (off >= 0x0C && off <= 0x14) { gpdr_[(off - 0x0C) / 4u] = value;  return; }
    /* GPSR/GPCR (Table 4-9/4-13): writing 1 sets/clears the output latch for a
       pin regardless of its GPDR direction (the latch holds the value; the pin
       drives it only when configured as output). Not masked by GPDR. */
    if (off >= 0x18 && off <= 0x20) { out_[(off - 0x18) / 4u] |= value;  return; } /* GPSR. */
    if (off >= 0x24 && off <= 0x2C) { out_[(off - 0x24) / 4u] &= ~value; return; } /* GPCR. */
    if (off >= 0x30 && off <= 0x38) { grer_[(off - 0x30) / 4u] = value;  return; }
    if (off >= 0x3C && off <= 0x44) { gfer_[(off - 0x3C) / 4u] = value;  return; }
    if (off >= 0x48 && off <= 0x50) return;                            /* GEDR W1C: status 0. */
    if (off >= 0x54 && off <= 0x68) { gafr_[(off - 0x54) / 4u] = value; return; }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

REGISTER_SERVICE(Pxa255Gpio);
