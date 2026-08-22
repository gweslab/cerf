#include "pxa27x_gpio.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"

bool Pxa27xGpio::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSoc() == SocFamily::PXA27x;
}

Pxa2xxGpio::Reg Pxa27xGpio::Decode(uint32_t off, uint32_t* index) const {
    /* Intel PXA27x Developer's Manual 280000-001 Table 24-41 (page 24-34),
       GPIO<120:96> above the 0x40E0_0074-0x40E0_00FC reserved gap: "0x40E0_0100
       GPLR3", "0x40E0_010C GPDR3", "0x40E0_0118 GPSR3", "0x40E0_0124 GPCR3",
       "0x40E0_0130 GRER3", "0x40E0_013C GFER3", "0x40E0_0148 GEDR3". */
    static constexpr struct { uint32_t off; Reg reg; } kBank3[] = {
        {0x100u, Reg::kGplr}, {0x10Cu, Reg::kGpdr}, {0x118u, Reg::kGpsr},
        {0x124u, Reg::kGpcr}, {0x130u, Reg::kGrer}, {0x13Cu, Reg::kGfer},
        {0x148u, Reg::kGedr},
    };
    for (const auto& e : kBank3) {
        if (off == e.off) {
            *index = 3u;
            return e.reg;
        }
    }
    return Pxa2xxGpio::Decode(off, index);
}

REGISTER_SERVICE(Pxa27xGpio);
