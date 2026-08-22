#pragma once

#include "../pxa2xx/pxa2xx_uart16550.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"

#include <cstdint>

/* PXA255 on-chip 16550 UART (Ch10): word register stride; the TX interrupt is
   gated by UUE (IER.6, Table 10-8) and the ISR at index 8 (offset 0x20) selects
   IrDA/UART mode. FFUART/BTUART/STUART differ only by base + INTC source
   (Table 4-35). */
class Pxa255Uart16550 : public Pxa2xxUart16550 {
public:
    /* IER bits 7:4 are DMAE/UUE/NRZE/RTOIE, "used differently from the standard 16550
       register definition" (Table 10-7): UUE gates the unit ("0 - The unit is disabled")
       and RTOIE separately enables the character-timeout interrupt. The 64-byte FIFOs
       trigger at 1/8/16/32 bytes (Table 10-11, FCR[ITL]). */
    explicit Pxa255Uart16550(CerfEmulator& emu)
        : Pxa2xxUart16550(emu, Config{/*ier_mask=*/0xFFu,
                                      /*irq_gate_mcr=*/0u,
                                      /*irq_gate_ier=*/0x40u,
                                      /*rx_trigger=*/{1u, 8u, 16u, 32u},
                                      /*cti_ier_bit=*/0x10u}) {}

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }
};
