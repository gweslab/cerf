#pragma once

#include "../pxa2xx/pxa2xx_uart16550.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"

#include <cstdint>

class Pxa27xUart16550 : public Pxa2xxUart16550 {
public:
    explicit Pxa27xUart16550(CerfEmulator& emu)
        : Pxa2xxUart16550(emu, Config{
              /* Intel PXA27x Developer's Manual 280000-001 Table 10-8 (page 10-16)
                 IER: bits 31:8 reserved, bits 7:0 DMAE, UUE, NRZE, RTOIE, MIE,
                 RLSE, TIE, RAVIE. */
              .ier_mask = 0xFFu,
              /* Table 10-18 (page 10-30) MCR bit 3 OUT2: "OUT2 connects the UART's
                 interrupt output to the interrupt controller unit. When LOOP is
                 clear: 0 = UART interrupt is disabled." */
              .irq_gate_mcr = 0x08u,
              /* Table 10-8 IER bit 6 UUE: "0 = The unit is disabled." */
              .irq_gate_ier = 0x40u,
              /* Table 10-12 (page 10-21) FCR bits 7:6 ITL: "0b00 = 1 byte or more
                 in FIFO causes interrupt", 0b01 = 8, 0b10 = 16, 0b11 = 32. */
              .rx_trigger = {1u, 8u, 16u, 32u},
              /* Table 10-8 IER bit 4 RTOIE: "Receiver Time-Out Interrupt Enable
                 (Source IIR[TOD])". */
              .cti_ier_bit = 0x10u,
          }) {}

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }
};
