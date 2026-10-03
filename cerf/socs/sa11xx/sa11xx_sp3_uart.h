#pragma once

#include "sa11xx_uart_base.h"

/* SA-1110 §11.11 SP3 UART (PA 0x80050000). On the SmartBook G138 the companion
   MPU (keyboard/touch/battery controller) hangs off this port as "COM3:"; its
   board service installs a TX listener and pushes RX packets through the base
   hooks, the same way the iPaq MicroP uses SP1. */

class Sa11xxSp3Uart : public Sa11xxUartBase {
public:
    using Sa11xxUartBase::Sa11xxUartBase;

    uint32_t MmioBase() const override { return 0x80050000u; }

protected:
    const char* ChannelName()  const override { return "UART3"; }
    /* SA-1110 Dev Man Table 11-3 (Peripheral Unit Interrupt Numbers):
       Ser1-UART=15, Ser2-ICP=16, Ser3-UART=17. Needed so a pushed RX byte
       wakes the guest serial driver's ISR - the MPU stream is interrupt-driven. */
    int         IntcSourceBit() const override { return 17; }
    /* SA-1110 Table 11-6 (printed 11-9): Serial port 3 UART transmit DS 1000, receive DS 1001. */
    uint32_t    TransmitDeviceSelect() const override { return 0x8u; }
    uint32_t    ReceiveDeviceSelect() const override { return 0x9u; }
};
