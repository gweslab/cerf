#pragma once

#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/serial/serial_line.h"
#include "pr31x00_serial_wiring.h"
#include "pr31x00_uart_rx_dma.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

class Pr31x00Clock;
class SerialCradle;

class Pr31x00Uart : public Peripheral, public SerialLine {
public:
    explicit Pr31x00Uart(CerfEmulator& emu);
    ~Pr31x00Uart();

    bool ShouldRegister() override;
    void OnReady() override;
    void OnShutdown() override;

    uint32_t MmioSize() const override { return 0x18u; }

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void PushRx(const uint8_t* data, size_t n) override;
    bool RxEmpty() const override;
    void SetRxDrainCallback(RxDrainFn cb) override;
    void SetModemInputs(bool cts, bool dsr, bool ri, bool dcd) override;
    LineConfig GetLineConfig() const override;
    void SetLineConfigCallback(LineConfigFn cb) override;
    void SetEndpoint(SerialEndpoint* ep) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

protected:
    virtual const char* TxSource() const = 0;

    /* Interrupt Status 2 UARTRXINT bit, verified from serial.dll sub_1861B3C
       (UART A RX-int mask 0x80000000, UART B 0x200000) + nk.exe OAL table
       0x9F433AD4 (Status2 bit 31 -> SYSINTR 12). */
    virtual uint32_t RxIntBit() const = 0;

    /* Interrupt Status 2 UARTAEMPTYINT/UARTBEMPTYINT bit (TMPR3911 §8.3.2: THR
       and Transmit Shift Register both empty). serial.dll paces byte-by-byte
       PIO TX on it (sub_1862158 checks Status2 & this bit), so it must fire per
       drained TX byte or interrupt-driven TX stalls after byte 1. */
    virtual uint32_t TxEmptyIntBit() const = 0;

    /* Interrupt Status 2 UARTATXINT<26>/UARTBTXINT<16> (TMPR3911 §8.3.2);
       serial.dll PutBytes TX-pace mask [HWObj+0x94]=0x04000000/0x00010000
       (sub_1861B3C). */
    virtual uint32_t TxAvailIntBit() const = 0;

    /* Interrupt Status 2 UARTADMAFULLINT<23>/UARTBDMAFULLINT<13> and
       UARTADMAHALFINT<22>/UARTBDMAHALFINT<12> (TMPR3911 §8.3.2): the receive DMA's
       address counter reaching the end and the mid point of the buffer. */
    virtual uint32_t DmaFullIntBit() const = 0;
    virtual uint32_t DmaHalfIntBit() const = 0;

    /* ENUARTACLK<1> / ENUARTBCLK<0> in Clock Control (TMPR3911 §6.3.1 p6-6). */
    virtual uint32_t ClockEnableBit() const = 0;

private:
    void       WriteCtl1(uint32_t addr, uint32_t value);
    void       WriteTxHold(uint32_t addr, uint32_t value);
    LineConfig ComputeLineConfigLocked() const;
    Pr31x00UartRxDma::LineTiming LineTimingLocked() const;
    void       OnRxLineIdle();
    void       RaiseRxInts(const Pr31x00UartRxDma::RxInts& ints);
    void       OnMfioOut(uint32_t mfio_dout, uint32_t out_mask);
    void       OnIoOut(uint32_t io_dout, uint32_t out_mask);
    bool       RecomputeControlLocked(bool& dtr, bool& rts);
    void       NotifyControlLines(bool dtr, bool rts);
    bool       AssertedLocked(const Pr31x00SerialPin& p) const;
    void       DriveModemInput(const Pr31x00SerialPin& p, bool asserted);
    void       FireLineConfig();

    uint32_t    ctl1_ = 0;
    std::string tx_line_;

    std::optional<Pr31x00SerialModem> modem_;

    mutable std::mutex mu_;

    std::recursive_mutex endpoint_mu_;
    SerialEndpoint*      endpoint_ = nullptr;

    std::unique_ptr<Pr31x00UartRxDma> rx_dma_;

    uint32_t ctl2_baud_ = 0;
    uint32_t   fired_baud_ = 0;
    LineConfig line_cfg_;

    Pr31x00Clock* module_clock_ = nullptr;

    RxDrainFn    rx_drain_cb_;
    LineConfigFn line_cfg_cb_;

    uint32_t mfio_dout_     = 0;
    uint32_t mfio_out_mask_ = 0;
    uint32_t io_dout_       = 0;
    uint32_t io_out_mask_   = 0;

    bool dtr_ = false;
    bool rts_ = false;

    std::unique_ptr<SerialCradle> cradle_;
};
