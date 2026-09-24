#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../tracing/kernel_debug_sink.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <string>

namespace {

constexpr int      kUartCount   = 3;
constexpr uint32_t kUartStride  = 0x4000u;
constexpr uint32_t kRegBlockEnd = 0x2Cu;       /* one past UBRDIV */
constexpr size_t   kRegsPerUart = 11;

constexpr uint32_t kSlotULCON   = 0;
constexpr uint32_t kSlotUCON    = 1;
constexpr uint32_t kSlotUFCON   = 2;
constexpr uint32_t kSlotUMCON   = 3;
constexpr uint32_t kSlotUTRSTAT = 4;
constexpr uint32_t kSlotUERSTAT = 5;
constexpr uint32_t kSlotUFSTAT  = 6;
constexpr uint32_t kSlotUMSTAT  = 7;
constexpr uint32_t kSlotUTXH    = 8;
constexpr uint32_t kSlotURXH    = 9;
constexpr uint32_t kSlotUBRDIV  = 10;

/* UTRSTAT: bit 0 = RX data ready (always 0; no input), bit 1 = TX
   buffer empty (always 1), bit 2 = transmitter empty (always 1). */
constexpr uint32_t kUtrstatTxIdle = 0x6u;

class S3C2410Uart : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::S3c2410;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x50000000u; }
    uint32_t MmioSize() const override { return 0x0000C000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    /* Only the register file is machine state - tx_line_ is a host-side
       console line accumulator, rebuilt as the guest writes. */
    void SaveState(StateWriter& w) override    { w.WriteBytes("storage", storage_, sizeof(storage_)); }
    void RestoreState(StateReader& r) override { r.ReadBytes("storage", storage_, sizeof(storage_)); }

private:
    void     EmitTxByte(int uart_idx, uint8_t ch);

    uint32_t    storage_ [kUartCount][kRegsPerUart] = {};
    std::string tx_line_ [kUartCount];
};

uint32_t S3C2410Uart::ReadWord(uint32_t addr) {
    const uint32_t off       = addr - MmioBase();
    const uint32_t uart_idx  = off / kUartStride;
    const uint32_t reg_off   = off - uart_idx * kUartStride;
    if (uart_idx >= kUartCount || reg_off >= kRegBlockEnd) {
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }
    const uint32_t slot = reg_off / 4u;

    uint32_t value;
    if (slot == kSlotUTRSTAT) {
        value = kUtrstatTxIdle;
    } else if (slot == kSlotURXH) {
        /* No input source - last-received byte stays at 0. */
        value = 0;
    } else {
        value = storage_[uart_idx][slot];
    }
    return value;
}

void S3C2410Uart::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off       = addr - MmioBase();
    const uint32_t uart_idx  = off / kUartStride;
    const uint32_t reg_off   = off - uart_idx * kUartStride;
    if (uart_idx >= kUartCount || reg_off >= kRegBlockEnd) {
        HaltUnsupportedAccess("WriteWord", addr, value);
    }
    const uint32_t slot = reg_off / 4u;

    if (slot == kSlotUTXH) {
        EmitTxByte((int)uart_idx, (uint8_t)(value & 0xFFu));
        return;
    }
    storage_[uart_idx][slot] = value;
}

void S3C2410Uart::EmitTxByte(int uart_idx, uint8_t ch) {
    char tag[8];
    std::snprintf(tag, sizeof(tag), "UART%d", uart_idx);
    /* UART1 is the debug console - only it mirrors to HwScreen. */
    emu_.Get<KernelDebugSink>().EmitChar(static_cast<char>(ch), tx_line_[uart_idx],
                                         tag, true);
}

}  /* namespace */

REGISTER_SERVICE(S3C2410Uart);
