#include "p2_fpga_serial.h"

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/uart_screen.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>

namespace {

/* PRODUCT_SER (PA 0x10004000, slot 4) + IR_SER (PA 0x10008000,
   slot 3). Same SERB_TX_EN 0→1 dispatch as DEBUG_SER. */

constexpr uint32_t kDramPaBase = 0x0C000000u;

constexpr uint32_t kSlotDmaLow  = 0x00u;
constexpr uint32_t kSlotDmaHigh = 0x04u;
constexpr uint32_t kDmaPairSize = 0x08u;

constexpr uint32_t kProductSerCsrPa     = 0x10004000u;
constexpr uint32_t kProductSerTxDmaPa   = 0x10090810u;
constexpr uint32_t kProductSerRxDmaPa   = 0x10080810u;
constexpr uint32_t kIrSerCsrPa          = 0x10008000u;
constexpr uint32_t kIrSerTxDmaPa        = 0x10070810u;
constexpr uint32_t kIrSerRxDmaPa        = 0x10060810u;

class P2DmaPair : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OdoArm720;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioSize() const override final { return kDmaPairSize; }
    virtual const char* PortName() const = 0;

    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off != kSlotDmaLow && off != kSlotDmaHigh) {
            HaltUnsupportedAccess("WriteHalf", addr, value);
        }
#if CERF_DEV_MODE
        LOG(SocUart, "Odo %s TX_DMA write +0x%02X = 0x%04X\n",
            PortName(), off, value);
#endif
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (off == kSlotDmaLow) dma_low_  = value;
        else                    dma_high_ = value;
    }

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        uint16_t value;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            if      (off == kSlotDmaLow)  value = dma_low_;
            else if (off == kSlotDmaHigh) value = dma_high_;
            else HaltUnsupportedAccess("ReadHalf", addr, 0);
        }
#if CERF_DEV_MODE
        LOG(SocUart, "Odo %s read  +0x%02X -> 0x%04X\n",
            PortName(), off, value);
#endif
        return value;
    }

    /* Reconstruct CPU-side PA. HIGH masked to 8 bits defensively
       (the kernel does the same via `& 0xff` in DEBUG.C line 222);
       DRAM PA base from MAP720.H line 39. */
    uint32_t GetEffectivePa() {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const uint32_t chip_addr =
            (static_cast<uint32_t>(dma_high_ & 0xFFu) << 16) |
            static_cast<uint32_t>(dma_low_);
        return kDramPaBase + chip_addr;
    }

private:
    mutable std::mutex state_mutex_;
    uint16_t           dma_low_  = 0;
    uint16_t           dma_high_ = 0;
};

class OdoArm720ProductSerialTxDma : public P2DmaPair {
public:
    using P2DmaPair::P2DmaPair;
    uint32_t    MmioBase() const override { return kProductSerTxDmaPa; }
    const char* PortName() const override { return "PRODUCT_SER TX_DMA"; }
};

class OdoArm720ProductSerialRxDma : public P2DmaPair {
public:
    using P2DmaPair::P2DmaPair;
    uint32_t    MmioBase() const override { return kProductSerRxDmaPa; }
    const char* PortName() const override { return "PRODUCT_SER RX_DMA"; }
};

class OdoArm720IrSerialTxDma : public P2DmaPair {
public:
    using P2DmaPair::P2DmaPair;
    uint32_t    MmioBase() const override { return kIrSerTxDmaPa; }
    const char* PortName() const override { return "IR_SER TX_DMA"; }
};

class OdoArm720IrSerialRxDma : public P2DmaPair {
public:
    using P2DmaPair::P2DmaPair;
    uint32_t    MmioBase() const override { return kIrSerRxDmaPa; }
    const char* PortName() const override { return "IR_SER RX_DMA"; }
};


/* CSR base for the two ports. Owns CSR A/B state via composition
   on P2FpgaSerial; on SERB_TX_EN rising-edge in CSR B, dispatches
   a byte through the per-port virtual GetTxDmaEffectivePa hook
   and routes the resulting byte to UartScreen + LOG. */
class P2SerialCsrWithTx : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OdoArm720;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioSize() const override final { return kSerialBlockSize; }

    virtual const char* PortName() const = 0;

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (!P2FpgaSerial::IsValidOffset(off)) {
            HaltUnsupportedAccess("ReadHalf", addr, 0);
        }
        const uint16_t value = core_.Read(off);
#if CERF_DEV_MODE
        LOG(SocUart, "Odo %s read  +0x%02X -> 0x%04X\n",
            PortName(), off, value);
#endif
        return value;
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t off = addr - MmioBase();
        if (!P2FpgaSerial::IsValidOffset(off)) {
            HaltUnsupportedAccess("WriteHalf", addr, value);
        }
#if CERF_DEV_MODE
        LOG(SocUart, "Odo %s write +0x%02X = 0x%04X\n",
            PortName(), off, value);
#endif
        const bool tx_en_rising = core_.Write(off, value);
        if (tx_en_rising) DispatchTx();
    }

protected:
    /* Concrete returns the CPU-side PA of the byte the kernel
       wants to TX (reconstructed from this port's TX DMA pointer
       pair). */
    virtual uint32_t GetTxDmaEffectivePa() = 0;

private:
    void DispatchTx() {
        auto& mem        = emu_.Get<EmulatedMemory>();
        const uint32_t pa   = GetTxDmaEffectivePa();
        const uint8_t  byte = mem.ReadByte(pa);
        EmitTxByte(byte);
        core_.SetCsrABits(kSeraTxIntr);
    }

    void EmitTxByte(uint8_t ch) {
        if (ch == '\n') {
            FlushLine();
            return;
        }
        if (ch == '\r') return;
        if (ch >= 0x20 && ch < 0x7F) {
            tx_line_.push_back(static_cast<char>(ch));
        } else {
            char esc[8];
            std::snprintf(esc, sizeof(esc), "\\x%02X", ch);
            tx_line_.append(esc);
        }
        if (tx_line_.size() >= 256) {
            /* Flush if no LF after 256 bytes so a runaway sender
               can't hide subsequent output from view. */
            FlushLine();
        }
    }

    void FlushLine() {
        if (tx_line_.empty()) return;
        emu_.Get<UartScreen>().AddLine(tx_line_);
        LOG(SocUart, "%s TX: %s\n", PortName(), tx_line_.c_str());
        tx_line_.clear();
    }

    P2FpgaSerial core_;
    std::string  tx_line_;
};

class OdoArm720ProductSerial : public P2SerialCsrWithTx {
public:
    using P2SerialCsrWithTx::P2SerialCsrWithTx;
    uint32_t    MmioBase() const override { return kProductSerCsrPa; }
    const char* PortName() const override { return "PRODUCT_SER"; }
protected:
    uint32_t GetTxDmaEffectivePa() override {
        return emu_.Get<OdoArm720ProductSerialTxDma>().GetEffectivePa();
    }
};

class OdoArm720IrSerial : public P2SerialCsrWithTx {
public:
    using P2SerialCsrWithTx::P2SerialCsrWithTx;
    uint32_t    MmioBase() const override { return kIrSerCsrPa; }
    const char* PortName() const override { return "IR_SER"; }
protected:
    uint32_t GetTxDmaEffectivePa() override {
        return emu_.Get<OdoArm720IrSerialTxDma>().GetEffectivePa();
    }
};

}  /* namespace */

REGISTER_SERVICE(OdoArm720ProductSerial);
REGISTER_SERVICE(OdoArm720IrSerial);
REGISTER_SERVICE(OdoArm720ProductSerialTxDma);
REGISTER_SERVICE(OdoArm720ProductSerialRxDma);
REGISTER_SERVICE(OdoArm720IrSerialTxDma);
REGISTER_SERVICE(OdoArm720IrSerialRxDma);
