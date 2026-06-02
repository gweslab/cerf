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

/* DispatchTx hooks SERB_TX_EN 0→1 (DEBUG.C OEMWriteDebugByte
   step 4 of 213-237) — by then DMA pointer writes + byte write
   already landed in DRAM. Hooking earlier or later misses the
   byte. Chip strips bits 31:26 of DMA address per DEBUG.C:38-39. */

constexpr uint32_t kDramPaBase        = 0x0C000000u;

constexpr uint32_t kSlotDmaLow        = 0x00u;
constexpr uint32_t kSlotDmaHigh       = 0x04u;
constexpr uint32_t kDmaPairSize       = 0x08u;

constexpr uint32_t kDebugSerCsrPa     = 0x10002000u;
constexpr uint32_t kDebugSerRxDmaPa   = 0x10000810u;
constexpr uint32_t kDebugSerTxDmaPa   = 0x10010810u;

class DmaPointerPair : public Peripheral {
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
        LOG(SocUart, "Odo %s write +0x%02X = 0x%04X\n",
            PortName(), off, value);
#endif
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (off == kSlotDmaLow) dma_low_  = value;
        else                    dma_high_ = value;
    }

    /* Recombine LOW + HIGH into a chip-effective 24-bit address,
       add DRAM PA base for the CPU-side PA. HIGH masked to 8 bits
       defensively (the kernel already does this in OEMWriteDebugByte
       line 222 via `& 0xff`). */
    uint32_t GetEffectivePa() {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const uint32_t chip_addr =
            (static_cast<uint32_t>(dma_high_ & 0xFFu) << 16) |
            static_cast<uint32_t>(dma_low_);
        return kDramPaBase + chip_addr;
    }

protected:
    /* Subclass-callable accessors for ReadHalf overrides that want
       to return the stored value rather than halt. */
    uint16_t StoredLow()  {
        std::lock_guard<std::mutex> lk(state_mutex_);
        return dma_low_;
    }
    uint16_t StoredHigh() {
        std::lock_guard<std::mutex> lk(state_mutex_);
        return dma_high_;
    }

private:
    mutable std::mutex state_mutex_;
    uint16_t           dma_low_  = 0;
    uint16_t           dma_high_ = 0;
};

class OdoArm720DebugSerialTxDma : public DmaPointerPair {
public:
    using DmaPointerPair::DmaPointerPair;
    uint32_t    MmioBase() const override { return kDebugSerTxDmaPa; }
    const char* PortName() const override { return "DEBUG_SER TX_DMA"; }

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        /* Kernel never reads TX DMA pointers per DEBUG.C lines
           221-222 (write-only). Halt loudly. */
        LOG(Caution, "Odo DEBUG_SER TX_DMA: read at +0x%02X — kernel "
                "never reads TX DMA pointers per DEBUG.C lines "
                "221-222; unexpected codepath\n", off);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
};

class OdoArm720DebugSerialRxDma : public DmaPointerPair {
public:
    using DmaPointerPair::DmaPointerPair;
    uint32_t    MmioBase() const override { return kDebugSerRxDmaPa; }
    const char* PortName() const override { return "DEBUG_SER RX_DMA"; }

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        /* DEBUG.C:258,260 OEMReadDebugByte polls — silent-zero
           here makes kernel spin forever waiting for RX. */
        LOG(Caution, "Odo DEBUG_SER RX_DMA: read at +0x%02X — kernel "
                "is polling for RX bytes via OEMReadDebugByte "
                "(DEBUG.C line 258/260); RX is not implemented.\n",
                off);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
};


/* DEBUG_SER CSR peripheral — owns CSR A / CSR B state through the
   shared P2FpgaSerial helper. Detects SERB_TX_EN rising-edge on CSR
   B writes and dispatches one byte via UartScreen + LOG. */
class OdoArm720DebugSerial : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OdoArm720;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        LOG(SocUart, "Odo DEBUG_SER: TX implemented "
                "(UartScreen + cerf.log); RX not implemented; "
                "OEMReadDebugByte halts on RX DMA read.\n");
    }

    uint32_t MmioBase() const override { return kDebugSerCsrPa; }
    uint32_t MmioSize() const override { return kSerialBlockSize; }

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (!P2FpgaSerial::IsValidOffset(off)) {
            HaltUnsupportedAccess("ReadHalf", addr, 0);
        }
        const uint16_t value = core_.Read(off);
        return value;
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t off = addr - MmioBase();
        if (!P2FpgaSerial::IsValidOffset(off)) {
            HaltUnsupportedAccess("WriteHalf", addr, value);
        }
        const bool tx_en_rising = core_.Write(off, value);
        if (tx_en_rising) DispatchTx();
    }

private:
    void DispatchTx() {
        auto& tx_dma = emu_.Get<OdoArm720DebugSerialTxDma>();
        auto& mem    = emu_.Get<EmulatedMemory>();
        const uint32_t pa   = tx_dma.GetEffectivePa();
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
            /* No-LF runaway: flush so a binary blob doesn't
               block visibility of later log lines. */
            FlushLine();
        }
    }

    void FlushLine() {
        if (tx_line_.empty()) return;
        emu_.Get<UartScreen>().AddLine(tx_line_);
        LOG(SocUart, "DEBUG_SER TX: %s\n", tx_line_.c_str());
        tx_line_.clear();
    }

    P2FpgaSerial core_;
    std::string  tx_line_;
};

}  /* namespace */

REGISTER_SERVICE(OdoArm720DebugSerial);
REGISTER_SERVICE(OdoArm720DebugSerialTxDma);
REGISTER_SERVICE(OdoArm720DebugSerialRxDma);
