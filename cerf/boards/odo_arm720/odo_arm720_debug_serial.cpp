#include "p2_fpga_serial.h"

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "odo_id.h"
#include "../../cpu/emulated_memory.h"
#include "../../tracing/kernel_debug_sink.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>

namespace {

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
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Odo;
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

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        w.Write("dma_low", dma_low_);
        w.Write("dma_high", dma_high_);
    }
    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        r.Read("dma_low", dma_low_);
        r.Read("dma_high", dma_high_);
    }

protected:
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
        LOG(Caution, "Odo DEBUG_SER TX_DMA: read at +0x%02X - the TX "
                "DMA pointers are write-only; unexpected codepath\n",
                off);
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
        LOG(Caution, "Odo DEBUG_SER RX_DMA: read at +0x%02X - the "
                "kernel is polling for RX bytes; RX is not "
                "implemented.\n", off);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
};


/* DEBUG_SER CSR peripheral - owns CSR A / CSR B state through the
   shared P2FpgaSerial helper. Detects SERB_TX_EN rising-edge on CSR
   B writes and dispatches one byte via HwScreen + LOG. */
class OdoArm720DebugSerial : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Odo;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        LOG(SocUart, "Odo DEBUG_SER: TX implemented "
                "(HwScreen + cerf.log); RX not implemented; "
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

    void SaveState(StateWriter& w) override { core_.SaveState(w); }
    void RestoreState(StateReader& r) override { core_.RestoreState(r); }

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
        emu_.Get<KernelDebugSink>().EmitLine(tx_line_, "DEBUG_SER");
        tx_line_.clear();
    }

    P2FpgaSerial core_;
    std::string  tx_line_;
};

}  /* namespace */

REGISTER_SERVICE(OdoArm720DebugSerial);
REGISTER_SERVICE(OdoArm720DebugSerialTxDma);
REGISTER_SERVICE(OdoArm720DebugSerialRxDma);
