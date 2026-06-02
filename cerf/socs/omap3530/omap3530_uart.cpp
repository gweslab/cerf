#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/uart_screen.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../boards/board_detector.h"
#include "omap3530_sdma.h"

#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>

namespace {

constexpr uint32_t kUartSize = 0x00001000u;  /* 4 KB per UART */

/* Register offsets within a bank. */
constexpr uint32_t kOffRhrThr = 0x00;
constexpr uint32_t kOffIerDll = 0x04;
constexpr uint32_t kOffIirFcr = 0x08;
constexpr uint32_t kOffLcr    = 0x0C;
constexpr uint32_t kOffMcr    = 0x10;
constexpr uint32_t kOffLsr    = 0x14;
constexpr uint32_t kOffMsr    = 0x18;
constexpr uint32_t kOffSpr    = 0x1C;
constexpr uint32_t kOffMdr1   = 0x20;
constexpr uint32_t kOffTxfll  = 0x28;
constexpr uint32_t kOffRxfll  = 0x2C;
constexpr uint32_t kOffTxflh  = 0x30;
constexpr uint32_t kOffScr    = 0x40;
constexpr uint32_t kOffSsr    = 0x44;
constexpr uint32_t kOffSysc   = 0x54;
constexpr uint32_t kOffSyss   = 0x58;
constexpr uint32_t kOffWer    = 0x5C;

constexpr uint8_t kLsrTxReady      = 0x60u;  /* TX_SR_E | TX_FIFO_E */
constexpr uint8_t kLcrDlabMask     = 0x80u;
constexpr uint8_t kSsrIdleVal      = 0x00u;  /* TX FIFO never full */
constexpr uint8_t kSyssRstDoneVal  = 0x01u;  /* reset always complete */
constexpr uint8_t kSyscRstBit      = 0x02u;
constexpr uint8_t kIirNoIntPending = 0x01u;

constexpr uint8_t kScrDmaModeCtl   = 1u << 0;
constexpr uint8_t kScrDmaMode2Mask = 0x6u;
constexpr uint8_t kFcrDmaMode      = 1u << 3;
constexpr uint8_t kFcrFifoEn       = 1u << 0;

class Omap3530UartBank : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::OMAP3530;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioSize() const override { return kUartSize; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

protected:
    /* Per-bank log tag used in "UART<N> TX: <line>" output. */
    virtual int      LogTag() const = 0;
    virtual uint32_t TxSyncSource() const = 0;
    virtual uint32_t RxSyncSource() const = 0;

private:
    uint8_t ReadByteLocked (uint32_t addr, uint32_t off);
    void    WriteByteLocked(uint32_t addr, uint32_t off, uint8_t value);
    void    EmitTxByte(uint8_t ch);
    bool    IsTxDmaActive() const;
    bool    IsRxDmaActive() const;
    void    FlushPendingDmaReqs(bool fire_tx, bool fire_rx);

    mutable std::mutex state_mutex_;
    uint8_t     ier_   = 0;
    uint8_t     fcr_   = 0;
    uint8_t     lcr_   = 0;
    uint8_t     mcr_   = 0;
    uint8_t     mdr1_  = 0;  /* UART16 mode at reset */
    uint8_t     scr_   = 0;
    uint8_t     msr_   = 0;
    uint8_t     spr_   = 0;
    uint8_t     dll_   = 0;
    uint8_t     dlh_   = 0;
    uint8_t     sysc_  = 0;
    uint8_t     wer_   = 0;
    bool        pending_tx_dma_req_ = false;
    bool        pending_rx_dma_req_ = false;
    std::string tx_line_;
};

bool Omap3530UartBank::IsTxDmaActive() const {
    if (scr_ & kScrDmaModeCtl) {
        const uint8_t mode2 = (scr_ & kScrDmaMode2Mask) >> 1;
        return mode2 == 1u || mode2 == 3u;
    }
    return (fcr_ & kFcrFifoEn) && (fcr_ & kFcrDmaMode);
}

bool Omap3530UartBank::IsRxDmaActive() const {
    if (scr_ & kScrDmaModeCtl) {
        const uint8_t mode2 = (scr_ & kScrDmaMode2Mask) >> 1;
        return mode2 == 1u || mode2 == 2u;
    }
    return (fcr_ & kFcrFifoEn) && (fcr_ & kFcrDmaMode);
}

void Omap3530UartBank::FlushPendingDmaReqs(bool fire_tx, bool fire_rx) {
    if (fire_tx) emu_.Get<Omap3530Sdma>().RaiseSyncEvent(TxSyncSource());
    if (fire_rx) emu_.Get<Omap3530Sdma>().RaiseSyncEvent(RxSyncSource());
}

uint8_t Omap3530UartBank::ReadByteLocked(uint32_t addr, uint32_t off) {
    const bool dlab = (lcr_ & kLcrDlabMask) != 0;
    switch (off) {
    case kOffRhrThr: return dlab ? dll_ : 0u;  /* RHR has no source */
    case kOffIerDll: return dlab ? dlh_ : ier_;
    case kOffIirFcr: return kIirNoIntPending;
    case kOffLcr:    return lcr_;
    case kOffMcr:    return mcr_;
    case kOffLsr:    return kLsrTxReady;
    case kOffMsr:    return msr_;
    case kOffSpr:    return spr_;
    case kOffMdr1:   return mdr1_;
    case kOffTxfll:  return 0u;             /* TX FIFO empty */
    case kOffRxfll:  return 0u;             /* RX FIFO empty */
    case kOffTxflh:  return 0u;
    case kOffScr:    return scr_;
    case kOffSsr:    return kSsrIdleVal;
    case kOffSysc:   return sysc_;
    case kOffSyss:   return kSyssRstDoneVal;
    case kOffWer:    return wer_;
    }
    HaltUnsupportedAccess("ReadByte", addr, 0);
}

void Omap3530UartBank::WriteByteLocked(uint32_t addr, uint32_t off,
                                       uint8_t value) {
    const bool dlab = (lcr_ & kLcrDlabMask) != 0;
    switch (off) {
    case kOffRhrThr:
        if (dlab) dll_ = value;
        else {
            EmitTxByte(value);
            if (IsTxDmaActive()) pending_tx_dma_req_ = true;
        }
        return;
    case kOffIerDll:
        if (dlab) dlh_ = value;
        else      ier_ = value;
        return;
    case kOffIirFcr:
        fcr_ = value;
        if (IsTxDmaActive()) pending_tx_dma_req_ = true;
        return;
    case kOffLcr:    lcr_ = value; return;
    case kOffMcr:    mcr_ = value; return;
    case kOffLsr:                  return;  /* read-only */
    case kOffMsr:    msr_ = value; return;
    case kOffSpr:    spr_ = value; return;
    case kOffMdr1:
        /* Accept any MODE_SELECT — UART TX path (EmitTxByte via THR)
           only fires when guest writes RHR/THR; disable mode just
           means kernel won't queue bytes. */
        mdr1_ = value;
        return;
    case kOffTxfll:                          return;  /* read-only in UART16 */
    case kOffRxfll:                          return;
    case kOffTxflh:                          return;
    case kOffScr:
        scr_ = value;
        if (IsTxDmaActive()) pending_tx_dma_req_ = true;
        return;
    case kOffSsr:    return;                /* read-only */
    case kOffSysc:
        sysc_ = value & ~kSyscRstBit;
        return;
    case kOffSyss:   return;                /* read-only */
    case kOffWer:    wer_ = value; return;
    }
    HaltUnsupportedAccess("WriteByte", addr, value);
}

void Omap3530UartBank::EmitTxByte(uint8_t ch) {
    /* Caller holds state_mutex_; LOG / UartScreen calls below do
       not nest back into UART writes. */
    if (ch == '\n') {
        LOG(SocUart, "UART%d TX: %s\n", LogTag(), tx_line_.c_str());
        emu_.Get<UartScreen>().AddLine(tx_line_);
        tx_line_.clear();
        return;
    }
    if (ch == '\r') return;  /* CE emits CRLF — drop CR, flush on LF. */
    if (ch >= 0x20 && ch < 0x7F) {
        tx_line_.push_back(static_cast<char>(ch));
    } else {
        char esc[8];
        std::snprintf(esc, sizeof(esc), "\\x%02X", ch);
        tx_line_.append(esc);
    }
    if (tx_line_.size() >= 256) {
        LOG(SocUart, "UART%d TX (no LF, flushed at 256B): %s\n",
            LogTag(), tx_line_.c_str());
        emu_.Get<UartScreen>().AddLine(tx_line_);
        tx_line_.clear();
    }
}

uint8_t Omap3530UartBank::ReadByte(uint32_t addr) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return ReadByteLocked(addr, addr - MmioBase());
}

void Omap3530UartBank::WriteByte(uint32_t addr, uint8_t value) {
    bool fire_tx = false;
    bool fire_rx = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        WriteByteLocked(addr, addr - MmioBase(), value);
        fire_tx = pending_tx_dma_req_; pending_tx_dma_req_ = false;
        fire_rx = pending_rx_dma_req_; pending_rx_dma_req_ = false;
    }
    FlushPendingDmaReqs(fire_tx, fire_rx);
}

uint32_t Omap3530UartBank::ReadWord(uint32_t addr) {
    /* OMAP UART registers are byte-typed (UINT8 in the BSP struct
       OMAP_UART_REGS), but the OAL occasionally issues word-width
       accesses; return the byte zero-extended. */
    std::lock_guard<std::mutex> lk(state_mutex_);
    return ReadByteLocked(addr, addr - MmioBase());
}

void Omap3530UartBank::WriteWord(uint32_t addr, uint32_t value) {
    bool fire_tx = false;
    bool fire_rx = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        WriteByteLocked(addr, addr - MmioBase(),
                        static_cast<uint8_t>(value & 0xFFu));
        fire_tx = pending_tx_dma_req_; pending_tx_dma_req_ = false;
        fire_rx = pending_rx_dma_req_; pending_rx_dma_req_ = false;
    }
    FlushPendingDmaReqs(fire_tx, fire_rx);
}

class Omap3530Uart1 : public Omap3530UartBank {
public:
    using Omap3530UartBank::Omap3530UartBank;
    uint32_t MmioBase() const override { return 0x4806A000u; }
protected:
    int      LogTag()       const override { return 1; }
    uint32_t TxSyncSource() const override { return Omap3530Sdma::kSyncUart1Tx; }
    uint32_t RxSyncSource() const override { return Omap3530Sdma::kSyncUart1Rx; }
};
class Omap3530Uart2 : public Omap3530UartBank {
public:
    using Omap3530UartBank::Omap3530UartBank;
    uint32_t MmioBase() const override { return 0x4806C000u; }
protected:
    int      LogTag()       const override { return 2; }
    uint32_t TxSyncSource() const override { return Omap3530Sdma::kSyncUart2Tx; }
    uint32_t RxSyncSource() const override { return Omap3530Sdma::kSyncUart2Rx; }
};
class Omap3530Uart3 : public Omap3530UartBank {
public:
    using Omap3530UartBank::Omap3530UartBank;
    uint32_t MmioBase() const override { return 0x49020000u; }
protected:
    int      LogTag()       const override { return 3; }
    uint32_t TxSyncSource() const override { return Omap3530Sdma::kSyncUart3Tx; }
    uint32_t RxSyncSource() const override { return Omap3530Sdma::kSyncUart3Rx; }
};

}  /* namespace */

REGISTER_SERVICE(Omap3530Uart1);
REGISTER_SERVICE(Omap3530Uart2);
REGISTER_SERVICE(Omap3530Uart3);
