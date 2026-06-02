#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../boards/board_detector.h"
#include "omap3530_sdma.h"
#include "twl4030.h"

#include <cstdint>
#include <deque>
#include <mutex>

namespace {

constexpr uint32_t kI2cSize = 0x00001000u;

constexpr uint32_t kOffRev      = 0x00;
constexpr uint32_t kOffIe       = 0x04;
constexpr uint32_t kOffStat     = 0x08;
constexpr uint32_t kOffWe       = 0x0C;
constexpr uint32_t kOffSyss     = 0x10;
constexpr uint32_t kOffBuf      = 0x14;
constexpr uint32_t kOffCnt      = 0x18;
constexpr uint32_t kOffData     = 0x1C;
constexpr uint32_t kOffSysc     = 0x20;
constexpr uint32_t kOffCon      = 0x24;
constexpr uint32_t kOffOa0      = 0x28;
constexpr uint32_t kOffSa       = 0x2C;
constexpr uint32_t kOffPsc      = 0x30;
constexpr uint32_t kOffScll     = 0x34;
constexpr uint32_t kOffSclh     = 0x38;
constexpr uint32_t kOffSystest  = 0x3C;
constexpr uint32_t kOffBufstat  = 0x40;
constexpr uint32_t kOffOa1      = 0x44;
constexpr uint32_t kOffOa2      = 0x48;
constexpr uint32_t kOffOa3      = 0x4C;
constexpr uint32_t kOffActoa    = 0x50;
constexpr uint32_t kOffSblock   = 0x54;

constexpr uint16_t kI2cConStt        = 1u << 0;
constexpr uint16_t kI2cConTrx        = 1u << 9;
constexpr uint16_t kI2cSyscSrst      = 1u << 1;
constexpr uint16_t kI2cSyssRdone     = 1u << 0;
constexpr uint16_t kI2cStatAl        = 1u << 0;
constexpr uint16_t kI2cStatNack      = 1u << 1;
constexpr uint16_t kI2cStatArdy      = 1u << 2;
constexpr uint16_t kI2cStatRrdy      = 1u << 3;
constexpr uint16_t kI2cStatXrdy      = 1u << 4;
constexpr uint16_t kI2cStatXudf      = 1u << 10;
constexpr uint16_t kI2cStatRdr       = 1u << 13;
constexpr uint16_t kI2cStatXdr       = 1u << 14;
constexpr uint16_t kI2cStatTxBits    =
    kI2cStatXrdy | kI2cStatXdr | kI2cStatXudf;
constexpr uint16_t kI2cStatRxBits    =
    kI2cStatRrdy | kI2cStatRdr | (1u << 11);   /* ROVR */
constexpr uint16_t kI2cBufTxFifoClr  = 1u << 6;
constexpr uint16_t kI2cBufRxFifoClr  = 1u << 14;
constexpr uint16_t kI2cBufXdmaEn     = 1u << 7;
constexpr uint16_t kI2cBufRdmaEn     = 1u << 15;

class Omap3530I2cBank : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::OMAP3530;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioSize() const override { return kI2cSize; }

    uint8_t  ReadByte (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    uint16_t ReadHalf (uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

protected:
    /* Slave-side dispatch hooks. Caller (this base class) holds
       state_mutex_ around both calls. The write hook drains
       tx_fifo_; the read hook fills rx_fifo_ with `count` bytes.
       Default (no slave): halt loudly with a diagnostic. */
    virtual void DispatchWriteLocked (uint32_t guest_addr_for_diag,
                                      uint8_t  slave_addr);
    virtual void DispatchReadLocked  (uint32_t guest_addr_for_diag,
                                      uint8_t  slave_addr,
                                      uint16_t count);

    /* Per-bank SDMA sync source IDs. Default 0 = no DMA wiring
       (I2C3 high-speed bus is PIO-only on OMAP3530). */
    virtual int TxSyncSource() const { return 0; }
    virtual int RxSyncSource() const { return 0; }

    mutable std::mutex  state_mutex_;
    std::deque<uint8_t> tx_fifo_;
    std::deque<uint8_t> rx_fifo_;

    /* Pending-transaction state captured at CON.STT write,
       consumed at STAT W1C (write) or at CNT write (read). */
    bool    pending_active_     = false;
    bool    pending_is_read_    = false;
    uint8_t pending_slave_addr_ = 0;
    bool    pending_tx_dma_req_ = false;
    bool    pending_rx_dma_req_ = false;

private:
    bool     IsKnownOffset(uint32_t off) const;
    uint16_t ReadHalfLocked (uint32_t off);
    void     WriteHalfLocked(uint32_t guest_addr_for_diag,
                             uint32_t off, uint16_t value);
    void     ApplyResetLocked();
    void     OnConStartLocked(uint32_t guest_addr_for_diag);
    void     OnCntWriteLocked(uint32_t guest_addr_for_diag);
    void     OnStatW1cLocked (uint32_t guest_addr_for_diag,
                              uint16_t value);
    void     FlushPendingDmaReqs(bool fire_tx, bool fire_rx);

    uint16_t stat_    = 0;
    uint16_t ie_      = 0;
    uint16_t we_      = 0;
    uint16_t buf_     = 0;
    uint16_t cnt_     = 0;
    uint16_t sysc_    = 0;
    uint16_t con_     = 0;
    uint16_t oa0_     = 0;
    uint16_t sa_      = 0;
    uint16_t psc_     = 0;
    uint16_t scll_    = 0;
    uint16_t sclh_    = 0;
    uint16_t systest_ = 0;
    uint16_t oa1_     = 0;
    uint16_t oa2_     = 0;
    uint16_t oa3_     = 0;
    uint16_t actoa_   = 0;
    uint16_t sblock_  = 0;
};

void Omap3530I2cBank::ApplyResetLocked() {
    stat_ = ie_ = we_ = buf_ = cnt_ = sysc_ = con_ = 0;
    oa0_ = sa_ = psc_ = scll_ = sclh_ = systest_ = 0;
    oa1_ = oa2_ = oa3_ = actoa_ = sblock_ = 0;
    tx_fifo_.clear();
    rx_fifo_.clear();
    pending_active_ = false;
    pending_is_read_ = false;
    pending_slave_addr_ = 0;
    pending_tx_dma_req_ = false;
    pending_rx_dma_req_ = false;
}

void Omap3530I2cBank::DispatchWriteLocked(uint32_t /*guest_addr_for_diag*/,
                                          uint8_t  slave_addr) {
    LOG(Caution, "Omap3530I2cBank: I2C write to slave 0x%02X but no "
            "slave is wired on this bus\n", slave_addr);
    /* Real silicon NACKs an unaddressed slave; oal_i2c.c:695 aborts
       the transaction on STAT.NACK | STAT.AL | STAT.AERR. */
    stat_ |= kI2cStatNack | kI2cStatArdy;
}

void Omap3530I2cBank::DispatchReadLocked(uint32_t /*guest_addr_for_diag*/,
                                         uint8_t  slave_addr,
                                         uint16_t count) {
    LOG(Caution, "Omap3530I2cBank: I2C read from slave 0x%02X "
            "(%u byte%s) but no slave is wired on this bus\n",
            slave_addr, count, count == 1 ? "" : "s");
    stat_ |= kI2cStatNack | kI2cStatArdy;
}

bool Omap3530I2cBank::IsKnownOffset(uint32_t off) const {
    switch (off) {
    case kOffRev: case kOffIe: case kOffStat: case kOffWe:
    case kOffSyss: case kOffBuf: case kOffCnt: case kOffData:
    case kOffSysc: case kOffCon: case kOffOa0: case kOffSa:
    case kOffPsc: case kOffScll: case kOffSclh: case kOffSystest:
    case kOffBufstat: case kOffOa1: case kOffOa2: case kOffOa3:
    case kOffActoa: case kOffSblock:
        return true;
    }
    return false;
}

void Omap3530I2cBank::OnConStartLocked(uint32_t /*guest_addr_for_diag*/) {
    /* Dispatch deferred: STAT W1C XRDY|XDR|XUDF (write, oal_i2c.c
       :769) or CNT write (read, :852). CON|STT precedes both. */
    pending_active_     = true;
    pending_is_read_    = (con_ & kI2cConTrx) == 0;
    pending_slave_addr_ = static_cast<uint8_t>(sa_ & 0x7Fu);
    /* STT auto-clears once the controller observes it. */
    con_ &= ~kI2cConStt;
}

void Omap3530I2cBank::OnCntWriteLocked(uint32_t guest_addr_for_diag) {
    if (!pending_active_ || !pending_is_read_) return;
    /* Pre-fill rx_fifo_ from the slave with `cnt_` bytes. */
    rx_fifo_.clear();
    DispatchReadLocked(guest_addr_for_diag, pending_slave_addr_, cnt_);
    stat_ |= kI2cStatRrdy | kI2cStatArdy;
    pending_active_ = false;
    if (!rx_fifo_.empty() && (buf_ & kI2cBufRdmaEn) && RxSyncSource() != 0) {
        pending_rx_dma_req_ = true;
    }
}

void Omap3530I2cBank::OnStatW1cLocked(uint32_t guest_addr_for_diag,
                                      uint16_t value) {
    /* If a write transaction is pending and the kernel just W1Cs
       any of XRDY|XDR|XUDF, the OAL's "fill phase complete" signal
       has arrived — drain tx_fifo_ to the slave and set ARDY so
       the next loop iteration sees the packet complete. */
    if (pending_active_ && !pending_is_read_ &&
        (value & kI2cStatTxBits) != 0) {
        DispatchWriteLocked(guest_addr_for_diag, pending_slave_addr_);
        stat_ |= kI2cStatArdy;
        pending_active_ = false;
    }
    /* W1C the bits the kernel wrote. */
    stat_ &= ~value;
}

uint16_t Omap3530I2cBank::ReadHalfLocked(uint32_t off) {
    switch (off) {
    case kOffRev:     return 0u;
    case kOffIe:      return ie_;
    case kOffStat:    return stat_;
    case kOffWe:      return we_;
    case kOffSyss:    return kI2cSyssRdone;
    case kOffBuf:     return buf_;
    case kOffCnt:     return cnt_;
    case kOffData: {
        if (rx_fifo_.empty()) return 0u;
        const uint8_t b = rx_fifo_.front();
        rx_fifo_.pop_front();
        if (!rx_fifo_.empty() && (buf_ & kI2cBufRdmaEn) &&
            RxSyncSource() != 0) {
            pending_rx_dma_req_ = true;
        }
        return b;
    }
    case kOffSysc:    return sysc_;
    case kOffCon:     return con_;
    case kOffOa0:     return oa0_;
    case kOffSa:      return sa_;
    case kOffPsc:     return psc_;
    case kOffScll:    return scll_;
    case kOffSclh:    return sclh_;
    case kOffSystest: return systest_;
    case kOffBufstat: return 0u;
    case kOffOa1:     return oa1_;
    case kOffOa2:     return oa2_;
    case kOffOa3:     return oa3_;
    case kOffActoa:   return actoa_;
    case kOffSblock:  return sblock_;
    }
    return 0u;
}

void Omap3530I2cBank::WriteHalfLocked(uint32_t guest_addr_for_diag,
                                      uint32_t off, uint16_t value) {
    switch (off) {
    case kOffRev:     return;
    case kOffIe:      ie_ = value; return;
    case kOffStat:    OnStatW1cLocked(guest_addr_for_diag, value);
                      return;
    case kOffWe:      we_ = value; return;
    case kOffSyss:    return;
    case kOffBuf:
        if (value & kI2cBufTxFifoClr) tx_fifo_.clear();
        if (value & kI2cBufRxFifoClr) rx_fifo_.clear();
        /* TXFIFO_CLR / RXFIFO_CLR self-clear after the FIFO is
           cleared; mirror that so subsequent BUF reads don't see
           a stale "clear request" bit. */
        buf_ = value & ~(kI2cBufTxFifoClr | kI2cBufRxFifoClr);
        return;
    case kOffCnt:
        cnt_ = value;
        OnCntWriteLocked(guest_addr_for_diag);
        return;
    case kOffData:
        tx_fifo_.push_back(static_cast<uint8_t>(value & 0xFFu));
        if ((buf_ & kI2cBufXdmaEn) && TxSyncSource() != 0) {
            pending_tx_dma_req_ = true;
        }
        return;
    case kOffSysc:
        if (value & kI2cSyscSrst) ApplyResetLocked();
        sysc_ = value & ~kI2cSyscSrst;
        return;
    case kOffCon:
        con_ = value;
        if (value & kI2cConStt) {
            OnConStartLocked(guest_addr_for_diag);
            if ((con_ & kI2cConTrx) && (buf_ & kI2cBufXdmaEn) &&
                TxSyncSource() != 0) {
                pending_tx_dma_req_ = true;
            }
        }
        return;
    case kOffOa0:     oa0_     = value; return;
    case kOffSa:      sa_      = value; return;
    case kOffPsc:     psc_     = value; return;
    case kOffScll:    scll_    = value; return;
    case kOffSclh:    sclh_    = value; return;
    case kOffSystest: systest_ = value; return;
    case kOffBufstat: return;
    case kOffOa1:     oa1_     = value; return;
    case kOffOa2:     oa2_     = value; return;
    case kOffOa3:     oa3_     = value; return;
    case kOffActoa:   actoa_   = value; return;
    case kOffSblock:  sblock_  = value; return;
    }
}

uint16_t Omap3530I2cBank::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if ((off & 0x1u) != 0 || !IsKnownOffset(off)) {
        HaltUnsupportedAccess("ReadHalf (unknown offset or unaligned)",
                              addr, 0);
    }
    uint16_t result;
    bool fire_tx, fire_rx;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        result = ReadHalfLocked(off);
        fire_tx = pending_tx_dma_req_; pending_tx_dma_req_ = false;
        fire_rx = pending_rx_dma_req_; pending_rx_dma_req_ = false;
    }
    FlushPendingDmaReqs(fire_tx, fire_rx);
    return result;
}

void Omap3530I2cBank::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - MmioBase();
    if ((off & 0x1u) != 0 || !IsKnownOffset(off)) {
        HaltUnsupportedAccess("WriteHalf (unknown offset or unaligned)",
                              addr, value);
    }
    bool fire_tx, fire_rx;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        WriteHalfLocked(addr, off, value);
        fire_tx = pending_tx_dma_req_; pending_tx_dma_req_ = false;
        fire_rx = pending_rx_dma_req_; pending_rx_dma_req_ = false;
    }
    FlushPendingDmaReqs(fire_tx, fire_rx);
}

uint8_t Omap3530I2cBank::ReadByte(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off != kOffData) {
        HaltUnsupportedAccess(
            "ReadByte (only I2C_DATA at 0x1C supports byte access)",
            addr, 0);
    }
    uint8_t result = 0;
    bool fire_rx = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (!rx_fifo_.empty()) {
            result = rx_fifo_.front();
            rx_fifo_.pop_front();
            if (!rx_fifo_.empty() && (buf_ & kI2cBufRdmaEn) &&
                RxSyncSource() != 0) {
                pending_rx_dma_req_ = true;
            }
        }
        fire_rx = pending_rx_dma_req_; pending_rx_dma_req_ = false;
    }
    FlushPendingDmaReqs(false, fire_rx);
    return result;
}

void Omap3530I2cBank::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - MmioBase();
    if (off != kOffData) {
        HaltUnsupportedAccess(
            "WriteByte (only I2C_DATA at 0x1C supports byte access)",
            addr, value);
    }
    bool fire_tx = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        tx_fifo_.push_back(value);
        if ((buf_ & kI2cBufXdmaEn) && TxSyncSource() != 0) {
            pending_tx_dma_req_ = true;
        }
        fire_tx = pending_tx_dma_req_; pending_tx_dma_req_ = false;
    }
    FlushPendingDmaReqs(fire_tx, false);
}

void Omap3530I2cBank::FlushPendingDmaReqs(bool fire_tx, bool fire_rx) {
    if (!fire_tx && !fire_rx) return;
    auto& sdma = emu_.Get<Omap3530Sdma>();
    if (fire_rx && RxSyncSource() != 0) {
        sdma.RaiseSyncEvent(static_cast<uint32_t>(RxSyncSource()));
    }
    if (fire_tx && TxSyncSource() != 0) {
        sdma.RaiseSyncEvent(static_cast<uint32_t>(TxSyncSource()));
    }
}

uint32_t Omap3530I2cBank::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off != kOffBufstat) {
        HaltUnsupportedAccess(
            "ReadWord (only I2C_BUFSTAT at 0x40 is word-accessed by "
            "the OAL; all other I2C registers are 16-bit)",
            addr, 0);
    }
    std::lock_guard<std::mutex> lk(state_mutex_);
    return ReadHalfLocked(kOffBufstat);
}

void Omap3530I2cBank::WriteWord(uint32_t addr, uint32_t value) {
    HaltUnsupportedAccess(
        "WriteWord (I2C registers are 16-bit; no 32-bit write expected)",
        addr, value);
}

/* I2C1 — talks to the TWL4030 PMIC. Dispatch hooks routed to the
   TWL4030 slave service. */
class Omap3530I2c1 : public Omap3530I2cBank {
public:
    using Omap3530I2cBank::Omap3530I2cBank;
    uint32_t MmioBase() const override { return 0x48070000u; }

protected:
    int TxSyncSource() const override { return Omap3530Sdma::kSyncI2c1Tx; }
    int RxSyncSource() const override { return Omap3530Sdma::kSyncI2c1Rx; }
    void DispatchWriteLocked(uint32_t guest_addr_for_diag,
                             uint8_t  slave_addr) override;
    void DispatchReadLocked (uint32_t guest_addr_for_diag,
                             uint8_t  slave_addr,
                             uint16_t count) override;
};

void Omap3530I2c1::DispatchWriteLocked(uint32_t guest_addr_for_diag,
                                       uint8_t  slave_addr) {
    auto& twl = emu_.Get<Twl4030>();
    if (!twl.MatchesAddress(slave_addr)) {
        Omap3530I2cBank::DispatchWriteLocked(guest_addr_for_diag,
                                             slave_addr);
    }
    twl.TxnStart(slave_addr);
    while (!tx_fifo_.empty()) {
        twl.TxnWriteByte(slave_addr, tx_fifo_.front());
        tx_fifo_.pop_front();
    }
}

void Omap3530I2c1::DispatchReadLocked(uint32_t guest_addr_for_diag,
                                      uint8_t  slave_addr,
                                      uint16_t count) {
    auto& twl = emu_.Get<Twl4030>();
    if (!twl.MatchesAddress(slave_addr)) {
        Omap3530I2cBank::DispatchReadLocked(guest_addr_for_diag,
                                            slave_addr, count);
    }
    twl.TxnStart(slave_addr);
    for (uint16_t i = 0; i < count; ++i) {
        rx_fifo_.push_back(twl.TxnReadByte(slave_addr));
    }
}

class Omap3530I2c2 : public Omap3530I2cBank {
public:
    using Omap3530I2cBank::Omap3530I2cBank;
    uint32_t MmioBase() const override { return 0x48072000u; }
protected:
    int TxSyncSource() const override { return Omap3530Sdma::kSyncI2c2Tx; }
    int RxSyncSource() const override { return Omap3530Sdma::kSyncI2c2Rx; }
};
class Omap3530I2c3 : public Omap3530I2cBank {
public:
    using Omap3530I2cBank::Omap3530I2cBank;
    uint32_t MmioBase() const override { return 0x48060000u; }
    /* I2C3 is high-speed I2C with no SDMA wiring on OMAP3530 — uses
       its own internal FIFO and CPU-driven transfers. */
};

}  /* namespace */

REGISTER_SERVICE(Omap3530I2c1);
REGISTER_SERVICE(Omap3530I2c2);
REGISTER_SERVICE(Omap3530I2c3);
