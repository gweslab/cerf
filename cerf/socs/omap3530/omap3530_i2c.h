#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "omap3530_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <deque>
#include <mutex>

/* OMAP3530 I2C controller bank. I2C1/2/3 share this register + transaction
   model; concrete subclasses supply MmioBase and route slave dispatch
   (I2C1 -> TWL4030 PMIC). */
class Omap3530I2cBank : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Omap3530;
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

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        w.Write("stat", stat_);    w.Write("ie", ie_);   w.Write("we", we_);   w.Write("buf", buf_);
        w.Write("cnt", cnt_);     w.Write("sysc", sysc_); w.Write("con", con_);  w.Write("oa0", oa0_);
        w.Write("sa", sa_);      w.Write("psc", psc_);  w.Write("scll", scll_); w.Write("sclh", sclh_);
        w.Write("systest", systest_); w.Write("oa1", oa1_);  w.Write("oa2", oa2_);  w.Write("oa3", oa3_);
        w.Write("actoa", actoa_);   w.Write("sblock", sblock_);
        w.Write("pending_active", pending_active_);
        w.Write("pending_is_read", pending_is_read_);
        w.Write("pending_slave_addr", pending_slave_addr_);
        w.Write("pending_tx_dma_req", pending_tx_dma_req_);
        w.Write("pending_rx_dma_req", pending_rx_dma_req_);
        w.Write<uint32_t>("tx_fifo_count", static_cast<uint32_t>(tx_fifo_.size()));
        for (uint8_t b : tx_fifo_) w.Write("tx_fifo", b);
        w.Write<uint32_t>("rx_fifo_count", static_cast<uint32_t>(rx_fifo_.size()));
        for (uint8_t b : rx_fifo_) w.Write("rx_fifo", b);
    }
    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        r.Read("stat", stat_);    r.Read("ie", ie_);   r.Read("we", we_);   r.Read("buf", buf_);
        r.Read("cnt", cnt_);     r.Read("sysc", sysc_); r.Read("con", con_);  r.Read("oa0", oa0_);
        r.Read("sa", sa_);      r.Read("psc", psc_);  r.Read("scll", scll_); r.Read("sclh", sclh_);
        r.Read("systest", systest_); r.Read("oa1", oa1_);  r.Read("oa2", oa2_);  r.Read("oa3", oa3_);
        r.Read("actoa", actoa_);   r.Read("sblock", sblock_);
        r.Read("pending_active", pending_active_);
        r.Read("pending_is_read", pending_is_read_);
        r.Read("pending_slave_addr", pending_slave_addr_);
        r.Read("pending_tx_dma_req", pending_tx_dma_req_);
        r.Read("pending_rx_dma_req", pending_rx_dma_req_);
        tx_fifo_.clear();
        uint32_t n = 0;
        r.Read("tx_fifo_count", n);
        for (uint32_t i = 0; i < n; ++i) { uint8_t b = 0; r.Read("tx_fifo", b); tx_fifo_.push_back(b); }
        rx_fifo_.clear();
        r.Read("rx_fifo_count", n);
        for (uint32_t i = 0; i < n; ++i) { uint8_t b = 0; r.Read("rx_fifo", b); rx_fifo_.push_back(b); }
    }

protected:
    static constexpr uint32_t kI2cSize = 0x00001000u;

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
