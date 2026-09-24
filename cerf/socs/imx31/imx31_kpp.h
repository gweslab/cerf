#pragma once

#include "../../peripherals/peripheral_base.h"
#include "../../state/state_stream.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

/* i.MX31 Keypad Port (KPP), PA 0x43FA_8000 - MCIMX31RM Ch 27. Zune front
   controls are a KPP matrix: pyxis_keybd.dll scans 4 cols (KPDR 8-11) x 5 rows
   (KPDR 0-4), key index 5*col+row. SetMatrixKey is the host-input entry. */
class Imx31Kpp : public Peripheral {
public:
    using Peripheral::Peripheral;
    ~Imx31Kpp() override;

    bool ShouldRegister() override;
    void OnReady() override;
    void OnShutdown() override;

    uint32_t MmioBase() const override { return 0x43FA8000u; }
    uint32_t MmioSize() const override { return 0x00004000u; }  /* AIPS slot */

    uint8_t  ReadByte (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t value) override;
    uint16_t ReadHalf (uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    /* Host input toggles a matrix cell (col 0..3, row 0..4). */
    void SetMatrixKey(uint8_t col, uint8_t row, bool pressed);

    /* SetMatrixKey runs on the host-input thread under mtx_, so the
       register snapshot is taken under the same lock. The synchronizer
       thread / condition variable / stop_ flag are host-side control
       and are re-created on restore, not serialized. */
    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(mtx_);
        w.Write("kpcr", kpcr_);
        w.Write("kpsr", kpsr_);
        w.Write("kddr", kddr_);
        w.Write("kpdr_col", kpdr_col_);
        w.WriteBytes("pressed", pressed_, sizeof(pressed_));
        const uint8_t irq = irq_on_.load(std::memory_order_acquire) ? 1u : 0u;
        w.Write("irq", irq);
    }
    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(mtx_);
        r.Read("kpcr", kpcr_);
        r.Read("kpsr", kpsr_);
        r.Read("kddr", kddr_);
        r.Read("kpdr_col", kpdr_col_);
        r.ReadBytes("pressed", pressed_, sizeof(pressed_));
        uint8_t irq = 0;
        r.Read("irq", irq);
        irq_on_.store(irq != 0, std::memory_order_release);
    }

    void PostRestore() override;

private:
    void     StopSyncThread();
    uint16_t ReadReg16Locked(uint32_t off);
    bool     WriteReg16Locked(uint32_t off, uint16_t value);  /* true => re-eval IRQ */
    uint16_t RowSenseLocked() const;
    bool     IrqDesiredLocked() const;
    bool     AnyPressedLocked() const;
    void     ApplyIrq(bool desired);
    void     SyncDetectLoop();

    mutable std::mutex mtx_;
    uint16_t kpcr_     = 0;        /* KPCR  @0x00 */
    uint16_t kpsr_     = 0;        /* KPSR  @0x02 */
    uint16_t kddr_     = 0;        /* KDDR  @0x04 */
    uint16_t kpdr_col_ = 0xFF00u;  /* KPDR  @0x06 driven column data (bits 8-15) */
    uint8_t  pressed_[4] = {};     /* per-column 5-bit pressed-row mask */

    std::atomic<bool> irq_on_{false};

    /* Synchronizer re-detect: a held key re-asserts KPKD after each scan's
       re-arm so the driver's 40 ms (GetTickCount) debounce completes. */
    std::condition_variable sync_cv_;
    std::thread             sync_thread_;
    bool                    stop_ = false;
};
