#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../i2c_slave.h"
#include "../irq_controller.h"

#include <cstdint>

namespace cerf_imx51_i2c_detail {

/* i.MX51 I2C controller - Freescale I2C v1 (register offsets + bit semantics:
   MCIMX31RM Ch 26, same IP as the i.MX31 I2C; confirmed against the BSP
   i2c.dll IST). Interrupt-mode master FSM with I2cSlave dispatch. */
constexpr uint32_t kSize = 0x00004000u;     /* AIPS slot (RM Table 2-1) */

constexpr uint32_t kOffIadr = 0x00u;        /* I2C Address Register */
constexpr uint32_t kOffIfdr = 0x04u;        /* I2C Frequency Divider */
constexpr uint32_t kOffI2cr = 0x08u;        /* I2C Control Register */
constexpr uint32_t kOffI2sr = 0x0Cu;        /* I2C Status Register */
constexpr uint32_t kOffI2dr = 0x10u;        /* I2C Data Register */

constexpr uint16_t kI2crIen  = 0x80u;       /* module enable */
constexpr uint16_t kI2crIien = 0x40u;       /* interrupt enable */
constexpr uint16_t kI2crMsta = 0x20u;       /* master mode: 0->1 START, 1->0 STOP */
constexpr uint16_t kI2crMtx  = 0x10u;       /* transmit (1) / receive (0) */
constexpr uint16_t kI2crTxak = 0x08u;       /* transmit-ack (NACK the byte) */
constexpr uint16_t kI2crRsta = 0x04u;       /* repeated START */

constexpr uint16_t kI2srIcf  = 0x80u;       /* data transfer complete */
constexpr uint16_t kI2srIbb  = 0x20u;       /* bus busy */
constexpr uint16_t kI2srIal  = 0x10u;       /* arbitration lost (w0c) */
constexpr uint16_t kI2srIif  = 0x02u;       /* interrupt flag (w0c) */
constexpr uint16_t kI2srRxak = 0x01u;       /* 0 = ACK received */

template <uint32_t kBase, int kIrq>
class Imx51I2cImpl : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint16_t ReadHalf(uint32_t addr) override {
        switch (addr - kBase) {
            case kOffIadr: return iadr_;
            case kOffIfdr: return ifdr_;
            case kOffI2cr: return i2cr_;
            case kOffI2sr: return i2sr_;
            case kOffI2dr: return MasterReadData();
        }
        HaltUnsupportedAccess("ReadHalf", addr, 0);
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        switch (addr - kBase) {
            case kOffIadr: iadr_ = value; return;
            case kOffIfdr: ifdr_ = value; return;
            case kOffI2cr: WriteControl(value); return;
            /* I2SR: IIF/IAL are write-0-to-clear (the IST W0Cs IIF to ack the
               interrupt). Clearing IIF drops the TZIC line. */
            case kOffI2sr: {
                const uint16_t before = i2sr_;
                i2sr_ &= (value | ~(kI2srIif | kI2srIal));
                if ((before & kI2srIif) && !(i2sr_ & kI2srIif)) UpdateIrq();
                return;
            }
            case kOffI2dr: MasterWriteData(static_cast<uint8_t>(value)); return;
        }
        HaltUnsupportedAccess("WriteHalf", addr, value);
    }

    void SaveState(StateWriter& w) override {
        w.Write("iadr", iadr_); w.Write("ifdr", ifdr_); w.Write("i2cr", i2cr_);
        w.Write("i2sr", i2sr_); w.Write("i2dr", i2dr_);
        w.Write<uint8_t>("addr_phase", addr_phase_ ? 1 : 0);
        w.Write<uint8_t>("matched", matched_ ? 1 : 0);
        w.Write("cur_addr", cur_addr_);
        w.Write("rx_shift", rx_shift_);
        if (auto* s = WiredSlave()) s->SaveState(w);
    }
    void RestoreState(StateReader& r) override {
        r.Read("iadr", iadr_); r.Read("ifdr", ifdr_); r.Read("i2cr", i2cr_);
        r.Read("i2sr", i2sr_); r.Read("i2dr", i2dr_);
        uint8_t b = 0;
        r.Read("addr_phase", b); addr_phase_ = b != 0;
        r.Read("matched", b); matched_ = b != 0;
        r.Read("cur_addr", cur_addr_);
        r.Read("rx_shift", rx_shift_);
        if (auto* s = WiredSlave()) s->RestoreState(r);
    }
    /* Re-drive the (level) TZIC line from the restored IIF/IIEN state. */
    void PostRestore() override { UpdateIrq(); }

protected:
    /* The slave wired to this controller (e.g. I2C2 -> MC13892). Default: no
       slave -> the controller NACKs (RXAK=1), the guest driver aborts cleanly. */
    virtual I2cSlave* WiredSlave() { return nullptr; }

private:
    void WriteControl(uint16_t value) {
        const bool was_master = (i2cr_ & kI2crMsta) != 0;
        const bool is_master  = (value & kI2crMsta) != 0;
        const bool rsta       = (value & kI2crRsta) != 0;
        i2cr_ = value;
        if (!was_master && is_master) {            /* START */
            i2sr_ |= kI2srIbb;
            addr_phase_ = true;
            matched_ = false;
        } else if (was_master && !is_master) {     /* STOP */
            i2sr_ &= ~(kI2srIbb | kI2srIcf);
            addr_phase_ = false;
            matched_ = false;
        } else if (is_master && rsta) {            /* repeated START */
            addr_phase_ = true;
        }
        UpdateIrq();   /* IIEN may have just been (de)asserted */
    }

    void MasterWriteData(uint8_t value) {
        i2dr_ = value;
        if (addr_phase_) {
            cur_addr_ = static_cast<uint8_t>(value >> 1);
            addr_phase_ = false;
            I2cSlave* s = WiredSlave();
            matched_ = s && s->MatchesAddress(cur_addr_);
            if (matched_) s->TxnStart(cur_addr_);
        } else if (matched_) {
            WiredSlave()->TxnWriteByte(cur_addr_, value);
        }
        if (matched_) i2sr_ &= ~kI2srRxak;         /* ACK */
        else          i2sr_ |= kI2srRxak;          /* no slave -> NACK */
        CompleteByte();
    }

    uint16_t MasterReadData() {
        /* i.MX I2C master receive is "delayed by one": reading I2DR returns the
           byte clocked in by the PREVIOUS read and clocks the next one - the
           first read after addressing is the dummy read (MCIMX51RM Ch 40,
           Figure 40-15 "Dummy Read from I2DR" in the master-receive flow). */
        const uint8_t out = rx_shift_;
        rx_shift_ = matched_ ? WiredSlave()->TxnReadByte(cur_addr_) : 0xFFu;
        CompleteByte();
        return out;
    }

    /* A byte transfer finished: set ICF + IIF, raise the interrupt if enabled. */
    void CompleteByte() {
        i2sr_ |= (kI2srIcf | kI2srIif);
        UpdateIrq();
    }

    void UpdateIrq() {
        const bool want = (i2sr_ & kI2srIif) && (i2cr_ & kI2crIien);
        if (want == irq_asserted_) return;
        irq_asserted_ = want;
        if (want) emu_.Get<IrqController>().AssertIrq(kIrq);
        else      emu_.Get<IrqController>().DeAssertIrq(kIrq);
    }

    uint16_t iadr_ = 0, ifdr_ = 0, i2cr_ = 0, i2sr_ = 0, i2dr_ = 0;
    bool     addr_phase_ = false;
    bool     matched_    = false;
    uint8_t  cur_addr_   = 0;
    uint8_t  rx_shift_   = 0;
    bool     irq_asserted_ = false;
};

}  /* namespace cerf_imx51_i2c_detail */
