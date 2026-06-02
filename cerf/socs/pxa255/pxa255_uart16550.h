#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../host/uart_screen.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "pxa255_intc.h"

#include <cstdint>
#include <cstdio>
#include <string>

/* PXA255 16550 UART (Ch10, Table 10-18). FFUART/BTUART/STUART are one IP at
   different bases + INTC sources (Table 4-35); a concrete supplies MmioBase +
   IntcBit + Name. LCR.DLAB (Table 10-12) remaps 0x00/0x04 to DLL/DLH. TX is
   instantaneous: LSR (Table 10-13) always reads TEMT|TDRQ, RBR reads 0. */
class Pxa255Uart16550 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord(uint32_t addr) override {
        switch (addr - MmioBase()) {
        case kRBR_THR_DLL: return dlab() ? dll_ : 0u;   /* RBR: no input source. */
        case kIER_DLH:     return dlab() ? dlh_ : ier_;
        case kIIR_FCR: {
            uint32_t iir = 0x01u;                        /* IP=1: no interrupt. */
            if (TxIntPending()) { iir = 0x02u; tx_acked_ = true; RecomputeInterrupt(); }
            if (fcr_ & 0x01u) iir |= 0xC0u;
            return iir;
        }
        case kLCR: return lcr_;
        case kMCR: return mcr_;
        case kLSR: return kLsrTxReady;
        case kMSR: return 0u;                            /* no modem inputs. */
        case kSPR: return spr_;
        case kISR: return isr_;
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        switch (addr - MmioBase()) {
        case kRBR_THR_DLL:
            if (dlab()) { dll_ = value; return; }
            EmitTxByte(static_cast<uint8_t>(value & 0xFFu));
            tx_acked_ = false;       /* drained → THRE=1 again → re-assert if TIE. */
            RecomputeInterrupt();
            return;
        case kIER_DLH:
            if (dlab()) { dlh_ = value; return; }
            ier_ = value;
            tx_acked_ = false;       /* TIE set while THRE=1 (re-)asserts (Table 10-8). */
            RecomputeInterrupt();
            return;
        case kIIR_FCR: fcr_ = value; return;             /* FCR (write side). */
        case kLCR:     lcr_ = value; return;
        case kMCR:     mcr_ = value; return;
        case kSPR:     spr_ = value; return;
        case kISR:     isr_ = value; return;
        case kLSR:                                        /* read-only. */
        case kMSR:     return;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

protected:
    virtual uint32_t    IntcBit() const = 0;
    virtual const char* Name()    const = 0;

private:
    enum : uint32_t {
        kRBR_THR_DLL = 0x00, kIER_DLH = 0x04, kIIR_FCR = 0x08, kLCR = 0x0C,
        kMCR = 0x10, kLSR = 0x14, kMSR = 0x18, kSPR = 0x1C, kISR = 0x20,
    };
    static constexpr uint32_t kLsrTxReady = 0x60u;  /* TEMT|TDRQ (Table 10-13). */

    bool dlab() const { return (lcr_ & 0x80u) != 0u; }

    /* THRE is the only assertable source (Table 10-8); TX is instantaneous so
       THRE is always 1, leaving it pending whenever UUE(IER.6) & TIE(IER.1) are
       set and unacknowledged (IIR-read / THR-write acks & re-arms, Table 10-10). */
    bool TxIntPending() const {
        return (ier_ & 0x40u) && (ier_ & 0x02u) && !tx_acked_;
    }
    void RecomputeInterrupt() {
        if (TxIntPending()) emu_.Get<Pxa255Intc>().AssertSource(IntcBit());
        else                emu_.Get<Pxa255Intc>().DeassertSource(IntcBit());
    }

    void EmitTxByte(uint8_t ch) {
        if (ch == '\n') {
            LOG(SocUart, "%s TX: %s\n", Name(), tx_line_.c_str());
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
            LOG(SocUart, "%s TX (no LF, flushed at 256B): %s\n", Name(), tx_line_.c_str());
            emu_.Get<UartScreen>().AddLine(tx_line_);
            tx_line_.clear();
        }
    }

    uint32_t ier_ = 0, fcr_ = 0, lcr_ = 0, mcr_ = 0,
             spr_ = 0, isr_ = 0, dll_ = 0, dlh_ = 0;
    bool tx_acked_ = false;
    std::string tx_line_;
};
