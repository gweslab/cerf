#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>
#include <cstdio>
#include <string>

namespace cerf_imx31_uart_detail {

/* i.MX31 UART (MCIMX31RM Ch 31). Registers are 16-bit-significant 32-bit-aligned
   and take 8/16/32-bit reads with bits[31:16]=0 (§31.3.2) — so reads align+shift.
   Status regs read fixed idle (TX-ready, no RX); UTXD drains to SocUart. If
   UTS.TXFULL ever reads set or USR1.TRDY clear, the kernel TX spin never exits. */
template <uint32_t kBase, int kUartNum>
class Imx31UartImpl : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::iMX31;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return 0x4000u; }

    uint8_t ReadByte(uint32_t a) override {
        const uint32_t off = a - kBase;
        return static_cast<uint8_t>(Reg(off & ~3u) >> ((off & 3u) * 8u));
    }
    uint16_t ReadHalf(uint32_t a) override {
        const uint32_t off = a - kBase;
        return static_cast<uint16_t>(Reg(off & ~3u) >> ((off & 2u) * 8u));
    }
    uint32_t ReadWord(uint32_t a) override { return Reg(a - kBase); }

    void WriteByte(uint32_t a, uint8_t  v) override { Wr(a - kBase, v, (a & 3u) * 8u, 0xFFu); }
    void WriteHalf(uint32_t a, uint16_t v) override { Wr(a - kBase, v, (a & 2u) * 8u, 0xFFFFu); }
    void WriteWord(uint32_t a, uint32_t v) override { Wr(a - kBase, v, 0u, 0xFFFFFFFFu); }

private:
    static constexpr uint32_t kURXD = 0x00u, kUTXD = 0x40u;
    static constexpr uint32_t kUSR1 = 0x94u, kUSR2 = 0x98u, kUTS = 0xB4u;
    static constexpr uint32_t kCtrlLo = 0x80u, kCtrlHi = 0xB8u;

    /* §31.3.3 reset values that ARE the idle TX-ready/RX-empty status: USR1.TRDY
       (0x2040), USR2.TXDC+TXFE (0x4028), UTS.TXEMPTY (0x60, TXFULL clear). */
    static constexpr uint32_t kUsr1Idle = 0x2040u;
    static constexpr uint32_t kUsr2Idle = 0x4028u;
    static constexpr uint32_t kUtsIdle  = 0x0060u;

    /* Control/baud regs 0x80..0xB8 step 4, reset values (MCIMX31RM Table 31-2). */
    uint32_t ctrl_[15] = {
        0x0000u, 0x0001u, 0x0700u, 0x8000u, 0x0801u,  /* UCR1 UCR2 UCR3 UCR4 UFCR */
        0x2040u, 0x4028u, 0x002Bu, 0x0000u, 0x0000u,  /* USR1 USR2 UESC UTIM UBIR */
        0x0000u, 0x0004u, 0x0000u, 0x0060u, 0x0000u,  /* UBMR UBRC ONEMS UTS  UMCR */
    };
    std::string tx_line_;

    uint32_t Reg(uint32_t off) {
        if (off == kURXD) return 0u;        /* no RX data (CHARRDY=0) */
        if (off == kUTXD) return 0u;
        if (off == kUSR1) return kUsr1Idle;
        if (off == kUSR2) return kUsr2Idle;
        if (off == kUTS)  return kUtsIdle;
        if (off >= kCtrlLo && off <= kCtrlHi && (off & 3u) == 0u)
            return ctrl_[(off - kCtrlLo) / 4u];
        HaltUnsupportedAccess("Read", kBase + off, 0);
    }

    void Wr(uint32_t off, uint32_t v, uint32_t shift, uint32_t vmask) {
        const uint32_t aligned = off & ~3u;
        if (aligned == kUTXD) { EmitTx(static_cast<uint8_t>(v & 0xFFu)); return; }
        if (aligned == kUSR1 || aligned == kUSR2) return;  /* W1C status; idle */
        if (aligned >= kCtrlLo && aligned <= kCtrlHi) {
            /* Registers hold only bits[15:0]; a 32-bit write's 16 MSB are "not
               taken into account" (§31.3.2), so clamp the merge mask to the low
               half — upper-half writes are intentionally dropped, NOT preserved. */
            const uint32_t m = (vmask << shift) & 0xFFFFu;
            uint32_t& r = ctrl_[(aligned - kCtrlLo) / 4u];
            r = (r & ~m) | ((v << shift) & m);
            return;
        }
        HaltUnsupportedAccess("Write", kBase + off, v);
    }

    void EmitTx(uint8_t ch) {
        if (ch == '\n') {
            LOG(SocUart, "UART%d TX: %s\n", kUartNum, tx_line_.c_str());
            tx_line_.clear();
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
            LOG(SocUart, "UART%d TX (256B flush): %s\n", kUartNum, tx_line_.c_str());
            tx_line_.clear();
        }
    }
};

}  /* namespace cerf_imx31_uart_detail */
