#pragma once

#include "../peripherals/peripheral_base.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../boards/board_context.h"
#include "imx51/imx51_id.h"
#include "../tracing/kernel_debug_sink.h"
#include "../peripherals/peripheral_dispatcher.h"
#include "../state/state_stream.h"
#include "uart_endpoint.h"
#include "freescale_sdma_bus.h"

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <string>

namespace cerf_freescale_uart_detail {

/* Freescale i.MX UART, register-identical on i.MX31 (MCIMX31RM Ch 31) and i.MX51
   (MCIMX51RM Ch 59) - same map + reset values - so the model is shared, gated per
   concrete by kSoc. Status regs MUST read fixed idle: if UTS.TXFULL ever reads set
   or USR1.TRDY clear, the guest TX spin never exits. */
template <uint32_t kBase, int kUartNum, const std::string_view& kSoc>
class FreescaleUartBase : public Peripheral, public FreescaleSdmaPeripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == kSoc;
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

    /* Only the control/baud register file is machine state. tx_line_ is a
       host-side console line accumulator (rebuilt as the guest writes UTXD),
       so it is skipped. An attached endpoint (e.g. the VMCU peer) serializes
       its own guest-coupled state via the forward below. */
    void SaveState(StateWriter& w) override {
        w.WriteBytes("ctrl", ctrl_, sizeof(ctrl_));
        if (endpoint_) endpoint_->SaveState(w);
    }
    void RestoreState(StateReader& r) override {
        r.ReadBytes("ctrl", ctrl_, sizeof(ctrl_));
        if (endpoint_) endpoint_->RestoreState(r);
    }

    /* A board wires an off-chip device (e.g. the SYNC2 VMCU) to this UART. */
    void AttachEndpoint(UartEndpoint* ep) { endpoint_ = ep; }

    /* Wire this UART to the i.MX SDMA: its driver moves TX/RX through DMA rather
       than UTXD/URXD when bound. tx_event / rx_event are the SDMA DMA-request
       events (MCIMX51RM Table 3-3). */
    void BindSdma(FreescaleSdmaBus* bus, uint32_t tx_event, uint32_t rx_event) {
        sdma_bus_ = bus;
        rx_dma_event_ = rx_event;
        if (bus) {
            bus->RegisterSdmaEvent(tx_event, this, true);
            bus->RegisterSdmaEvent(rx_event, this, false);
        }
    }

    /* FreescaleSdmaPeripheral: a byte the SDMA read from a TX channel's buffer. */
    void SdmaTxByte(uint8_t byte) override { EmitTx(byte); }

    /* The endpoint pushes reply bytes into the guest. With a DMA-driven serial
       driver the bytes are delivered into the armed RX DMA channel; otherwise into
       the RxFIFO, raising the RX interrupt if the guest enabled it. */
    void InjectRx(const uint8_t* data, size_t n) {
        if (sdma_bus_ && rx_dma_event_ != 0
            && sdma_bus_->SdmaRxDeliver(rx_dma_event_, data, n))
            return;
        for (size_t i = 0; i < n; ++i) rx_fifo_.push_back(data[i]);
        UpdateRxIrq();
    }

protected:
    /* Per-SoC RX-interrupt line to the INTC; default no-op (UART has no RX
       consumer). i.MX51 UART2 -> Imx51Tzic source 32. */
    virtual void AssertRxIrq()   {}
    virtual void DeassertRxIrq() {}

private:
    static constexpr uint32_t kURXD = 0x00u, kUTXD = 0x40u;
    static constexpr uint32_t kUCR1 = 0x80u, kUCR2 = 0x84u;
    static constexpr uint32_t kUCR4 = 0x8Cu, kUFCR = 0x90u;
    static constexpr uint32_t kUSR1 = 0x94u, kUSR2 = 0x98u;
    static constexpr uint32_t kONEMS = 0xB0u, kUTS = 0xB4u;
    static constexpr uint32_t kCtrlLo = 0x80u, kCtrlHi = 0xB8u;

    /* RX-interrupt bits (MCIMX51RM Table 59-8 UCR1.RRDYEN b9 / Table 59-22:
       UCR4.RDREN b0 enable; USR1.RRDY b9 / USR2.RDR b0 flags; URXD.CHARRDY b15;
       UFCR.RXTL = bits 0..5 RxFIFO trigger level). */
    static constexpr uint32_t kUcr1Rrdyen = 1u << 9;
    static constexpr uint32_t kUcr4Rdren  = 1u << 0;
    static constexpr uint32_t kUsr1Rrdy   = 1u << 9;
    static constexpr uint32_t kUsr1Agtim  = 1u << 8;   /* RX aging-timer flag */
    static constexpr uint32_t kUsr2Rdr    = 1u << 0;
    static constexpr uint32_t kUrxdCharrdy = 1u << 15;
    static constexpr uint32_t kUfcrRxtlMask = 0x3Fu;

    /* SRST self-deasserts after a 4-cycle reset (MCIMX51RM §59.3.3.4); the reset is
       instant in emulation so UCR2 bit0 reads 1 always. Without this, a guest that
       writes SRST=0 then polls bit0 for completion (SBOOT UART3 init) spins forever. */
    static constexpr uint32_t kSrst = 0x0001u;

    /* ONEMS (0xB0) is 24-bit only on i.MX51 (MCIMX51RM §59.3.1); on i.MX31 every
       UART register including ONEMS is 16 LSB (MCIMX31RM §31.3.2). */
    static constexpr uint32_t kOnemsMask =
        (kSoc == SocId::Imx51) ? 0xFFFFFFu : 0xFFFFu;

    /* §59.3.3 reset values that ARE the idle TX-ready/RX-empty status: USR1.TRDY
       (0x2040), USR2.TXDC+TXFE (0x4028), UTS.TXEMPTY (0x60, TXFULL clear). */
    static constexpr uint32_t kUsr1Idle = 0x2040u;
    static constexpr uint32_t kUsr2Idle = 0x4028u;
    static constexpr uint32_t kUtsIdle  = 0x0060u;

    /* Control/baud regs 0x80..0xB8 step 4, reset values (MCIMX51RM Table 59-3 /
       MCIMX31RM Table 31-2). ONEMS (0xB0) is the only 24-bit register. */
    uint32_t ctrl_[15] = {
        0x0000u, 0x0001u, 0x0700u, 0x8000u, 0x0801u,  /* UCR1 UCR2 UCR3 UCR4 UFCR */
        0x2040u, 0x4028u, 0x002Bu, 0x0000u, 0x0000u,  /* USR1 USR2 UESC UTIM UBIR */
        0x0000u, 0x0004u, 0x0000u, 0x0060u, 0x0000u,  /* UBMR UBRC ONEMS UTS  UMCR */
    };
    std::string tx_line_;

    uint32_t RxTrigger() const {
        const uint32_t t = ctrl_[(kUFCR - kCtrlLo) / 4u] & kUfcrRxtlMask;
        return t == 0u ? 1u : t;
    }

    void UpdateRxIrq() {
        const uint32_t ucr1 = ctrl_[(kUCR1 - kCtrlLo) / 4u];
        const uint32_t ucr4 = ctrl_[(kUCR4 - kCtrlLo) / 4u];
        /* The RX aging timer (USR1.AGTIM, MCIMX51RM Table 59-22) delivers any
           pending RxFIFO data below RXTL, so a complete received frame always
           raises the interrupt regardless of the trigger level - assert on >=1
           byte whenever an RX-data interrupt source is enabled. */
        const bool rx_int_en = (ucr1 & kUcr1Rrdyen) || (ucr4 & kUcr4Rdren);
        if (rx_int_en && !rx_fifo_.empty()) AssertRxIrq();
        else                                DeassertRxIrq();
    }

    uint32_t Reg(uint32_t off) {
        if (off == kURXD) {
            if (rx_fifo_.empty()) return 0u;   /* CHARRDY=0 */
            const uint8_t b = rx_fifo_.front();
            rx_fifo_.pop_front();
            UpdateRxIrq();
            return b | kUrxdCharrdy;
        }
        if (off == kUTXD) return 0u;
        if (off == kUSR1) {
            const size_t n = rx_fifo_.size();
            uint32_t v = kUsr1Idle;
            if (n >= RxTrigger()) v |= kUsr1Rrdy;
            else if (n >= 1u)     v |= kUsr1Agtim;
            return v;
        }
        if (off == kUSR2)
            return kUsr2Idle | (rx_fifo_.empty() ? 0u : kUsr2Rdr);
        if (off == kUTS)  return kUtsIdle;
        if (off >= kCtrlLo && off <= kCtrlHi && (off & 3u) == 0u) {
            uint32_t v = ctrl_[(off - kCtrlLo) / 4u];
            if (off == kUCR2) v |= kSrst;   /* SRST self-deasserts (reset instant) */
            return v;
        }
        HaltUnsupportedAccess("Read", kBase + off, 0);
    }

    void Wr(uint32_t off, uint32_t v, uint32_t shift, uint32_t vmask) {
        const uint32_t aligned = off & ~3u;
        if (aligned == kUTXD) { EmitTx(static_cast<uint8_t>(v & 0xFFu)); return; }
        if (aligned == kUSR1 || aligned == kUSR2) return;  /* W1C status; idle */
        if (aligned >= kCtrlLo && aligned <= kCtrlHi) {
            /* Each register holds only its significant low bits; the upper bits of
               a 32-bit write are "not taken into account" (MCIMX51RM §59.3.1), so
               clamp the merge mask to the register's width. */
            const uint32_t regmax = (aligned == kONEMS) ? kOnemsMask : 0xFFFFu;
            const uint32_t m = (vmask << shift) & regmax;
            uint32_t& r = ctrl_[(aligned - kCtrlLo) / 4u];
            r = (r & ~m) | ((v << shift) & m);
            if (aligned == kUCR1 || aligned == kUCR4 || aligned == kUFCR)
                UpdateRxIrq();   /* enable/threshold changed */
            return;
        }
        HaltUnsupportedAccess("Write", kBase + off, v);
    }

    void EmitTx(uint8_t ch) {
        if (endpoint_) { endpoint_->OnGuestTx(ch); return; }
        char tag[8];
        std::snprintf(tag, sizeof(tag), "UART%d", kUartNum);
        emu_.Get<KernelDebugSink>().EmitChar(static_cast<char>(ch), tx_line_, tag);
    }

    UartEndpoint*        endpoint_ = nullptr;
    std::deque<uint8_t>  rx_fifo_;
    FreescaleSdmaBus*    sdma_bus_      = nullptr;
    uint32_t             rx_dma_event_  = 0;
};

}  /* namespace cerf_freescale_uart_detail */
