#include "pr31x00_uart.h"

#include "pr31x00_intc.h"
#include "pr31x00_io.h"

#include "../../boards/board_context.h"
#include "pr31500_id.h"
#include "pr31700_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../host/host_widget_registry.h"
#include "../../peripherals/serial/serial_cradle.h"
#include "../../peripherals/serial/serial_endpoint.h"
#include "../../state/state_stream.h"
#include "../../tracing/kernel_debug_sink.h"

#include <cstdint>
#include <utility>

namespace {

constexpr uint32_t kOffCtl1     = 0x00u;   /* $0B0 UARTA, $0C8 UARTB */
constexpr uint32_t kOffCtl2     = 0x04u;   /* write-only */
constexpr uint32_t kOffDmaCtl1  = 0x08u;   /* write-only */
constexpr uint32_t kOffDmaCtl2  = 0x0Cu;   /* write-only */
constexpr uint32_t kOffDmaCount = 0x10u;   /* read-only */
constexpr uint32_t kOffData     = 0x14u;   /* write TXHOLD, read RXHOLD */

/* UART Control 2 (§16.5.2), write-only: Baud Rate = f_UARTCLK / ((BAUDRATE + 1) * 16).
   The field is BAUDRATE[10:0] on the TMPR3912 parts and [9:0] on the TMPR3911, and the
   PR31700 carries the TMPR3912 internal function register map (R3912.H). */
constexpr uint32_t kCtl2BaudMask = 0x000007FFu;

/* f_UARTCLK / 16 = 230400: serial.dll sub_186311C writes BAUDRATE = 0x38400/baud - 1
   (0x38400 = 230400), so baud = 230400 / (BAUDRATE + 1). */
constexpr uint32_t kUartClkOver16 = 230400u;

/* UART DMA Control 1 (§16.5.3): DMASTARTVAL[31:2] is the DMA buffer's physical
   address; bits 1-0 reserved. DMA Control 2 (§16.5.4): DMALENGTH[15:0], which carries
   the buffer length MINUS ONE (§16.2.4), so serial.dll's 511 is a 512-byte buffer. */
constexpr uint32_t kDmaCtl1Reserved = 0x00000003u;
constexpr uint32_t kDmaCtl2Reserved = 0xFFFF0000u;
constexpr uint32_t kDmaLenMask      = 0x0000FFFFu;

/* Transmit Holding (§16.5.6), write-only: BREAK<8> TXDATA[7:0]. Setting BREAK with
   TXDATA $00 drives a line break until it is cleared. */
constexpr uint32_t kTxBreak        = 1u << 8;
constexpr uint32_t kTxDataMask     = 0x000000FFu;
constexpr uint32_t kTxHoldReserved = 0xFFFFFE00u;

/* UART Control 1 (§16.5.1): UARTON<31> EMPTY<30> PRXHOLDFULL<29> RXHOLDFULL<28>
   are read-only; ENUART<0> and the frame-format bits are R/W. EMPTY and DISTXD<6>
   are the only two bits that reset to 1, and UARTON reads 0 while the module is
   off - nk.exe sub_9F411310 stops the CPU only when it is. */
constexpr uint32_t kCtl1Reset = (1u << 30) | (1u << 6);

constexpr uint32_t kCtl1Uarton   = 1u << 31;
constexpr uint32_t kCtl1Empty    = 1u << 30;
constexpr uint32_t kCtl1Reserved = 0x0FFF0000u;
constexpr uint32_t kCtl1DisTxd   = 1u << 6;
constexpr uint32_t kCtl1EnUart   = 1u << 0;

/* ENDMARX<15>/ENDMALOOP<10> arm a circular RX DMA: serial.dll sub_1862BDC opens COM1
   with CTL1 |= 0x8401 (ENDMARX|ENDMALOOP|ENUART). ENDMATX<14>, ENBREAKHALT<12>,
   LOOPBACK<4> and the IC-test bits (13/11) stay unmodeled (§16.5.1). */
constexpr uint32_t kCtl1EnDmaRx   = 1u << 15;
constexpr uint32_t kCtl1EnDmaLoop = 1u << 10;
constexpr uint32_t kCtl1Unmodeled = 0x00007810u;
constexpr uint32_t kCtl1Writable  = 0x000087EFu;

/* Frame format (§16.5.1): BIT_7<3> selects a 7-bit character, ENPARITY<1> enables
   parity with EVENPARITY<2> selecting even, TWOSTOP<5> selects two stop bits. */
constexpr uint32_t kCtl1Bit7       = 1u << 3;
constexpr uint32_t kCtl1EvenParity = 1u << 2;
constexpr uint32_t kCtl1EnParity   = 1u << 1;
constexpr uint32_t kCtl1TwoStop    = 1u << 5;

}  /* namespace */

bool Pr31x00Uart::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd) return false;
    const std::string_view soc = bd->GetSocId();
    return soc == SocId::Pr31500 || soc == SocId::Pr31700;
}

void Pr31x00Uart::OnReady() {
    ctl1_ = kCtl1Reset & kCtl1Writable;
    emu_.Get<PeripheralDispatcher>().Register(this);

    rx_dma_ = std::make_unique<Pr31x00UartRxDma>(emu_, TxSource());
    rx_dma_->Start([this](const Pr31x00UartRxDma::RxInts& i) { RaiseRxInts(i); },
                   [this] { OnRxLineIdle(); });

    auto* wiring = emu_.TryGet<Pr31x00SerialWiring>();
    if (!wiring) return;
    modem_ = wiring->ForUart(MmioBase());
    if (!modem_) return;

    auto& io = emu_.Get<Pr31x00Io>();
    io.RegisterMfioOutObserver([this](uint32_t v, uint32_t m) { OnMfioOut(v, m); });
    io.RegisterIoOutObserver([this](uint32_t v, uint32_t m) { OnIoOut(v, m); });

    /* No endpoint is attached yet. The lines are active low, so leaving their pins
       at the 0 they reset to reads as CTS and carrier already asserted - on the Velo
       that also fires the driver's carrier-detect system event (sub_1EB2750). */
    SetModemInputs(false, false, false, false);

    cradle_ = std::make_unique<SerialCradle>(emu_, *this, modem_->label);
    emu_.Get<HostWidgetRegistry>().Register(cradle_.get());
    LOG(Periph, "[UART] %s attached as serial endpoint line '%ls'\n",
        TxSource(), modem_->label.c_str());
}

Pr31x00Uart::Pr31x00Uart(CerfEmulator& emu) : Peripheral(emu) {}

Pr31x00Uart::~Pr31x00Uart() = default;

/* The pacing thread reaches the endpoint through the drain callback, so it stops before
   the cradle tears that endpoint down. */
void Pr31x00Uart::OnShutdown() {
    rx_dma_->Stop();
    if (cradle_) cradle_->OnShutdown();
}

/* The transmit holding and shift registers drain within the access that fills them,
   so EMPTY never falls and UARTON tracks ENUART with no shutdown delay. RX bytes go
   to the DMA buffer, not the holding register, so PRXHOLDFULL/RXHOLDFULL stay clear. */
uint32_t Pr31x00Uart::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
        case kOffCtl1: {
            std::lock_guard<std::mutex> lk(mu_);
            uint32_t v = (ctl1_ & kCtl1Writable) | kCtl1Empty;
            if (ctl1_ & kCtl1EnUart) v |= kCtl1Uarton;
            return v;
        }

        /* DMA_COUNT (§16.5.5), read-only: the receive DMA's own address counter. The
           driver adds it to the buffer base to find the write offset and copies up to
           there (serial.dll sub_1EB2620), keeping its read cursor privately. */
        case kOffDmaCount: return rx_dma_->Count();

        default: HaltUnsupportedAccess("PR31x00 UART ReadWord", addr, 0);
    }
}

void Pr31x00Uart::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
        case kOffCtl1: WriteCtl1(addr, value); return;

        case kOffCtl2:
            if (value & ~kCtl2BaudMask) {
                HaltUnsupportedAccess("PR31x00 UART CTL2 reserved", addr, value);
            }
            { std::lock_guard<std::mutex> lk(mu_); ctl2_baud_ = value & kCtl2BaudMask; }
            FireLineConfig();
            return;

        case kOffDmaCtl1:
            if (value & kDmaCtl1Reserved) {
                HaltUnsupportedAccess("PR31x00 UART DMA_CTL1 reserved", addr, value);
            }
            rx_dma_->SetBuffer(value);
            return;

        case kOffDmaCtl2:
            if (value & kDmaCtl2Reserved) {
                HaltUnsupportedAccess("PR31x00 UART DMA_CTL2 reserved", addr, value);
            }
            rx_dma_->SetLength((value & kDmaLenMask) + 1u);
            return;

        case kOffData: WriteTxHold(addr, value); return;

        default: HaltUnsupportedAccess("PR31x00 UART WriteWord", addr, value);
    }
}

void Pr31x00Uart::WriteCtl1(uint32_t addr, uint32_t value) {
    if (value & kCtl1Reserved) {
        HaltUnsupportedAccess("PR31x00 UART CTL1 reserved", addr, value);
    }
    if (value & kCtl1Unmodeled) {
        HaltUnsupportedAccess("PR31x00 UART CTL1 unmodeled control", addr, value);
    }
    /* ENDMALOOP clear stops the DMA when it reaches the end of the buffer (§16.2.4);
       only the looping channel is modelled. */
    if ((value & kCtl1EnDmaRx) && !(value & kCtl1EnDmaLoop)) {
        HaltUnsupportedAccess("PR31x00 UART RX DMA armed without ENDMALOOP", addr, value);
    }
    {
        std::lock_guard<std::mutex> lk(mu_);
        ctl1_ = value & kCtl1Writable;   /* UARTON, EMPTY, PRXHOLDFULL, RXHOLDFULL are read-only */
    }
    rx_dma_->SetArmed((value & kCtl1EnDmaRx) != 0u);
    FireLineConfig();
}

/* DISTXD disconnects TXD from the pin, so a byte written while it is set never
   reaches the wire; when an endpoint is attached its stream replaces the debug sink. */
void Pr31x00Uart::WriteTxHold(uint32_t addr, uint32_t value) {
    if (value & kTxHoldReserved) {
        HaltUnsupportedAccess("PR31x00 UART TXHOLD reserved", addr, value);
    }
    if (value & kTxBreak) {
        HaltUnsupportedAccess("PR31x00 UART TXHOLD BREAK", addr, value);
    }

    {
        std::lock_guard<std::mutex> lk(mu_);
        if ((ctl1_ & kCtl1EnUart) == 0u || (ctl1_ & kCtl1DisTxd) != 0u) {
            return;
        }
    }

    const uint8_t byte = static_cast<uint8_t>(value & kTxDataMask);
    {
        std::lock_guard<std::recursive_mutex> elk(endpoint_mu_);
        if (endpoint_) {
            endpoint_->OnGuestTx(&byte, 1);
            if (cradle_) cradle_->MarkTx();
        } else {
            emu_.Get<KernelDebugSink>().EmitChar(static_cast<char>(byte), tx_line_,
                                                 TxSource());
        }
    }
    emu_.Get<Pr31x00Intc>().SetPending(1, TxEmptyIntBit() | TxAvailIntBit());
}

void Pr31x00Uart::PushRx(const uint8_t* data, size_t n) {
    if (n == 0) return;
    {
        std::lock_guard<std::mutex> lk(mu_);
        /* The receiver is off, so nothing reaches the Receive Holding Register. */
        if ((ctl1_ & kCtl1EnUart) == 0u) return;
        /* ENUART without ENDMARX leaves each byte in the Receive Holding Register for
           the CPU to read (§16.2.4). serial.dll sets and clears the two together (Open
           sub_1EB3374 CTL1 |= 0x8401, Close sub_1EB3550 CTL1 &= ~0x8401), so that path
           never runs and the holding-register receive is not modelled. */
        if ((ctl1_ & kCtl1EnDmaRx) == 0u) {
            HaltUnsupportedAccess("PR31x00 UART receive with no RX DMA armed",
                                  MmioBase(), ctl1_);
        }
    }
    /* An armed channel whose DMA_CTL2 was never written has no buffer to fill. */
    if (rx_dma_->Length() == 0u) {
        HaltUnsupportedAccess("PR31x00 UART RX DMA armed with no DMALENGTH programmed",
                              MmioBase(), 0);
    }
    rx_dma_->Receive(data, n);
    if (cradle_) cradle_->MarkRx();
}

/* The wire, not the guest's buffer: the DMA engine cannot tell how far the driver has
   read, so a feeder is free to send again once its bytes have all been clocked out. */
bool Pr31x00Uart::RxEmpty() const {
    return rx_dma_->LineIdle();
}

void Pr31x00Uart::OnRxLineIdle() {
    std::lock_guard<std::recursive_mutex> elk(endpoint_mu_);
    if (rx_drain_cb_) rx_drain_cb_();
}

void Pr31x00Uart::RaiseRxInts(const Pr31x00UartRxDma::RxInts& ints) {
    uint32_t bits = 0;
    if (ints.rx)       bits |= RxIntBit();
    if (ints.dma_half) bits |= DmaHalfIntBit();
    if (ints.dma_full) bits |= DmaFullIntBit();
    emu_.Get<Pr31x00Intc>().SetPending(1, bits);
}

void Pr31x00Uart::SetRxDrainCallback(RxDrainFn cb) {
    std::lock_guard<std::recursive_mutex> elk(endpoint_mu_);
    rx_drain_cb_ = std::move(cb);
}

/* An asserted line drives its pin low (Nino GetModemStatus sub_1861A68 takes CTS on
   (MFIODIN & 0x40)==0; Velo sub_1EB1F04 takes CTS on (MFIODIN & 0x40000000)==0 and
   DCD on (IODIN & 0x10)==0), so the level handed to the pin is the inverse. */
void Pr31x00Uart::SetModemInputs(bool cts, bool dsr, bool ri, bool dcd) {
    if (!modem_) return;
    DriveModemInput(modem_->cts, cts);
    DriveModemInput(modem_->dcd, dcd);
    DriveModemInput(modem_->dsr, dsr);
    DriveModemInput(modem_->ri,  ri);
}

void Pr31x00Uart::DriveModemInput(const Pr31x00SerialPin& p, bool asserted) {
    if (!p.Wired()) return;
    auto&          io  = emu_.Get<Pr31x00Io>();
    const uint32_t pin = static_cast<uint32_t>(p.pin);
    if (p.bank == Pr31x00SerialPin::Bank::Mfio) io.DriveMfioInput(pin, !asserted);
    else                                        io.DriveIoInput(pin, !asserted);
}

SerialLine::LineConfig Pr31x00Uart::ComputeLineConfigLocked() const {
    LineConfig c;
    c.baud      = kUartClkOver16 / (ctl2_baud_ + 1u);
    c.data_bits = (ctl1_ & kCtl1Bit7) ? 7u : 8u;
    if ((ctl1_ & kCtl1EnParity) == 0u) c.parity = LineConfig::Parity::None;
    else c.parity = (ctl1_ & kCtl1EvenParity) ? LineConfig::Parity::Even
                                              : LineConfig::Parity::Odd;
    c.stop = (ctl1_ & kCtl1TwoStop) ? LineConfig::Stop::Two : LineConfig::Stop::One;
    return c;
}

SerialLine::LineConfig Pr31x00Uart::GetLineConfig() const {
    std::lock_guard<std::mutex> lk(mu_);
    return ComputeLineConfigLocked();
}

void Pr31x00Uart::SetLineConfigCallback(LineConfigFn cb) {
    std::lock_guard<std::recursive_mutex> elk(endpoint_mu_);
    line_cfg_cb_ = std::move(cb);
}

void Pr31x00Uart::FireLineConfig() {
    LineConfig cfg;
    { std::lock_guard<std::mutex> lk(mu_); cfg = ComputeLineConfigLocked(); }
    rx_dma_->SetLineRate(cfg.baud, cfg.BitsPerChar());
    std::lock_guard<std::recursive_mutex> elk(endpoint_mu_);
    if (line_cfg_cb_) line_cfg_cb_(cfg);
}

void Pr31x00Uart::SetEndpoint(SerialEndpoint* ep) {
    bool dtr, rts;
    { std::lock_guard<std::mutex> lk(mu_); dtr = dtr_; rts = rts_; }
    std::lock_guard<std::recursive_mutex> elk(endpoint_mu_);
    endpoint_ = ep;
    if (ep) ep->OnControlLines(dtr, rts);
}

/* SET_DTR/SET_RTS clear the pin's bit, so an asserted output reads low. DTR and RTS
   can sit in different banks (Velo RTS on MFIODOUT<31>, DTR on IODOUT<3>), so each
   bank's latest value is kept and both lines recomputed from whichever one moved. */
bool Pr31x00Uart::AssertedLocked(const Pr31x00SerialPin& p) const {
    if (!p.Wired()) return false;
    const bool     mfio = p.bank == Pr31x00SerialPin::Bank::Mfio;
    const uint32_t dout = mfio ? mfio_dout_ : io_dout_;
    const uint32_t mask = mfio ? mfio_out_mask_ : io_out_mask_;
    const uint32_t bit  = 1u << p.pin;
    /* The pins reset to inputs, so an undriven line is not asserted even though its
       DOUT bit reads 0. */
    if ((mask & bit) == 0u) return false;
    return (dout & bit) == 0u;
}

bool Pr31x00Uart::RecomputeControlLocked(bool& dtr, bool& rts) {
    const bool nd = AssertedLocked(modem_->dtr);
    const bool nr = AssertedLocked(modem_->rts);
    if (nd == dtr_ && nr == rts_) return false;
    dtr_ = nd;
    rts_ = nr;
    dtr  = nd;
    rts  = nr;
    return true;
}

void Pr31x00Uart::NotifyControlLines(bool dtr, bool rts) {
    std::lock_guard<std::recursive_mutex> elk(endpoint_mu_);
    if (endpoint_) endpoint_->OnControlLines(dtr, rts);
}

void Pr31x00Uart::OnMfioOut(uint32_t mfio_dout, uint32_t out_mask) {
    bool dtr, rts;
    {
        std::lock_guard<std::mutex> lk(mu_);
        mfio_dout_     = mfio_dout;
        mfio_out_mask_ = out_mask;
        if (!RecomputeControlLocked(dtr, rts)) return;
    }
    NotifyControlLines(dtr, rts);
}

void Pr31x00Uart::OnIoOut(uint32_t io_dout, uint32_t out_mask) {
    bool dtr, rts;
    {
        std::lock_guard<std::mutex> lk(mu_);
        io_dout_     = io_dout;
        io_out_mask_ = out_mask;
        if (!RecomputeControlLocked(dtr, rts)) return;
    }
    NotifyControlLines(dtr, rts);
}

/* Every insert and eject takes SerialCradle::mtx_ and then this mu_ (SetEndpoint,
   GetLineConfig), so mu_ is dropped before the cradle is asked for its own state:
   holding it across that call is the opposite order and deadlocks a save against a
   user ejecting the card. */
void Pr31x00Uart::SaveState(StateWriter& w) {
    /* Not named ctl1: dlgs.h (via windows.h) defines that as a dialog control id. */
    uint32_t ctl1_v, baud, mfio_dout, mfio_mask, io_dout, io_mask;
    uint8_t  dtr, rts;
    {
        std::lock_guard<std::mutex> lk(mu_);
        ctl1_v    = ctl1_;
        baud      = ctl2_baud_;
        mfio_dout = mfio_dout_;
        mfio_mask = mfio_out_mask_;
        io_dout   = io_dout_;
        io_mask   = io_out_mask_;
        dtr       = dtr_ ? 1u : 0u;
        rts       = rts_ ? 1u : 0u;
    }
    w.Write("ctl1_v", ctl1_v);
    w.Write("baud", baud);
    w.Write("mfio_dout", mfio_dout);
    w.Write("mfio_mask", mfio_mask);
    w.Write("io_dout", io_dout);
    w.Write("io_mask", io_mask);
    w.Write("dtr", dtr);
    w.Write("rts", rts);
    rx_dma_->SaveState(w);
    if (cradle_) cradle_->SaveCradleState(w);
}

void Pr31x00Uart::RestoreState(StateReader& r) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        r.Read("ctl1_v", ctl1_);
        r.Read("baud", ctl2_baud_);
        r.Read("mfio_dout", mfio_dout_);
        r.Read("mfio_mask", mfio_out_mask_);
        r.Read("io_dout", io_dout_);
        r.Read("io_mask", io_out_mask_);
        uint8_t b = 0;
        r.Read("dtr", b); dtr_ = b != 0;
        r.Read("rts", b); rts_ = b != 0;
    }
    {
        std::lock_guard<std::recursive_mutex> elk(endpoint_mu_);
        endpoint_ = nullptr;
        rx_drain_cb_ = nullptr;
        line_cfg_cb_ = nullptr;
    }
    rx_dma_->RestoreState(r);
    if (cradle_) cradle_->RestoreCradleState(r);
}

/* RestoreState detaches the line's endpoint, and WriteTxHold routes guest TX to the
   debug sink whenever no endpoint is bound, so a restored port only carries traffic
   once the cradle re-inserts the card it saved. The DMA engine's clock rate is derived
   from CTL1 and CTL2, so it is re-applied once both are back. */
void Pr31x00Uart::PostRestore() {
    LineConfig cfg;
    { std::lock_guard<std::mutex> lk(mu_); cfg = ComputeLineConfigLocked(); }
    rx_dma_->SetLineRate(cfg.baud, cfg.BitsPerChar());
    if (cradle_) cradle_->PostRestore();
}
