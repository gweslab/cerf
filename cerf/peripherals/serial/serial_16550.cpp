#include "serial_16550.h"

#include "serial_endpoint.h"
#include "../../core/log.h"
#include "../../host/host_widget.h"
#include "../../state/state_stream.h"

#include <utility>

namespace {
constexpr uint32_t kRbrThrDll = 0;   /* RBR/THR, or DLL when LCR.DLAB */
constexpr uint32_t kIerDlm    = 1;   /* IER,     or DLM when LCR.DLAB */
constexpr uint32_t kIirFcr    = 2;   /* IIR (r) / FCR (w)             */
constexpr uint32_t kLcr       = 3;
constexpr uint32_t kMcr       = 4;
constexpr uint32_t kLsr       = 5;
constexpr uint32_t kMsr       = 6;
constexpr uint32_t kScr       = 7;

constexpr uint8_t IER_RDA = 0x01, IER_THR = 0x02, IER_RLS = 0x04, IER_MS = 0x08;

constexpr uint8_t IIR_NONE = 0x01;
constexpr uint8_t IIR_RLS  = 0x06, IIR_RDA = 0x04, IIR_CTI = 0x0C,
                  IIR_THRE = 0x02, IIR_MS  = 0x00;
constexpr uint8_t IIR_FIFO_BITS = 0xC0;
constexpr uint8_t kNoSource     = 0xFF;   /* sentinel (IIR_MS is 0x00) */

constexpr uint8_t FCR_ENABLE = 0x01, FCR_RCVR_RESET = 0x02;

constexpr uint8_t LCR_DLAB = 0x80;

constexpr uint8_t MCR_DTR = 0x01, MCR_RTS = 0x02, MCR_OUT1 = 0x04,
                  MCR_OUT2 = 0x08, MCR_LOOP = 0x10;

constexpr uint8_t LSR_DR = 0x01, LSR_THRE = 0x20, LSR_TEMT = 0x40;
constexpr uint8_t LSR_RLS_BITS = 0x1E;   /* OE|PE|FE|BI: generate the RLS intr */

constexpr uint8_t MSR_DCTS = 0x01, MSR_DDSR = 0x02, MSR_TERI = 0x04,
                  MSR_DDCD = 0x08;
constexpr uint8_t MSR_CTS = 0x10, MSR_DSR = 0x20, MSR_RI = 0x40, MSR_DCD = 0x80;
constexpr uint8_t MSR_DELTAS = MSR_DCTS | MSR_DDSR | MSR_TERI | MSR_DDCD;

/* Backlog cap for a feeder with no flow control: a guest that stops draining otherwise
   grows the queue without limit and is later handed the whole stale burst. */
constexpr size_t kRxMax = 64u * 1024u;
}  /* namespace */

/* FCR bits 7:6 select the RX FIFO trigger; FIFO disabled triggers at 1 byte. */
size_t Serial16550::RxTriggerLocked() const {
    if (!(fcr_ & FCR_ENABLE)) return 1;
    return cfg_.rx_trigger[(fcr_ >> 6) & 3u];
}

Serial16550::Serial16550(SerialEndpoint* endpoint, IrqLineFn irq_line, Config cfg)
    : irq_line_(std::move(irq_line)), cfg_(cfg), endpoint_(endpoint) {
    Reset();
}

bool Serial16550::DeliverTxToEndpoint(uint8_t byte) {
    std::lock_guard<std::recursive_mutex> elk(endpoint_mu_);
    if (!endpoint_) return false;
    endpoint_->OnGuestTx(&byte, 1);
    return true;
}

void Serial16550::DeliverTx(uint8_t byte) { DeliverTxToEndpoint(byte); }

/* A personality plugged after the guest has already raised DTR/RTS would otherwise start
   with them believed low and read the next edge as a hang-up. */
void Serial16550::SetEndpoint(SerialEndpoint* endpoint) {
    bool dtr, rts;
    {
        std::lock_guard<std::mutex> lk(mu_);
        dtr = (mcr_ & MCR_DTR) != 0;
        rts = (mcr_ & MCR_RTS) != 0;
    }
    std::lock_guard<std::recursive_mutex> elk(endpoint_mu_);
    endpoint_ = endpoint;
    if (endpoint) endpoint->OnControlLines(dtr, rts);
}

void Serial16550::Reset() {
    ResetRegisters();
    ResendEndpointInputs();
}

void Serial16550::ResetRegisters() {
    std::lock_guard<std::mutex> lk(mu_);
    ier_ = fcr_ = lcr_ = mcr_ = lsr_ = msr_ = scr_ = 0;
    dll_ = dlm_ = 0;
    thre_armed_ = false;
    rx_.clear();
    rx_pos_ = 0;
    if (last_irq_level_) { last_irq_level_ = false; irq_line_(false); }
}

void Serial16550::ResendEndpointInputs() {
    std::lock_guard<std::recursive_mutex> elk(endpoint_mu_);
    if (endpoint_) endpoint_->ResendModemInputs();
}

uint32_t Serial16550::BaudRate() const {
    std::lock_guard<std::mutex> lk(mu_);
    const uint32_t div = (uint32_t)dll_ | ((uint32_t)dlm_ << 8);
    return div ? (115200u / div) : 115200u;
}

Serial16550::LineConfig Serial16550::GetLineConfigLocked() const {
    LineConfig c;
    const uint32_t div = (uint32_t)dll_ | ((uint32_t)dlm_ << 8);
    c.baud = div ? (115200u / div) : 115200u;
    c.data_bits = (uint8_t)(5u + (lcr_ & 0x03u));
    if (!(lcr_ & 0x08u)) {
        c.parity = LineConfig::Parity::None;        /* parity disabled */
    } else {
        switch (lcr_ & 0x38u) {
            case 0x08u: c.parity = LineConfig::Parity::Odd;   break;
            case 0x18u: c.parity = LineConfig::Parity::Even;  break;
            case 0x28u: c.parity = LineConfig::Parity::Mark;  break;
            default:    c.parity = LineConfig::Parity::Space; break;   /* 0x38 */
        }
    }
    if (!(lcr_ & 0x04u))      c.stop = LineConfig::Stop::One;
    else if (c.data_bits == 5) c.stop = LineConfig::Stop::OnePointFive;
    else                       c.stop = LineConfig::Stop::Two;
    return c;
}

Serial16550::LineConfig Serial16550::GetLineConfig() const {
    std::lock_guard<std::mutex> lk(mu_);
    return GetLineConfigLocked();
}

void Serial16550::SetLineConfigCallback(LineConfigFn cb) {
    std::lock_guard<std::recursive_mutex> elk(endpoint_mu_);
    line_cfg_cb_ = std::move(cb);
}

/* Highest-priority enabled pending source, or kNoSource. The character-timeout source
   is FIFO-mode only and carries its own enable on parts that separate it from RDA. */
uint8_t Serial16550::PendingSourceLocked() const {
    const size_t rx_avail = RxAvailLocked();
    if ((ier_ & IER_RLS) && (lsr_ & LSR_RLS_BITS)) return IIR_RLS;
    if ((ier_ & IER_RDA) && rx_avail >= RxTriggerLocked()) return IIR_RDA;
    if ((ier_ & cfg_.cti_ier_bit) && (fcr_ & FCR_ENABLE) && rx_avail > 0) return IIR_CTI;
    if ((ier_ & IER_THR) && thre_armed_) return IIR_THRE;
    if ((ier_ & IER_MS) && (msr_ & MSR_DELTAS)) return IIR_MS;
    return kNoSource;
}

/* PC16550D §8.6.6: "Disabling an interrupt prevents it from being indicated as active in
   the IIR and from activating the INTR output signal." */
bool Serial16550::ComputeIrqLevelLocked() const {
    if ((mcr_ & cfg_.irq_gate_mcr) != cfg_.irq_gate_mcr) return false;
    if ((ier_ & cfg_.irq_gate_ier) != cfg_.irq_gate_ier) return false;
    return PendingSourceLocked() != kNoSource;
}

void Serial16550::SettleAndFireIrq() {
    const bool level = ComputeIrqLevelLocked();
    if (level != last_irq_level_) {
        last_irq_level_ = level;
        irq_line_(level);   /* safe under mu_: the slot IRQ path never re-enters
                               this UART, and serializing the call here prevents
                               two threads racing stale levels onto the line. */
    }
}

uint8_t Serial16550::ReadIirLocked() {
    const uint8_t src  = PendingSourceLocked();
    const uint8_t fifo = (fcr_ & FCR_ENABLE) ? IIR_FIFO_BITS : 0;
    if (src == kNoSource) return IIR_NONE | fifo;
    if (src == IIR_THRE) thre_armed_ = false;   /* IIR read clears THRE source */
    return src | fifo;
}

uint8_t Serial16550::ReadReg8(uint32_t offset) {
    uint8_t result = 0xFF;
    bool drained = false;
    {
    std::lock_guard<std::mutex> lk(mu_);
    switch (offset & 7u) {
        case kRbrThrDll:
            if (lcr_ & LCR_DLAB) { result = dll_; break; }
            if (RxAvailLocked() > 0) {
                result = rx_[rx_pos_++];
                if (rx_pos_ == rx_.size()) { rx_.clear(); rx_pos_ = 0; drained = true; }
            } else {
                result = 0;
            }
            break;
        case kIerDlm: result = (lcr_ & LCR_DLAB) ? dlm_ : ier_; break;
        case kIirFcr: result = ReadIirLocked(); break;
        case kLcr:    result = lcr_; break;
        case kMcr:    result = mcr_; break;
        case kLsr:
            /* TX is drained instantly, so THRE+TEMT always read set. */
            result = (uint8_t)(lsr_ | LSR_THRE | LSR_TEMT);
            if (RxAvailLocked() > 0) result |= LSR_DR;
            lsr_ &= (uint8_t)~LSR_RLS_BITS;     /* reading LSR clears error/break */
            break;
        case kMsr:
            result = msr_;
            msr_ &= (uint8_t)~MSR_DELTAS;       /* reading MSR clears delta bits  */
            break;
        case kScr: result = scr_; break;
    }
    SettleAndFireIrq();
    }
    if (drained) {                           /* off-lock: feeder pushes next */
        std::lock_guard<std::recursive_mutex> elk(endpoint_mu_);
        if (rx_drain_) rx_drain_();
    }
    return result;
}

void Serial16550::WriteReg8(uint32_t offset, uint8_t value) {
    uint8_t tx_byte = 0;
    bool do_tx = false, loop_tx = false, notify_lines = false, dtr = false,
         rts = false, line_changed = false;
    LineConfig   line_cfg;
    {
        std::lock_guard<std::mutex> lk(mu_);
        switch (offset & 7u) {
            case kRbrThrDll:
                if (lcr_ & LCR_DLAB) { dll_ = value; line_changed = true; break; }
                /* THR write: byte goes out, THR re-empties -> THRE re-arms. */
                thre_armed_ = true;
                tx_byte = value;
                if (mcr_ & MCR_LOOP) loop_tx = true; else do_tx = true;
                break;
            case kIerDlm:
                if (lcr_ & LCR_DLAB) { dlm_ = value; line_changed = true; break; }
                /* PC16550D §8.6.3 bit 5: THRE "causes the UART to issue an interrupt to
                   the CPU when the [THRE] Interrupt enable is set high", so a driver that
                   starts transmitting by arming TIE gets that first interrupt. */
                if (!(ier_ & IER_THR) && (value & IER_THR)) thre_armed_ = true;
                ier_ = value & cfg_.ier_mask;
                break;
            case kIirFcr:
                fcr_ = value;
                if (value & FCR_RCVR_RESET) { rx_.clear(); rx_pos_ = 0; }
                break;
            case kLcr: lcr_ = value; line_changed = true; break;
            case kMcr: {
                const uint8_t old = mcr_;
                mcr_ = value & 0x1Fu;
                if (mcr_ & MCR_LOOP) {
                    uint8_t lvl = 0;
                    if (mcr_ & MCR_RTS)  lvl |= MSR_CTS;
                    if (mcr_ & MCR_DTR)  lvl |= MSR_DSR;
                    if (mcr_ & MCR_OUT1) lvl |= MSR_RI;
                    if (mcr_ & MCR_OUT2) lvl |= MSR_DCD;
                    const uint8_t diff = (uint8_t)((lvl ^ msr_) & 0xF0u);
                    uint8_t d = msr_ & MSR_DELTAS;
                    if (diff & MSR_CTS) d |= MSR_DCTS;
                    if (diff & MSR_DSR) d |= MSR_DDSR;
                    if (diff & MSR_RI)  d |= MSR_TERI;
                    if (diff & MSR_DCD) d |= MSR_DDCD;
                    msr_ = (uint8_t)(lvl | d);
                }
                if ((old ^ mcr_) & (MCR_DTR | MCR_RTS)) {
                    notify_lines = true;
                    dtr = (mcr_ & MCR_DTR) != 0;
                    rts = (mcr_ & MCR_RTS) != 0;
                }
                break;
            }
            case kLsr: case kMsr: break;   /* read-only */
            case kScr: scr_ = value; break;
        }
        SettleAndFireIrq();
        if (line_changed) line_cfg = GetLineConfigLocked();
    }
    /* Off-lock: the endpoint may call back into PushRx (re-locks mu_). */
    if (do_tx) {
        DeliverTx(tx_byte);
        if (activity_) activity_->MarkTx();
    }
    if (loop_tx) PushRx(&tx_byte, 1);

    if (!notify_lines && !line_changed) return;
    std::lock_guard<std::recursive_mutex> elk(endpoint_mu_);
    if (notify_lines && endpoint_) endpoint_->OnControlLines(dtr, rts);
    if (line_changed && line_cfg_cb_) line_cfg_cb_(line_cfg);
}

bool Serial16550::RxEmpty() const {
    std::lock_guard<std::mutex> lk(mu_);
    return RxAvailLocked() == 0;
}

void Serial16550::SetRxDrainCallback(RxDrainFn cb) {
    std::lock_guard<std::recursive_mutex> elk(endpoint_mu_);
    rx_drain_ = std::move(cb);
}

void Serial16550::PushRx(const uint8_t* data, size_t n) {
    if (n == 0) return;
    if (activity_) activity_->MarkRx();
    std::lock_guard<std::mutex> lk(mu_);
    if (rx_pos_ == rx_.size()) { rx_.clear(); rx_pos_ = 0; }
    else if (rx_pos_ > 4096) { rx_.erase(rx_.begin(), rx_.begin() + rx_pos_); rx_pos_ = 0; }
    if (RxAvailLocked() + n > kRxMax) {
        LOG(Caution, "[16550] RX overrun: the guest is not draining the receiver, "
                     "dropping %zu bytes\n", n);
        return;
    }
    rx_.insert(rx_.end(), data, data + n);
    SettleAndFireIrq();
}

void Serial16550::SaveState(StateWriter& w) const {
    std::lock_guard<std::mutex> lk(mu_);
    w.Write("ier", ier_); w.Write("fcr", fcr_); w.Write("lcr", lcr_); w.Write("mcr", mcr_);
    w.Write("lsr", lsr_); w.Write("msr", msr_); w.Write("scr", scr_);
    w.Write("dll", dll_); w.Write("dlm", dlm_);
    w.Write<uint8_t>("thre_armed", thre_armed_ ? 1u : 0u);
    w.Write<uint64_t>("rx_count", rx_.size());
    if (!rx_.empty()) w.WriteBytes("rx", rx_.data(), rx_.size());
    w.Write<uint64_t>("rx_pos", rx_pos_);
}

void Serial16550::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mu_);
    r.Read("ier", ier_); r.Read("fcr", fcr_); r.Read("lcr", lcr_); r.Read("mcr", mcr_);
    r.Read("lsr", lsr_); r.Read("msr", msr_); r.Read("scr", scr_);
    r.Read("dll", dll_); r.Read("dlm", dlm_);
    uint8_t armed = 0; r.Read("thre_armed", armed); thre_armed_ = (armed != 0);
    uint64_t n = 0; r.Read("rx_count", n);
    rx_.assign(static_cast<size_t>(n), 0u);
    if (n) r.ReadBytes("rx", rx_.data(), static_cast<size_t>(n));
    uint64_t pos = 0; r.Read("rx_pos", pos);
    rx_pos_ = static_cast<size_t>(pos);
}

void Serial16550::RepublishIrq() {
    std::lock_guard<std::mutex> lk(mu_);
    last_irq_level_ = ComputeIrqLevelLocked();
    irq_line_(last_irq_level_);
}

void Serial16550::SetModemInputs(bool cts, bool dsr, bool ri, bool dcd) {
    std::lock_guard<std::mutex> lk(mu_);
    if (mcr_ & MCR_LOOP) return;   /* loopback owns MSR; ignore external inputs */
    const uint8_t lvl = (uint8_t)((cts ? MSR_CTS : 0) | (dsr ? MSR_DSR : 0) |
                                  (ri ? MSR_RI : 0) | (dcd ? MSR_DCD : 0));
    const uint8_t old = msr_ & 0xF0u;
    const uint8_t diff = old ^ lvl;
    uint8_t d = msr_ & MSR_DELTAS;
    if (diff & MSR_CTS) d |= MSR_DCTS;
    if (diff & MSR_DSR) d |= MSR_DDSR;
    if ((old & MSR_RI) && !(lvl & MSR_RI)) d |= MSR_TERI;   /* RI trailing edge */
    if (diff & MSR_DCD) d |= MSR_DDCD;
    msr_ = (uint8_t)(lvl | d);
    SettleAndFireIrq();
}
