#include "sa11xx_uart_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../tracing/kernel_debug_sink.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "sa11xx_intc.h"
#include "sa11xx_uart_receiver.h"
#include "sa11xx_uart_regs.h"
#include "sa11xx_uart_transmitter.h"

#include <string>

using namespace sa11xx_uart;

namespace {

/* SA-1110 §11.11.7 UTSR0 (printed 11-122): TFS 0; §11.11.8 UTSR1 (printed 11-125): TBY 0,
   TNF 2. */
constexpr uint32_t kUtsr0Tfs = 1u << 0;
constexpr uint32_t kUtsr1Tby = 1u << 0;
constexpr uint32_t kUtsr1Tnf = 1u << 2;

}

bool Sa11xxUartBase::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
}

void Sa11xxUartBase::OnReady() {
    clock_ = &emu_.Get<GuestCycleClock>();
    tx_    = &emu_.Get<Sa11xxUartTransmitter>();
    rx_    = &emu_.Get<Sa11xxUartReceiver>();
    port_    = tx_->Attach(this, MmioBase() + 0x14u, TransmitDeviceSelect(), ChannelName());
    rx_port_ = rx_->Attach(this, MmioBase() + 0x14u, ReceiveDeviceSelect(), ChannelName());
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) { OnResetLine(); });
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void Sa11xxUartBase::FlushLine() {
    std::string ascii;
    for (uint8_t b : tx_line_) {
        ascii.push_back((b >= 0x20 && b < 0x7F) ? char(b) : '.');
    }
    emu_.Get<KernelDebugSink>().EmitLine(ascii, ChannelName());
    tx_line_.clear();
}

void Sa11xxUartBase::TxByte(uint8_t b) {
    tx_line_.push_back(b);
    if (b == '\n' || tx_line_.size() >= 256) FlushLine();
    if (tx_listener_) tx_listener_(b);
}

void Sa11xxUartBase::Emit(const std::vector<uint8_t>& out) {
    for (uint8_t b : out) TxByte(b);
}

void Sa11xxUartBase::OnTransmitted(const std::vector<uint8_t>& out) {
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        RefreshIrqLocked();
    }
    Emit(out);
}

void Sa11xxUartBase::OnReceived() {
    std::lock_guard<std::mutex> lk(state_mtx_);
    RefreshIrqLocked();
}

uint32_t Sa11xxUartBase::Utsr1Locked() const {
    uint32_t v = rx_->Utsr1(rx_port_);
    if (tx_->Tby(port_)) v |= kUtsr1Tby;
    if (tx_->Tnf(port_)) v |= kUtsr1Tnf;
    return v;
}

uint32_t Sa11xxUartBase::ComputeUtsr0Locked() const {
    return rx_->Utsr0(rx_port_) | (tx_->Tfs(port_) ? kUtsr0Tfs : 0u);
}

/* §11.11.5.4 / §11.11.5.5 (printed 11-117): RIE gates RFS and RID, TIE gates TFS, toward the
   interrupt controller. */
void Sa11xxUartBase::RefreshIrqLocked() {
    const int bit = IntcSourceBit();
    if (bit < 0) return;
    const bool rx_irq = rx_->InterruptRequest(rx_port_);
    const bool tx_irq = (utcr3_ & kUtcr3Tie) && tx_->Tfs(port_);
    const bool want = rx_irq || tx_irq;
    if (want && !intc_asserted_) {
        intc_asserted_ = true;
        emu_.Get<Sa11xxIntc>().AssertSource(static_cast<uint32_t>(bit));
    } else if (!want && intc_asserted_) {
        intc_asserted_ = false;
        emu_.Get<Sa11xxIntc>().DeassertSource(static_cast<uint32_t>(bit));
    }
}

void Sa11xxUartBase::PushRxByte(uint8_t b) {
    rx_->Push(rx_port_, &b, 1u);
}

void Sa11xxUartBase::PushRxBurst(const uint8_t* data, size_t n) {
    rx_->Push(rx_port_, data, n);
}

/* §11.11.1 (printed 11-109): "Following hardware reset, the UART is disabled"; "Reset also causes
   the UART's transmit and receive FIFOs to be flushed"; UTCR3 reset row: RXE 0, TXE 0. */
void Sa11xxUartBase::OnResetLine() {
    std::lock_guard<std::mutex> lk(state_mtx_);
    utcr3_ &= ~(kUtcr3Rxe | kUtcr3Txe);
    tx_->Reset(port_);
    rx_->Reset(rx_port_);
    RefreshIrqLocked();
}

uint32_t Sa11xxUartBase::ReadReg(uint32_t off) {
    std::vector<uint8_t> out;
    uint32_t v = 0;
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        const uint64_t now = clock_->Cycles();
        tx_->Settle(port_, now, out);
        rx_->Settle(rx_port_, now);
        switch (off) {
            case 0x00: v = utcr0_; break;
            case 0x04: v = utcr1_; break;
            case 0x08: v = utcr2_; break;
            case 0x0C: v = utcr3_; break;
            case 0x10: v = utcr4_; break;
            case 0x14: v = rx_->Pop(rx_port_, now); break;
            case 0x1C: v = ComputeUtsr0Locked(); break;
            case 0x20: v = Utsr1Locked(); break;
            default:   break;
        }
        RefreshIrqLocked();
    }
    Emit(out);
    return v;
}

/* §11.11.3.7 (printed 11-113) UTCR0 and §11.10.4 (printed 11-93) UTCR4: the UART "must be disabled
   (RXE=TXE=0) when changing the state of" their bits; §11.11.4.1 (printed 11-115): the same
   "whenever these registers are written" for UTCR1 / UTCR2. */
void Sa11xxUartBase::WriteReg(uint32_t off, uint32_t value) {
    std::vector<uint8_t> out;
    bool port_change = false;
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        const uint64_t now = clock_->Cycles();
        const bool enabled = (utcr3_ & (kUtcr3Rxe | kUtcr3Txe)) != 0u;
        if (enabled && (off == 0x04 || off == 0x08 || (off == 0x00 && value != utcr0_) ||
                        (off == 0x10 && value != utcr4_))) {
            emu_.Get<Fatal>().Die("%s: UTCR%u write 0x%02X while the UART is enabled (UTCR3 0x%02X); "
                                  "not modelled", ChannelName(), off / 4u, value, utcr3_);
        }
        switch (off) {
            case 0x00: utcr0_ = value; break;
            case 0x04: utcr1_ = value; break;
            case 0x08: utcr2_ = value; break;
            case 0x0C: utcr3_ = value; break;
            case 0x10: utcr4_ = value; break;
            case 0x14: tx_->Write(port_, now, static_cast<uint8_t>(value & 0xFFu), out); break;
            case 0x1C: rx_->ClearStatus(rx_port_, now, value); break;
            default:   break;
        }
        if (off <= 0x0C) {
            port_change = tx_->WriteControl(
                port_, now, Sa11xxUartTransmitter::Control{utcr0_, utcr1_, utcr2_, utcr3_}, out);
            rx_->WriteControl(rx_port_, now,
                              Sa11xxUartReceiver::Control{utcr0_, utcr1_, utcr2_, utcr3_});
        }
        RefreshIrqLocked();
    }
    Emit(out);
    if (port_change) tx_->NotifyDma();
}

uint8_t Sa11xxUartBase::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("ReadByte", addr, 0);
    return static_cast<uint8_t>((ReadReg(base) >> shift) & 0xFFu);
}

uint32_t Sa11xxUartBase::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return ReadReg(off);
}

void Sa11xxUartBase::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("WriteByte", addr, value);
    if (base == 0x14) { WriteReg(base, value); return; }
    const uint32_t cur     = ReadReg(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    WriteReg(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Sa11xxUartBase::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    WriteReg(off, value);
}

void Sa11xxUartBase::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    w.Write("utcr0", utcr0_);
    w.Write("utcr1", utcr1_);
    w.Write("utcr2", utcr2_);
    w.Write("utcr3", utcr3_);
    w.Write("utcr4", utcr4_);
    w.Write("intc_asserted", intc_asserted_);
    tx_->Save(port_, w);
    rx_->Save(rx_port_, w);
}

void Sa11xxUartBase::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    r.Read("utcr0", utcr0_);
    r.Read("utcr1", utcr1_);
    r.Read("utcr2", utcr2_);
    r.Read("utcr3", utcr3_);
    r.Read("utcr4", utcr4_);
    r.Read("intc_asserted", intc_asserted_);
    tx_->Restore(port_, r);
    rx_->Restore(rx_port_, r);
}

void Sa11xxUartBase::PostRestore() {
    std::lock_guard<std::mutex> lk(state_mtx_);
    tx_->PostRestore(port_);
    rx_->PostRestore(rx_port_);
    RefreshIrqLocked();
}
