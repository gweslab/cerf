#include "sa11xx_uart_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../tracing/kernel_debug_sink.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "sa11xx_intc.h"

#include <cstdio>
#include <string>


bool Sa11xxUartBase::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
}

void Sa11xxUartBase::OnReady() {
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

uint8_t Sa11xxUartBase::PopRxByteLocked() {
    if (rx_fifo_.empty()) return 0;
    uint8_t b = rx_fifo_.front();
    rx_fifo_.pop_front();
    RefreshIrqLocked();
    return b;
}

uint32_t Sa11xxUartBase::Utsr1Locked() const {
    uint32_t v = 0x04u;                       /* TNF=1 (instant TX) */
    if (!rx_fifo_.empty()) v |= 0x02u;        /* RNE=1 when RX has data */
    return v;
}

/* SA-1110 §11.9.10 / Linux SA-1100.h:
     UTSR0_RFS = bit 1 (auto-tracks FIFO 1/3..2/3 full)
     UTSR0_RID = bit 2 (sticky pulse after burst; cleared by W1C)
   UART asserts INTC source while UTSR0 RFS|RID is non-zero. */
static constexpr uint32_t kUtsr0Rfs = 1u << 1;
static constexpr uint32_t kUtsr0Rid = 1u << 2;

/* SA-1110 §11.11.7.1: UTSR0 TFS = bit 0 - set while the transmit FIFO
   is half-full or less. §11.11.5.5: UTCR3 TIE = bit 4 - when set, TFS
   asserts the UART INTC source. CERF flushes TX synchronously so the
   FIFO is always empty → TFS is always set. */
static constexpr uint32_t kUtsr0Tfs = 1u << 0;
static constexpr uint32_t kUtcr3Tie = 1u << 4;

/* SA-1110 §11.11.5.4: UTCR3 RIE = bit 3 gates the RFS/RID interrupt (RIE=0 ->
   RFS/RID ignored by the INTC). The J820 OAL clears RIE to silence the SP1 source
   while its IST drains (nk.exe 0x80059EB0); ignoring RIE keeps the source asserted,
   the OAL re-enters before the IST runs, and it storms returning NOP. */
static constexpr uint32_t kUtcr3Rie = 1u << 3;

uint32_t Sa11xxUartBase::ComputeUtsr0Locked() const {
    uint32_t v = utsr0_pending_ | kUtsr0Tfs;
    if (!rx_fifo_.empty()) v |= kUtsr0Rfs;
    return v;
}

void Sa11xxUartBase::RefreshIrqLocked() {
    const int bit = IntcSourceBit();
    if (bit < 0) return;
    const uint32_t utsr0 = ComputeUtsr0Locked();
    const bool rx_irq = (utcr3_ & kUtcr3Rie) && (utsr0 & (kUtsr0Rfs | kUtsr0Rid));
    const bool tx_irq = (utcr3_ & kUtcr3Tie) && (utsr0 & kUtsr0Tfs);
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
    std::lock_guard<std::mutex> lk(state_mtx_);
    rx_fifo_.push_back(b);
    utsr0_pending_ |= kUtsr0Rid;
    RefreshIrqLocked();
}

void Sa11xxUartBase::PushRxBurst(const uint8_t* data, size_t n) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    for (size_t i = 0; i < n; ++i) rx_fifo_.push_back(data[i]);
    utsr0_pending_ |= kUtsr0Rid;
    RefreshIrqLocked();
}

uint32_t Sa11xxUartBase::ReadReg(uint32_t off) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    switch (off) {
        case 0x00: return utcr0_;
        case 0x04: return utcr1_;
        case 0x08: return utcr2_;
        case 0x0C: return utcr3_;
        case 0x10: return utcr4_;
        case 0x14: return PopRxByteLocked();
        case 0x1C: return ComputeUtsr0Locked();           /* UTSR0 RFS|RID */
        case 0x20: return Utsr1Locked();
        default:   return 0;
    }
}

void Sa11xxUartBase::WriteReg(uint32_t off, uint32_t value) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    switch (off) {
        case 0x00: utcr0_ = value; break;
        case 0x04: utcr1_ = value; break;
        case 0x08: utcr2_ = value; break;
        case 0x0C:
            utcr3_ = value;
            /* RIE may have just been enabled with FIFO already
               non-empty - re-evaluate the IRQ line now or that data
               sits until the next push/pop. */
            RefreshIrqLocked();
            break;
        case 0x10: utcr4_ = value; break;
        case 0x14:
            /* TX path: release the lock around TxByte - the
               listener can do arbitrary work (e.g. MicroP parser)
               and re-entering with state_mtx_ held risks deadlock. */
            {
                const uint8_t tx = static_cast<uint8_t>(value & 0xFFu);
                state_mtx_.unlock();
                TxByte(tx);
                state_mtx_.lock();
            }
            break;
        case 0x1C:
            /* W1C: kernel writes UTSR0_RID etc. to ack. RFS is
               read-only (auto-tracks FIFO size) so masking it is
               a no-op. After ACK, UART may deassert INTC. */
            utsr0_pending_ &= ~value;
            RefreshIrqLocked();
            break;
        case 0x20: break;          /* UTSR1 R-O */
        default:   break;
    }
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
    if (base == 0x14) { TxByte(value); return; }
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
    w.Write("utsr0_pending", utsr0_pending_);
    w.Write("intc_asserted", intc_asserted_);
    w.Write<uint32_t>("rx_fifo_count", static_cast<uint32_t>(rx_fifo_.size()));
    for (uint8_t b : rx_fifo_) w.Write("rx_fifo", b);
}

void Sa11xxUartBase::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    r.Read("utcr0", utcr0_);
    r.Read("utcr1", utcr1_);
    r.Read("utcr2", utcr2_);
    r.Read("utcr3", utcr3_);
    r.Read("utcr4", utcr4_);
    r.Read("utsr0_pending", utsr0_pending_);
    r.Read("intc_asserted", intc_asserted_);
    rx_fifo_.clear();
    uint32_t n = 0;
    r.Read("rx_fifo_count", n);
    for (uint32_t i = 0; i < n; ++i) {
        uint8_t b = 0;
        r.Read("rx_fifo", b);
        rx_fifo_.push_back(b);
    }
}
