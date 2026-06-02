#include "sa1110_uart_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../host/uart_screen.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "sa1110_intc.h"

#include <cstdio>
#include <string>


bool Sa1110UartBase::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetSoc() == SocFamily::SA1110;
}

void Sa1110UartBase::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void Sa1110UartBase::FlushLine() {
    std::string ascii;
    for (uint8_t b : tx_line_) {
        ascii.push_back((b >= 0x20 && b < 0x7F) ? char(b) : '.');
    }
    LOG(SocUart, "%s TX (%zu bytes): %s\n",
        ChannelName(), tx_line_.size(), ascii.c_str());
    if (!ascii.empty()) emu_.Get<UartScreen>().AddLine(ascii);
    tx_line_.clear();
}

void Sa1110UartBase::TxByte(uint8_t b) {
    tx_line_.push_back(b);
    if (b == '\n' || tx_line_.size() >= 256) FlushLine();
    if (tx_listener_) tx_listener_(b);
}

uint8_t Sa1110UartBase::PopRxByteLocked() {
    if (rx_fifo_.empty()) return 0;
    uint8_t b = rx_fifo_.front();
    rx_fifo_.pop_front();
    RefreshIrqLocked();
    return b;
}

uint32_t Sa1110UartBase::Utsr1Locked() const {
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

uint32_t Sa1110UartBase::ComputeUtsr0Locked() const {
    uint32_t v = utsr0_pending_;
    if (!rx_fifo_.empty()) v |= kUtsr0Rfs;
    return v;
}

void Sa1110UartBase::RefreshIrqLocked() {
    const int bit = IntcSourceBit();
    if (bit < 0) return;
    const bool want = (ComputeUtsr0Locked() & (kUtsr0Rfs | kUtsr0Rid)) != 0;
    if (want && !intc_asserted_) {
        intc_asserted_ = true;
        emu_.Get<Sa1110Intc>().AssertSource(static_cast<uint32_t>(bit));
    } else if (!want && intc_asserted_) {
        intc_asserted_ = false;
        emu_.Get<Sa1110Intc>().DeassertSource(static_cast<uint32_t>(bit));
    }
}

void Sa1110UartBase::PushRxByte(uint8_t b) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    rx_fifo_.push_back(b);
    utsr0_pending_ |= kUtsr0Rid;
    RefreshIrqLocked();
}

uint32_t Sa1110UartBase::ReadReg(uint32_t off) {
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

void Sa1110UartBase::WriteReg(uint32_t off, uint32_t value) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    switch (off) {
        case 0x00: utcr0_ = value; break;
        case 0x04: utcr1_ = value; break;
        case 0x08: utcr2_ = value; break;
        case 0x0C:
            utcr3_ = value;
            /* RIE may have just been enabled with FIFO already
               non-empty — re-evaluate the IRQ line now or that data
               sits until the next push/pop. */
            RefreshIrqLocked();
            break;
        case 0x10: utcr4_ = value; break;
        case 0x14:
            /* TX path: release the lock around TxByte — the
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

uint8_t Sa1110UartBase::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("ReadByte", addr, 0);
    return static_cast<uint8_t>((ReadReg(base) >> shift) & 0xFFu);
}

uint32_t Sa1110UartBase::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return ReadReg(off);
}

void Sa1110UartBase::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    if (!IsKnown(base)) HaltUnsupportedAccess("WriteByte", addr, value);
    if (base == 0x14) { TxByte(value); return; }
    const uint32_t cur     = ReadReg(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    WriteReg(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Sa1110UartBase::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    WriteReg(off, value);
}
