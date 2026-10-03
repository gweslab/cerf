#define NOMINMAX

#include "sa11xx_uart_receiver.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../jit/host_request_channel.h"
#include "../../state/state_stream.h"
#include "sa11xx_dma.h"
#include "sa11xx_uart_base.h"
#include "sa11xx_uart_regs.h"

#include <algorithm>
#include <utility>

using namespace sa11xx_uart;

namespace {

/* SA-1110 §11.11 (printed 11-109): "a 12-entry x 11-bit FIFO is used to buffer incoming data";
   §11.11.7.2 (printed 11-120): RFS "when it contains eight entries of valid data"; §11.11.7.6:
   EIF for error bits "within the bottom four entries of the receive FIFO". */
constexpr size_t   kDepth      = 12u;
constexpr size_t   kRfsEntries = 8u;
constexpr uint16_t kTagOverrun = 1u << 10;
constexpr uint16_t kErrorTags  = 0x0700u;
constexpr size_t   kErrorWindow = 4u;

/* §11.11.7 UTSR0 (printed 11-122): RFS 1, RID 2, EIF 5; §11.11.8 UTSR1 (printed 11-125): RNE 1,
   ROR 5. */
constexpr uint32_t kUtsr0Rfs = 1u << 1;
constexpr uint32_t kUtsr0Rid = 1u << 2;
constexpr uint32_t kUtsr0Eif = 1u << 5;
constexpr uint32_t kUtsr1Rne = 1u << 1;
constexpr uint32_t kUtsr1Ror = 1u << 5;

constexpr size_t kWireMax = 64u * 1024u;

GuestCycleClock::Rate HalfBitRate(uint32_t utcr1, uint32_t utcr2) {
    const GuestCycleClock::Rate bit = BitRate(utcr1, utcr2);
    return GuestCycleClock::Rate{bit.num * 2u, bit.den};
}

}

bool Sa11xxUartReceiver::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
}

void Sa11xxUartReceiver::OnReady() {
    clock_    = &emu_.Get<GuestCycleClock>();
    requests_ = &emu_.Get<HostRequestChannel>();
    requests_->RegisterListener([this] { OnHostRequest(); });
    clock_->RegisterRateListener([this] { OnCpuRate(); });
}

uint32_t Sa11xxUartReceiver::Attach(Sa11xxUartBase* owner, uint32_t utdr, uint32_t device_select,
                                    const char* name) {
    if (count_ >= kPorts) emu_.Get<Fatal>().Die("Sa11xxUartReceiver: a fourth UART attached");
    const uint32_t index = count_++;
    ch_[index] = std::make_unique<Channel>(*this, index);
    Channel& c = *ch_[index];
    c.owner = owner;
    c.name  = name;
    c.utdr  = utdr;
    c.ev    = clock_->Add([this, index] { OnEvent(index); });
    emu_.Get<Sa11xxDma>().RegisterPort(device_select, &c.port);
    return index;
}

uint32_t Sa11xxUartReceiver::Port::DeviceAddress() const {
    return sa11xx_uart::DeviceAddress(r_.ch_[index_]->utdr);
}

bool Sa11xxUartReceiver::Port::CycleOfMoved(uint64_t words, uint64_t& cycle) {
    if (words != 0u) return false;
    cycle = r_.clock_->Cycles();
    return true;
}

GuestCycleClock::Rate Sa11xxUartReceiver::Port::WordRate() const {
    const Channel& c = *r_.ch_[index_];
    const GuestCycleClock::Rate bit = sa11xx_uart::BitRate(c.ctl.utcr1, c.ctl.utcr2);
    return GuestCycleClock::Rate{bit.num, bit.den * sa11xx_uart::FrameBits(c.ctl.utcr0)};
}

uint64_t Sa11xxUartReceiver::FrameBits(const Channel& c) {
    return sa11xx_uart::FrameBits(c.ctl.utcr0);
}

/* §11.11.7.2: "The receive FIFO is designed to signal the RFS bit to be set when it contains eight
   entries of valid data"; UTSR0 RFS row: "and receiver operation is enabled". */
bool Sa11xxUartReceiver::Rfs(const Channel& c) {
    return (c.ctl.utcr3 & kUtcr3Rxe) != 0u && c.fifo.size() >= kRfsEntries;
}

/* §11.11.7.6 (printed 11-121): EIF "is set when any error bits (8 through 10) are set within the
   bottom four entries of the receive FIFO". */
bool Sa11xxUartReceiver::Eif(const Channel& c) {
    const size_t n = std::min(c.fifo.size(), kErrorWindow);
    for (size_t i = 0; i < n; ++i) {
        if ((c.fifo[i] & kErrorTags) != 0u) return true;
    }
    return false;
}

/* §11.11.1.3 (printed 11-110): "If the receive FIFO contains valid data and three frame periods
   elapse without the reception of data on RXD3, the receiver idle interrupt is generated." */
void Sa11xxUartReceiver::CheckIdle(Channel& c, uint64_t tick) {
    if (c.rid_tick == kNever || c.rid_tick > tick) return;
    if (!c.fifo.empty()) c.rid = true;
    c.rid_tick = kNever;
}

/* §11.11.1.3: "If the FIFO is completely filled and the receive logic attempts to place additional
   data within the FIFO, the overrun bit is set next to the last byte of data received within the
   FIFO. Any data received while the FIFO is completely full is discarded." */
void Sa11xxUartReceiver::Store(Channel& c, uint8_t byte) {
    if (c.dma_supply != 0u) {
        emu_.Get<Fatal>().Die("%s: a received byte with the receive DMA running; not modelled",
                              c.name);
    }
    if (c.fifo.size() >= kDepth) {
        c.fifo.back() |= kTagOverrun;
        return;
    }
    c.fifo.push_back(static_cast<uint16_t>(byte & ((1u << DataBits(c.ctl.utcr0)) - 1u)));
}

/* §11.11.1.2 (printed 11-110): "The receive baud clock is synchronized with the data stream using a
   digital PLL each time the start bit is detected"; "Receive data is then sampled halfway through
   each bit period"; §11.11.1.1: "the receiver only tests for one stop bit per frame". */
void Sa11xxUartReceiver::SettleChannel(Channel& c, uint64_t now) {
    if (c.clocked) {
        const uint64_t t = c.bits.TicksAt(now);
        const uint64_t f = FrameBits(c);
        while (!c.line_end.empty() && c.line_end.front() <= t) {
            const uint64_t at = c.line_end.front();
            CheckIdle(c, at);
            Store(c, c.line_bytes.front());
            c.line_end.pop_front();
            c.line_bytes.pop_front();
            c.rid_tick = at + 6u * f;
        }
        CheckIdle(c, t);
    }
    Accept(c, now);
}

void Sa11xxUartReceiver::Accept(Channel& c, uint64_t now) {
    std::vector<uint8_t> bytes;
    {
        std::lock_guard<std::mutex> lk(c.wire_mtx);
        bytes.swap(c.wire);
    }
    if (bytes.empty() || (c.ctl.utcr3 & kUtcr3Rxe) == 0u) return;
    const uint64_t f   = FrameBits(c);
    const uint64_t one = f - ((c.ctl.utcr0 & kUtcr0Sbs) != 0u ? 1u : 0u);
    uint64_t start = c.next_start;
    if (!c.clocked || start <= c.bits.TicksAt(now)) {
        if (!c.bits.SetRate(clock_->ClockRate(), HalfBitRate(c.ctl.utcr1, c.ctl.utcr2))) {
            emu_.Get<Fatal>().Die("%s: baud rate overflows the cycle clock ratio", c.name);
        }
        c.bits.Start(now);
        c.clocked    = true;
        c.rid_tick   = kNever;
        start        = 0u;
    }
    for (uint8_t b : bytes) {
        c.line_end.push_back(start + 2u * one - 1u);
        c.line_bytes.push_back(b);
        start += 2u * f;
    }
    c.next_start = start;
}

void Sa11xxUartReceiver::Push(uint32_t port, const uint8_t* data, size_t n) {
    Channel& c = *ch_[port];
    {
        std::lock_guard<std::mutex> lk(c.wire_mtx);
        if (c.wire.size() + n > kWireMax) {
            LOG(Caution, "[UART] %s RX: the guest is not taking received bytes, dropping %zu\n",
                c.name, n);
            return;
        }
        c.wire.insert(c.wire.end(), data, data + n);
    }
    requests_->Request();
}

/* §11.11.5.1 (printed 11-116): "If the RXE bit is cleared to zero while the UART is actively
   receiving data, reception is stopped immediately"; "all entries within the receive FIFO are
   reset (all other control/status/flag bits remain intact)". */
void Sa11xxUartReceiver::StopReceive(Channel& c) {
    c.clocked  = false;
    c.fifo.clear();
    c.line_end.clear();
    c.line_bytes.clear();
    c.rid_tick = kNever;
    c.next_start = 0u;
}

/* §11.11.3.5 (printed 11-113): "When SCE=1, a clock is input from a GPIO pin and is used to
   synchronously drive both the transmit and receive logic"; "the digital PLL is shut down". */
void Sa11xxUartReceiver::WriteControl(uint32_t port, uint64_t now, const Control& ctl) {
    Channel& c = *ch_[port];
    if ((ctl.utcr3 & kUtcr3Rxe) != 0u && (ctl.utcr0 & kUtcr0Sce) != 0u) {
        emu_.Get<Fatal>().Die("%s: UTCR0 0x%02X enables the receiver on the GPIO sample clock; not "
                              "modelled", c.name, ctl.utcr0);
    }
    SettleChannel(c, now);
    const bool was = (c.ctl.utcr3 & kUtcr3Rxe) != 0u;
    c.ctl = ctl;
    if (was && (ctl.utcr3 & kUtcr3Rxe) == 0u) StopReceive(c);
    Arm(c, now);
}

void Sa11xxUartReceiver::Settle(uint32_t port, uint64_t now) {
    Channel& c = *ch_[port];
    SettleChannel(c, now);
    Arm(c, now);
}

uint8_t Sa11xxUartReceiver::Pop(uint32_t port, uint64_t now) {
    Channel& c = *ch_[port];
    SettleChannel(c, now);
    uint8_t value = 0u;
    if (!c.fifo.empty()) {
        value = static_cast<uint8_t>(c.fifo.front() & 0xFFu);
        c.fifo.pop_front();
    }
    Arm(c, now);
    return value;
}

uint32_t Sa11xxUartReceiver::Utsr0(uint32_t port) const {
    const Channel& c = *ch_[port];
    return (Rfs(c) ? kUtsr0Rfs : 0u) | (c.rid ? kUtsr0Rid : 0u) | (Eif(c) ? kUtsr0Eif : 0u);
}

/* §11.11.8.6 (printed 11-124): "Each time a data value is transferred to the bottom of the FIFO ...
   the state of this bit is moved from the FIFO to the ROR bit in the status register". */
uint32_t Sa11xxUartReceiver::Utsr1(uint32_t port) const {
    const Channel& c = *ch_[port];
    if (c.fifo.empty()) return 0u;
    return kUtsr1Rne | ((c.fifo.front() & kTagOverrun) != 0u ? kUtsr1Ror : 0u);
}

/* §11.11.7 (printed 11-120): "Writing a one to a sticky status bit clears it". */
void Sa11xxUartReceiver::ClearStatus(uint32_t port, uint64_t now, uint32_t mask) {
    Channel& c = *ch_[port];
    SettleChannel(c, now);
    if ((mask & kUtsr0Rid) != 0u) c.rid = false;
    Arm(c, now);
}

/* §11.11.5.4 (printed 11-117): RIE masks "both the receive FIFO service request interrupt and
   receiver idle interrupt"; §11.11.7.6: EIF is a nonmaskable interrupt. */
bool Sa11xxUartReceiver::InterruptRequest(uint32_t port) const {
    const Channel& c = *ch_[port];
    return ((c.ctl.utcr3 & kUtcr3Rie) != 0u && (Rfs(c) || c.rid)) || Eif(c);
}

void Sa11xxUartReceiver::Arm(Channel& c, uint64_t now) {
    uint64_t tick = kNever;
    if (c.clocked && (c.ctl.utcr3 & kUtcr3Rie) != 0u) {
        if (c.fifo.size() < kRfsEntries) {
            const size_t need = kRfsEntries - c.fifo.size();
            if (c.line_end.size() >= need) tick = c.line_end[need - 1u];
        }
        if (!c.rid) {
            if (!c.line_end.empty()) {
                tick = std::min(tick, c.line_end.back() + 6u * FrameBits(c));
            } else if (c.rid_tick != kNever && !c.fifo.empty()) {
                tick = std::min(tick, c.rid_tick);
            }
        }
    }
    if (tick == kNever) {
        clock_->Disarm(c.ev);
    } else {
        clock_->Arm(c.ev, std::max(c.bits.CycleOfTick(tick), now));
    }
}

void Sa11xxUartReceiver::SetDmaSupply(uint32_t port, uint64_t now, uint64_t words) {
    Channel& c = *ch_[port];
    SettleChannel(c, now);
    c.dma_supply = words;
    if (words != 0u && Rfs(c)) {
        emu_.Get<Fatal>().Die("%s: the receive DMA serves a FIFO holding %zu bytes; not modelled",
                              c.name, c.fifo.size());
    }
}

/* §11.11.1 (printed 11-109): "Reset also causes the UART's transmit and receive FIFOs to be
   flushed"; UTCR3 reset row: RXE 0. */
void Sa11xxUartReceiver::Reset(uint32_t port) {
    Channel& c = *ch_[port];
    {
        std::lock_guard<std::mutex> lk(c.wire_mtx);
        c.wire.clear();
    }
    c.ctl.utcr3 &= ~(kUtcr3Rxe | kUtcr3Txe);
    StopReceive(c);
    c.rid        = false;
    c.dma_supply = 0u;
    clock_->Disarm(c.ev);
}

void Sa11xxUartReceiver::OnHostRequest() {
    const uint64_t now = clock_->Cycles();
    for (uint32_t i = 0; i < count_; ++i) {
        Channel& c = *ch_[i];
        SettleChannel(c, now);
        Arm(c, now);
        c.owner->OnReceived();
    }
}

void Sa11xxUartReceiver::OnEvent(uint32_t port) {
    Channel& c = *ch_[port];
    const uint64_t now = clock_->Cycles();
    SettleChannel(c, now);
    Arm(c, now);
    c.owner->OnReceived();
}

void Sa11xxUartReceiver::OnCpuRate() {
    const uint64_t now = clock_->Cycles();
    for (uint32_t i = 0; i < count_; ++i) {
        Channel& c = *ch_[i];
        if (!c.clocked) continue;
        SettleChannel(c, now);
        if (!c.bits.Rescale(now, clock_->ClockRate(), HalfBitRate(c.ctl.utcr1, c.ctl.utcr2))) {
            emu_.Get<Fatal>().Die("%s: baud rate overflows the cycle clock ratio", c.name);
        }
        Arm(c, now);
    }
}

void Sa11xxUartReceiver::Save(uint32_t port, StateWriter& w) {
    Channel& c = *ch_[port];
    const uint64_t now = clock_->Cycles();
    const RatedTickCount::Position pos =
        c.clocked ? c.bits.PositionAt(now) : RatedTickCount::Position{};
    w.Write<uint32_t>("rx_utcr0", c.ctl.utcr0);
    w.Write<uint32_t>("rx_utcr1", c.ctl.utcr1);
    w.Write<uint32_t>("rx_utcr2", c.ctl.utcr2);
    w.Write<uint32_t>("rx_utcr3", c.ctl.utcr3);
    w.Write<uint8_t>("rx_clocked", c.clocked ? 1u : 0u);
    w.Write<uint64_t>("rx_half_bit_ticks", pos.ticks);
    w.Write<uint64_t>("rx_half_bit_phase", pos.phase);
    w.Write<uint64_t>("rx_half_bit_phase_den", pos.phase_den);
    w.Write<uint64_t>("rx_next_start", c.next_start);
    w.Write<uint8_t>("rx_rid", c.rid ? 1u : 0u);
    w.Write<uint64_t>("rx_rid_tick", c.rid_tick);
    w.Write<uint32_t>("rx_fifo_count", static_cast<uint32_t>(c.fifo.size()));
    for (uint16_t v : c.fifo) w.Write("rx_fifo_entry", v);
    w.Write<uint32_t>("rx_line_count", static_cast<uint32_t>(c.line_end.size()));
    for (size_t i = 0; i < c.line_end.size(); ++i) {
        w.Write("rx_line_end", c.line_end[i]);
        w.Write("rx_line_byte", c.line_bytes[i]);
    }
}

void Sa11xxUartReceiver::Restore(uint32_t port, StateReader& r) {
    Channel& c = *ch_[port];
    uint8_t  clocked = 0, rid = 0;
    uint32_t n = 0;
    RatedTickCount::Position pos;
    r.Read("rx_utcr0", c.ctl.utcr0);
    r.Read("rx_utcr1", c.ctl.utcr1);
    r.Read("rx_utcr2", c.ctl.utcr2);
    r.Read("rx_utcr3", c.ctl.utcr3);
    r.Read("rx_clocked", clocked);
    r.Read("rx_half_bit_ticks", pos.ticks);
    r.Read("rx_half_bit_phase", pos.phase);
    r.Read("rx_half_bit_phase_den", pos.phase_den);
    r.Read("rx_next_start", c.next_start);
    r.Read("rx_rid", rid);
    r.Read("rx_rid_tick", c.rid_tick);
    c.fifo.clear();
    r.Read("rx_fifo_count", n);
    for (uint32_t i = 0; i < n; ++i) {
        uint16_t v = 0;
        r.Read("rx_fifo_entry", v);
        c.fifo.push_back(v);
    }
    c.line_end.clear();
    c.line_bytes.clear();
    r.Read("rx_line_count", n);
    for (uint32_t i = 0; i < n; ++i) {
        uint64_t end = 0;
        uint8_t  b   = 0;
        r.Read("rx_line_end", end);
        r.Read("rx_line_byte", b);
        c.line_end.push_back(end);
        c.line_bytes.push_back(b);
    }
    {
        std::lock_guard<std::mutex> lk(c.wire_mtx);
        c.wire.clear();
    }
    c.clocked    = clocked != 0u;
    c.rid        = rid != 0u;
    c.dma_supply = 0u;
    if (!c.clocked) return;
    if (!c.bits.SetRate(clock_->ClockRate(), HalfBitRate(c.ctl.utcr1, c.ctl.utcr2)) ||
        !c.bits.PlaceAt(clock_->Cycles(), pos)) {
        r.Reject("%s: the restored receive clock at half-bit %llu does not fit the current core "
                 "ratio", c.name, static_cast<unsigned long long>(pos.ticks));
    }
}

void Sa11xxUartReceiver::PostRestore(uint32_t port) {
    Arm(*ch_[port], clock_->Cycles());
}

REGISTER_SERVICE(Sa11xxUartReceiver);
