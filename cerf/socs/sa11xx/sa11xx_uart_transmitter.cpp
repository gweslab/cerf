#define NOMINMAX

#include "sa11xx_uart_transmitter.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../cpu/emulated_memory.h"
#include "../../state/state_stream.h"
#include "sa11xx_dma.h"
#include "sa11xx_uart_base.h"
#include "sa11xx_uart_regs.h"

#include <algorithm>

using namespace sa11xx_uart;

namespace {

/* SA-1110 §11.11.1.5 (printed 11-111): the transmit FIFO "is 8 entries deep", signals "a service request
   when it has four or more empty entries"; "the burst size must be set to 4 words". */
constexpr uint32_t kDepth   = 8u;
constexpr uint32_t kRequest = 4u;
constexpr uint32_t kBurst   = 4u;

}

bool Sa11xxUartTransmitter::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
}

void Sa11xxUartTransmitter::OnReady() {
    clock_ = &emu_.Get<GuestCycleClock>();
    dma_   = &emu_.Get<Sa11xxDma>();
    clock_->RegisterRateListener([this] { OnCpuRate(); });
    dma_->RegisterTransmitObserver(this);
}

uint32_t Sa11xxUartTransmitter::Attach(Sa11xxUartBase* owner, uint32_t utdr,
                                       uint32_t device_select, const char* name) {
    if (count_ >= kPorts) {
        emu_.Get<Fatal>().Die("Sa11xxUartTransmitter: a fourth UART attached");
    }
    const uint32_t index = count_++;
    ch_[index] = std::make_unique<Channel>(*this, index);
    Channel& c = *ch_[index];
    c.owner = owner;
    c.name  = name;
    c.utdr  = utdr;
    c.ds    = device_select;
    c.fifo.Configure(kDepth, kRequest, kBurst);
    c.ev = clock_->Add([this, index] { OnEvent(index); });
    dma_->RegisterPort(device_select, &c.port);
    return index;
}

uint32_t Sa11xxUartTransmitter::Port::DeviceAddress() const {
    return sa11xx_uart::DeviceAddress(t_.ch_[index_]->utdr);
}

uint64_t Sa11xxUartTransmitter::FrameBits(const Channel& c) {
    return sa11xx_uart::FrameBits(c.ctl.utcr0);
}

GuestCycleClock::Rate Sa11xxUartTransmitter::BitRate(const Channel& c) {
    return sa11xx_uart::BitRate(c.ctl.utcr1, c.ctl.utcr2);
}

GuestCycleClock::Rate Sa11xxUartTransmitter::FrameRate(const Channel& c) {
    const GuestCycleClock::Rate bits = BitRate(c);
    return GuestCycleClock::Rate{bits.num, bits.den * FrameBits(c)};
}

/* §11.11.6 (printed 11-119): data "is loaded into the transmit serial shifter along with start and
   stop bits ... then is serially shifted out onto the TXD3 pin at the programmed baud rate". */
void Sa11xxUartTransmitter::SettleChannel(Channel& c, uint64_t now, Bytes& out) {
    if (!c.clocked) return;
    const uint64_t t     = c.bits.TicksAt(now);
    const uint64_t f     = FrameBits(c);
    const uint64_t first = c.run.RunLoads();
    const uint64_t loads = c.run.Settle(t, f, c.fifo);
    PullDma(c);
    const uint8_t mask = static_cast<uint8_t>((1u << DataBits(c.ctl.utcr0)) - 1u);
    for (uint64_t j = 0; j < loads; ++j) {
        c.line_end.push_back(c.run.RunStart() + (first + j + 1u) * f);
        c.line_bytes.push_back(static_cast<uint8_t>(c.data.front() & mask));
        c.data.pop_front();
    }
    while (!c.line_end.empty() && c.line_end.front() <= t) {
        out.push_back(c.line_bytes.front());
        c.line_end.pop_front();
        c.line_bytes.pop_front();
    }
    Publish(c);
}

void Sa11xxUartTransmitter::PullDma(Channel& c) {
    while (c.dma_pulled < c.fifo.Moved()) {
        if (c.dma_bytes.empty()) {
            emu_.Get<Fatal>().Die("%s: the transmit DMA moved byte %llu past the block it started; "
                                  "a burst into the next buffer is not modelled", c.name,
                                  static_cast<unsigned long long>(c.dma_pulled));
        }
        c.data.push_back(c.dma_bytes.front());
        c.dma_bytes.pop_front();
        ++c.dma_pulled;
    }
}

/* §11.11.3.5: SCE=1 drives the transmit logic from a GPIO clock instead of the baud generator. */
void Sa11xxUartTransmitter::StartBaud(Channel& c, uint64_t now) {
    if ((c.ctl.utcr0 & kUtcr0Sce) != 0u) {
        emu_.Get<Fatal>().Die("%s: UTCR0 0x%02X enables the transmitter on the GPIO sample clock; "
                              "not modelled", c.name, c.ctl.utcr0);
    }
    if (!c.bits.SetRate(clock_->ClockRate(), BitRate(c))) {
        emu_.Get<Fatal>().Die("%s: baud rate overflows the cycle clock ratio", c.name);
    }
    c.bits.Start(now);
    c.clocked = true;
}

/* §11.11.6 Note: "There may be a delay between the writing of data in the transit FIFO and the
   assertion of TBY". */
void Sa11xxUartTransmitter::StartRun(Channel& c, uint64_t now) {
    if (!c.clocked || c.run.Running() || c.fifo.Level() == 0u) return;
    const uint64_t t = c.bits.TicksAt(now);
    c.run.Start(c.bits.CycleOfTick(t) == now ? t : t + 1u);
}

/* §11.11.5.2: TXE cleared while transmitting stops transmission "immediately and the remaining bits
   within the transmit serial shifter are reset. In addition, all entries within the transmit FIFO
   are reset". */
void Sa11xxUartTransmitter::StopTransmit(Channel& c) {
    c.clocked = false;
    c.run.Reset();
    c.fifo.Clear();
    c.data.clear();
    c.line_end.clear();
    c.line_bytes.clear();
    Publish(c);
}

/* §11.11.7.1: TFS "1 - Transmit FIFO is half-full (four or fewer entries filled) and transmitter
   operation is enabled". */
void Sa11xxUartTransmitter::Publish(Channel& c) {
    c.tfs.store((c.ctl.utcr3 & kUtcr3Txe) != 0u && c.fifo.Level() <= kRequest,
                std::memory_order_release);
}

void Sa11xxUartTransmitter::Arm(Channel& c, uint64_t now) {
    uint64_t tick = kNoCycle;
    if (c.clocked) {
        if (!c.line_end.empty() && c.owner->HasTxListener()) tick = c.line_end.front();
        const uint64_t left = c.fifo.TakesBeforeEmpty();
        uint64_t at = 0;
        if ((c.ctl.utcr3 & kUtcr3Tie) != 0u && !c.tfs.load(std::memory_order_relaxed) &&
            left != DmaBurstFifo::kUnlimited && left > kRequest &&
            c.run.NextLoadTick(left - kRequest, FrameBits(c), at)) {
            tick = std::min(tick, at);
        }
    }
    const uint64_t cycle = tick == kNoCycle ? kNoCycle : std::max(c.bits.CycleOfTick(tick), now);
    if (cycle == c.armed) return;
    c.armed = cycle;
    if (cycle == kNoCycle) clock_->Disarm(c.ev);
    else                   clock_->Arm(c.ev, cycle);
}

/* §11.11.8.3: TNF "0 - Transmit FIFO is full". */
bool Sa11xxUartTransmitter::Tnf(uint32_t port) const {
    return ch_[port]->fifo.Level() < kDepth;
}

/* §11.11.5.3 BRK and §11.11.5.6 LBM change what the shifter drives onto the pin. */
bool Sa11xxUartTransmitter::WriteControl(uint32_t port, uint64_t now, const Control& ctl,
                                         Bytes& out) {
    Channel& c = *ch_[port];
    SettleChannel(c, now, out);
    if ((ctl.utcr3 & (kUtcr3Brk | kUtcr3Lbm)) != 0u) {
        emu_.Get<Fatal>().Die("%s: UTCR3 0x%02X sets break or loopback; not modelled", c.name,
                              ctl.utcr3);
    }
    const bool was = (c.ctl.utcr3 & kUtcr3Txe) != 0u;
    const bool txe = (ctl.utcr3 & kUtcr3Txe) != 0u;
    c.ctl = ctl;
    if (was && !txe) StopTransmit(c);
    if (!was && txe) {
        StartBaud(c, now);
        StartRun(c, now);
    }
    Publish(c);
    Arm(c, now);
    return was != txe;
}

void Sa11xxUartTransmitter::Write(uint32_t port, uint64_t now, uint8_t value, Bytes& out) {
    Channel& c = *ch_[port];
    SettleChannel(c, now, out);
    if (c.dma_supply != 0u || c.fifo.Level() >= kDepth) {
        emu_.Get<Fatal>().Die("%s: UTDR write 0x%02X with the transmit FIFO full or fed by DMA; not "
                              "modelled", c.name, value);
    }
    c.fifo.Put();
    c.data.push_back(value);
    StartRun(c, now);
    Publish(c);
    Arm(c, now);
}

void Sa11xxUartTransmitter::Settle(uint32_t port, uint64_t now, Bytes& out) {
    Channel& c = *ch_[port];
    SettleChannel(c, now, out);
    Arm(c, now);
}

/* §11.11.1 (printed 11-109): "Reset also causes the UART's transmit and receive FIFOs to be
   flushed"; UTCR3 reset row: TXE 0. */
void Sa11xxUartTransmitter::Reset(uint32_t port) {
    Channel& c = *ch_[port];
    c.ctl.utcr3 &= ~(kUtcr3Rxe | kUtcr3Txe);
    StopTransmit(c);
    c.dma_bytes.clear();
    c.dma_supply = 0u;
    c.fifo.SetSupply(0u);
    c.armed = kNoCycle;
    clock_->Disarm(c.ev);
}

void Sa11xxUartTransmitter::NotifyDma() {
    dma_->OnPortChange();
}

void Sa11xxUartTransmitter::PortSettle(uint32_t port, uint64_t now) {
    Bytes out;
    Settle(port, now, out);
    ch_[port]->owner->OnTransmitted(out);
}

/* §11.11.7.1: "When the TFS bit is set, a DMA service request is made". */
void Sa11xxUartTransmitter::SetDmaSupply(uint32_t port, uint64_t now, uint64_t words) {
    Channel& c = *ch_[port];
    Bytes out;
    SettleChannel(c, now, out);
    c.dma_supply = words;
    c.fifo.SetSupply((c.ctl.utcr3 & kUtcr3Txe) != 0u ? words : 0u);
    c.fifo.Refill();
    PullDma(c);
    StartRun(c, now);
    Publish(c);
    Arm(c, now);
    c.owner->OnTransmitted(out);
}

bool Sa11xxUartTransmitter::CycleOfMoved(uint32_t port, uint64_t words, uint64_t& cycle) {
    const Channel& c = *ch_[port];
    bool     immediate = false;
    uint64_t tick      = 0;
    if (!c.run.TickOfMoved(c.fifo, words, FrameBits(c), immediate, tick)) return false;
    cycle = immediate ? clock_->Cycles() : c.bits.CycleOfTick(tick);
    return true;
}

void Sa11xxUartTransmitter::OnTransmitBlock(uint32_t ddar, uint32_t pa, uint32_t bytes,
                                            GuestCycleClock::Rate) {
    for (uint32_t i = 0; i < count_; ++i) {
        Channel& c = *ch_[i];
        if (((ddar >> 4) & 0xFu) != c.ds || (ddar >> 8) != sa11xx_uart::DeviceAddress(c.utdr)) continue;
        Bytes block(bytes);
        emu_.Get<EmulatedMemory>().CopyOut(pa, block.data(), bytes);
        c.dma_bytes.assign(block.begin(), block.end());
        return;
    }
}

void Sa11xxUartTransmitter::OnEvent(uint32_t port) {
    Channel& c = *ch_[port];
    const uint64_t now = clock_->Cycles();
    Bytes out;
    c.armed = kNoCycle;
    SettleChannel(c, now, out);
    Arm(c, now);
    c.owner->OnTransmitted(out);
}

void Sa11xxUartTransmitter::OnCpuRate() {
    const uint64_t now = clock_->Cycles();
    for (uint32_t i = 0; i < count_; ++i) {
        Channel& c = *ch_[i];
        if (!c.clocked) continue;
        Bytes out;
        SettleChannel(c, now, out);
        if (!c.bits.Rescale(now, clock_->ClockRate(), BitRate(c))) {
            emu_.Get<Fatal>().Die("%s: baud rate overflows the cycle clock ratio", c.name);
        }
        c.armed = kNoCycle;
        Arm(c, now);
        c.owner->OnTransmitted(out);
    }
    dma_->OnPortChange();
}

void Sa11xxUartTransmitter::Save(uint32_t port, StateWriter& w) {
    const Channel& c = *ch_[port];
    const RatedTickCount::Position pos =
        c.clocked ? c.bits.PositionAt(clock_->Cycles()) : RatedTickCount::Position{};
    w.Write<uint32_t>("tx_utcr0", c.ctl.utcr0);
    w.Write<uint32_t>("tx_utcr1", c.ctl.utcr1);
    w.Write<uint32_t>("tx_utcr2", c.ctl.utcr2);
    w.Write<uint32_t>("tx_utcr3", c.ctl.utcr3);
    w.Write<uint8_t>("tx_clocked", c.clocked ? 1u : 0u);
    w.Write<uint64_t>("tx_bit_ticks", pos.ticks);
    w.Write<uint64_t>("tx_bit_phase", pos.phase);
    w.Write<uint64_t>("tx_bit_phase_den", pos.phase_den);
    w.Write<uint32_t>("tx_fifo_level", c.fifo.Level());
    w.Write<uint64_t>("tx_fifo_moved", c.fifo.Moved());
    w.Write<uint64_t>("tx_dma_pulled", c.dma_pulled);
    w.Write<uint64_t>("tx_dma_supply", c.dma_supply);
    c.run.Save(w);
    w.Write<uint32_t>("tx_data_count", static_cast<uint32_t>(c.data.size()));
    for (uint8_t b : c.data) w.Write("tx_data", b);
    w.Write<uint32_t>("tx_dma_count", static_cast<uint32_t>(c.dma_bytes.size()));
    for (uint8_t b : c.dma_bytes) w.Write("tx_dma_byte", b);
    w.Write<uint32_t>("tx_line_count", static_cast<uint32_t>(c.line_end.size()));
    for (size_t i = 0; i < c.line_end.size(); ++i) {
        w.Write("tx_line_end", c.line_end[i]);
        w.Write("tx_line_byte", c.line_bytes[i]);
    }
}

void Sa11xxUartTransmitter::Restore(uint32_t port, StateReader& r) {
    Channel& c = *ch_[port];
    uint8_t  clocked = 0;
    uint32_t level = 0, n = 0;
    uint64_t moved = 0;
    RatedTickCount::Position pos;
    r.Read("tx_utcr0", c.ctl.utcr0);
    r.Read("tx_utcr1", c.ctl.utcr1);
    r.Read("tx_utcr2", c.ctl.utcr2);
    r.Read("tx_utcr3", c.ctl.utcr3);
    r.Read("tx_clocked", clocked);
    r.Read("tx_bit_ticks", pos.ticks);
    r.Read("tx_bit_phase", pos.phase);
    r.Read("tx_bit_phase_den", pos.phase_den);
    r.Read("tx_fifo_level", level);
    r.Read("tx_fifo_moved", moved);
    r.Read("tx_dma_pulled", c.dma_pulled);
    r.Read("tx_dma_supply", c.dma_supply);
    c.run.Restore(r);
    c.data.clear();
    r.Read("tx_data_count", n);
    for (uint32_t i = 0; i < n; ++i) {
        uint8_t b = 0;
        r.Read("tx_data", b);
        c.data.push_back(b);
    }
    c.dma_bytes.clear();
    r.Read("tx_dma_count", n);
    for (uint32_t i = 0; i < n; ++i) {
        uint8_t b = 0;
        r.Read("tx_dma_byte", b);
        c.dma_bytes.push_back(b);
    }
    c.line_end.clear();
    c.line_bytes.clear();
    r.Read("tx_line_count", n);
    for (uint32_t i = 0; i < n; ++i) {
        uint64_t end = 0;
        uint8_t  b   = 0;
        r.Read("tx_line_end", end);
        r.Read("tx_line_byte", b);
        c.line_end.push_back(end);
        c.line_bytes.push_back(b);
    }
    c.fifo.Restore(level, moved);
    c.fifo.SetSupply(0u);
    c.clocked = clocked != 0u;
    c.armed   = kNoCycle;
    Publish(c);
    if (!c.clocked) return;
    if (!c.bits.SetRate(clock_->ClockRate(), BitRate(c)) || !c.bits.PlaceAt(clock_->Cycles(), pos)) {
        r.Reject("%s: the restored baud clock at bit %llu does not fit the current core ratio",
                 c.name, static_cast<unsigned long long>(pos.ticks));
    }
}

void Sa11xxUartTransmitter::PostRestore(uint32_t port) {
    Channel& c = *ch_[port];
    c.armed = kNoCycle;
    Arm(c, clock_->Cycles());
}

REGISTER_SERVICE(Sa11xxUartTransmitter);
