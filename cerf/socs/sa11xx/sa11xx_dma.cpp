#include "sa11xx_dma.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../core/rate_probe.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "sa11xx_intc.h"

namespace {

/* §11.6.1.2 DCSR bit layout. */
constexpr uint32_t kDcsrRun    = 1u << 0;
constexpr uint32_t kDcsrIe     = 1u << 1;
constexpr uint32_t kDcsrError  = 1u << 2;
constexpr uint32_t kDcsrDoneA  = 1u << 3;
constexpr uint32_t kDcsrStrtA  = 1u << 4;
constexpr uint32_t kDcsrDoneB  = 1u << 5;
constexpr uint32_t kDcsrStrtB  = 1u << 6;
constexpr uint32_t kDcsrIrqLevelBits = kDcsrDoneA | kDcsrDoneB | kDcsrError;

constexpr uint32_t kOffDdar     = 0x00;
constexpr uint32_t kOffDcsrSet  = 0x04;
constexpr uint32_t kOffDcsrClr  = 0x08;
constexpr uint32_t kOffDcsrRo   = 0x0C;
constexpr uint32_t kOffDbsa     = 0x10;
constexpr uint32_t kOffDbta     = 0x14;
constexpr uint32_t kOffDbsb     = 0x18;
constexpr uint32_t kOffDbtb     = 0x1C;

constexpr uint32_t kIntcBitDmaCh0 = 20;

}  /* namespace */

bool Sa11xxDma::DecodeOffset(uint32_t off, uint32_t& ch, uint32_t& reg) {
    const uint32_t kRegionSize = kChannelCount * kChannelStride;
    if (off >= kRegionSize) return false;
    ch  = off / kChannelStride;
    reg = off % kChannelStride;
    return true;
}

bool Sa11xxDma::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
}

void Sa11xxDma::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void Sa11xxDma::RegisterSink(SinkFn fn) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    sinks_.push_back(std::move(fn));
}

void Sa11xxDma::CompleteTransfer(uint32_t channel_index, bool buffer_b) {
    if (channel_index >= kChannelCount) return;
    std::lock_guard<std::mutex> lk(state_mtx_);
    Channel& c = ch_[channel_index];
    const uint32_t before = c.dcsr;
    if (buffer_b) { c.dcsr = (c.dcsr & ~kDcsrStrtB) | kDcsrDoneB; c.in_flight_b = false; }
    else          { c.dcsr = (c.dcsr & ~kDcsrStrtA) | kDcsrDoneA; c.in_flight_a = false; }
    LOG(Periph, "[Sa11xxDma] ch=%u CompleteTransfer buf=%c DCSR %08X -> %08X\n",
        channel_index, buffer_b ? 'B' : 'A', before, c.dcsr);
    RefreshIrqLineLocked(channel_index, c);
}

void Sa11xxDma::RefreshIrqLineLocked(uint32_t channel_index, Channel& c) {
    const bool want = ((c.dcsr & kDcsrIe) != 0)
                   && ((c.dcsr & kDcsrIrqLevelBits) != 0);
    auto& intc = emu_.Get<Sa11xxIntc>();
    if (want) intc.AssertSource  (kIntcBitDmaCh0 + channel_index);
    else      intc.DeassertSource(kIntcBitDmaCh0 + channel_index);
}

void Sa11xxDma::KickIfStartedLocked(uint32_t channel_index, Channel& c,
                                     uint32_t newly_set) {
    const uint32_t before = c.dcsr;

    /* §11.6.1.2: setting STRTA clears DONEA, NOT STRTA itself -
       wavedev sub_F524B4 polls until both STRT bits stay set after
       software writes them; clearing in-Kick makes it spin forever.
       The clear is unconditional on the STRT write, even under RUN=0. */
    if (newly_set & kDcsrStrtA) c.dcsr &= ~kDcsrDoneA;
    if (newly_set & kDcsrStrtB) c.dcsr &= ~kDcsrDoneB;

    if (!(c.dcsr & kDcsrRun)) {
        if (c.dcsr != before) RefreshIrqLineLocked(channel_index, c);
        return;
    }

    const auto try_sinks = [&](bool buffer_b) -> bool {
        ChannelState st{
            channel_index, c.ddar, c.dbsa, c.dbta, c.dbsb, c.dbtb, buffer_b,
        };
        for (auto& sink : sinks_) {
            if (sink(st)) return true;
        }
        return false;
    };

    /* §11.6.1.2: STRT is "functional only if the RUN bit is set" - STRT
       written under RUN=0 stays pending and takes effect on the RUN 0→1
       edge. PPC2002 wavedev arms STRTA/STRTB first and sets RUN|IE last;
       kicking only on STRT edges leaves those transfers dead forever. */
    uint32_t starting = (newly_set & kDcsrRun)
                      ? (c.dcsr    & (kDcsrStrtA | kDcsrStrtB))
                      : (newly_set & (kDcsrStrtA | kDcsrStrtB));
    /* A buffer a sink still owns continues across pause/resume
       (§11.6.1.3 "resume from the current pointer"); re-kicking it
       would double-submit the page. */
    if (c.in_flight_a) starting &= ~kDcsrStrtA;
    if (c.in_flight_b) starting &= ~kDcsrStrtB;
    const bool strt_a = (starting & kDcsrStrtA) != 0;
    const bool strt_b = (starting & kDcsrStrtB) != 0;

    /* DDAR[0]=1 is receive (Table 11-6). Faking DONE on an unclaimed receive
       manufactures a phantom completion the driver re-arms forever (UART3 RX
       wedged serial.dll); a real idle receive stays RUN-pending until data
       arrives, so leave DONE unset and let the IST block. */
    const bool is_receive = (c.ddar & 0x1u) != 0;
    bool a_claimed = false, b_claimed = false;
    if (strt_a) {
        a_claimed = try_sinks(false);
        if (a_claimed) c.in_flight_a = true;
        else if (!is_receive) c.dcsr |= kDcsrDoneA;
    }
    if (strt_b) {
        b_claimed = try_sinks(true);
        if (b_claimed) c.in_flight_b = true;
        else if (!is_receive) c.dcsr |= kDcsrDoneB;
    }

    if (strt_a || strt_b) {
        LOG(Periph, "[Sa11xxDma] ch=%u KICK strt_a=%d/claim=%d strt_b=%d/claim=%d "
                    "DCSR %08X -> %08X DDAR=%08X DBSA=%08X DBTA=%u DBSB=%08X DBTB=%u\n",
            channel_index, strt_a, a_claimed, strt_b, b_claimed,
            before, c.dcsr, c.ddar, c.dbsa, c.dbta, c.dbsb, c.dbtb);
    }

    RefreshIrqLineLocked(channel_index, c);
}

uint32_t Sa11xxDma::ReadRegLocked(uint32_t off) {
    uint32_t ch, reg;
    if (!DecodeOffset(off, ch, reg)) return 0;
    const Channel& c = ch_[ch];
    switch (reg) {
        case kOffDdar:    return c.ddar;
        case kOffDcsrSet: return 0;
        case kOffDcsrClr: return 0;
        case kOffDcsrRo:  return c.dcsr;
        case kOffDbsa:    return c.dbsa;
        case kOffDbta:    return c.dbta;
        case kOffDbsb:    return c.dbsb;
        case kOffDbtb:    return c.dbtb;
        default:          return 0;
    }
}

void Sa11xxDma::WriteRegLocked(uint32_t off, uint32_t value) {
    uint32_t ch, reg;
    if (!DecodeOffset(off, ch, reg)) return;
#if CERF_DEV_MODE
    emu_.Get<RateProbe>().Inc(RateProbe::Counter::DmaWrites);
#endif
    Channel& c = ch_[ch];
#if CERF_DEV_MODE
    LOG(Periph, "[Sa11xxDma] ch=%u W +0x%02X = 0x%08X\n", ch, reg, value);
#endif
    switch (reg) {
        case kOffDdar:    c.ddar = value; break;
        case kOffDcsrSet: {
            const uint32_t newly_set = value & ~c.dcsr;
            c.dcsr |= value;
            KickIfStartedLocked(ch, c, newly_set);
            break;
        }
        case kOffDcsrClr: {
            const uint32_t cleared = c.dcsr & value;
            c.dcsr &= ~value;
            if (cleared != 0) {
                LOG(Periph, "[Sa11xxDma] ch=%u W1C 0x%08X cleared 0x%08X "
                            "-> DCSR %08X\n",
                    ch, value, cleared, c.dcsr);
                RefreshIrqLineLocked(ch, c);
            }
            break;
        }
        case kOffDcsrRo:  break;
        case kOffDbsa:    c.dbsa = value; break;
        case kOffDbta:    c.dbta = value; break;
        case kOffDbsb:    c.dbsb = value; break;
        case kOffDbtb:    c.dbtb = value; break;
        default:          break;
    }
}

uint8_t Sa11xxDma::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    uint32_t ch, reg;
    if (!DecodeOffset(base, ch, reg)) HaltUnsupportedAccess("ReadByte", addr, 0);
    std::lock_guard<std::mutex> lk(state_mtx_);
    return static_cast<uint8_t>((ReadRegLocked(base) >> shift) & 0xFFu);
}

uint16_t Sa11xxDma::ReadHalf(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x2u) * 8;
    uint32_t ch, reg;
    if (!DecodeOffset(base, ch, reg)) HaltUnsupportedAccess("ReadHalf", addr, 0);
    std::lock_guard<std::mutex> lk(state_mtx_);
    return static_cast<uint16_t>((ReadRegLocked(base) >> shift) & 0xFFFFu);
}

uint32_t Sa11xxDma::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t ch, reg;
    if (!DecodeOffset(off, ch, reg)) HaltUnsupportedAccess("ReadWord", addr, 0);
    std::lock_guard<std::mutex> lk(state_mtx_);
    return ReadRegLocked(off);
}

void Sa11xxDma::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x2u) * 8;
    uint32_t ch, reg;
    if (!DecodeOffset(base, ch, reg)) HaltUnsupportedAccess("WriteHalf", addr, value);
    std::lock_guard<std::mutex> lk(state_mtx_);
    const uint32_t cur     = ReadRegLocked(base);
    const uint32_t cleared = cur & ~(0xFFFFu << shift);
    WriteRegLocked(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Sa11xxDma::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    uint32_t ch, reg;
    if (!DecodeOffset(base, ch, reg)) HaltUnsupportedAccess("WriteByte", addr, value);
    std::lock_guard<std::mutex> lk(state_mtx_);
    const uint32_t cur     = ReadRegLocked(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    WriteRegLocked(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Sa11xxDma::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    uint32_t ch, reg;
    if (!DecodeOffset(off, ch, reg)) HaltUnsupportedAccess("WriteWord", addr, value);
    std::lock_guard<std::mutex> lk(state_mtx_);
    WriteRegLocked(off, value);
}

void Sa11xxDma::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    static_assert(StateVisitCoversAllBytes<Channel>(
                      [](Channel& c, StateFieldBytes& f) { VisitChannel(c, f); }),
                  "Sa11xxDma::VisitChannel must name or skip every field of Channel");
    StateWriteField field(w);
    for (Channel& c : ch_) VisitChannel(c, field);
}

void Sa11xxDma::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    StateReadField field(r);
    for (Channel& c : ch_) {
        VisitChannel(c, field);
        c.in_flight_a = false;
        c.in_flight_b = false;
    }
}

REGISTER_SERVICE(Sa11xxDma);
