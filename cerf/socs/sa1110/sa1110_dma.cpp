#include "sa1110_dma.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../core/rate_probe.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "sa1110_intc.h"

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

bool Sa1110Dma::DecodeOffset(uint32_t off, uint32_t& ch, uint32_t& reg) {
    const uint32_t kRegionSize = kChannelCount * kChannelStride;
    if (off >= kRegionSize) return false;
    ch  = off / kChannelStride;
    reg = off % kChannelStride;
    return true;
}

bool Sa1110Dma::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetSoc() == SocFamily::SA1110;
}

void Sa1110Dma::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void Sa1110Dma::RegisterSink(SinkFn fn) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    sinks_.push_back(std::move(fn));
}

void Sa1110Dma::CompleteTransfer(uint32_t channel_index, bool buffer_b) {
    if (channel_index >= kChannelCount) return;
    std::lock_guard<std::mutex> lk(state_mtx_);
    Channel& c = ch_[channel_index];
    const uint32_t before = c.dcsr;
    if (buffer_b) c.dcsr = (c.dcsr & ~kDcsrStrtB) | kDcsrDoneB;
    else          c.dcsr = (c.dcsr & ~kDcsrStrtA) | kDcsrDoneA;
    LOG(Periph, "[Sa1110Dma] ch=%u CompleteTransfer buf=%c DCSR %08X -> %08X\n",
        channel_index, buffer_b ? 'B' : 'A', before, c.dcsr);
    RefreshIrqLineLocked(channel_index, c);
}

void Sa1110Dma::RefreshIrqLineLocked(uint32_t channel_index, Channel& c) {
    const bool want = ((c.dcsr & kDcsrIe) != 0)
                   && ((c.dcsr & kDcsrIrqLevelBits) != 0);
    auto& intc = emu_.Get<Sa1110Intc>();
    if (want) intc.AssertSource  (kIntcBitDmaCh0 + channel_index);
    else      intc.DeassertSource(kIntcBitDmaCh0 + channel_index);
}

void Sa1110Dma::KickIfStartedLocked(uint32_t channel_index, Channel& c,
                                     uint32_t newly_set) {
    if (!(c.dcsr & kDcsrRun)) return;

    const auto try_sinks = [&](bool buffer_b) -> bool {
        ChannelState st{
            channel_index, c.ddar, c.dbsa, c.dbta, c.dbsb, c.dbtb, buffer_b,
        };
        for (auto& sink : sinks_) {
            if (sink(st)) return true;
        }
        return false;
    };

    const uint32_t before = c.dcsr;
    const bool strt_a = (newly_set & kDcsrStrtA) != 0;
    const bool strt_b = (newly_set & kDcsrStrtB) != 0;

    /* §11.6.1.2: setting STRTA clears DONEA, NOT STRTA itself —
       wavedev sub_F524B4 polls until both STRT bits stay set after
       software writes them; clearing in-Kick makes it spin forever. */
    if (strt_a) c.dcsr &= ~kDcsrDoneA;
    if (strt_b) c.dcsr &= ~kDcsrDoneB;

    bool a_claimed = false, b_claimed = false;
    if (strt_a) {
        a_claimed = try_sinks(false);
        if (!a_claimed) c.dcsr |= kDcsrDoneA;
    }
    if (strt_b) {
        b_claimed = try_sinks(true);
        if (!b_claimed) c.dcsr |= kDcsrDoneB;
    }

    if (strt_a || strt_b) {
        LOG(Periph, "[Sa1110Dma] ch=%u KICK strt_a=%d/claim=%d strt_b=%d/claim=%d "
                    "DCSR %08X -> %08X DDAR=%08X DBSA=%08X DBTA=%u DBSB=%08X DBTB=%u\n",
            channel_index, strt_a, a_claimed, strt_b, b_claimed,
            before, c.dcsr, c.ddar, c.dbsa, c.dbta, c.dbsb, c.dbtb);
    }

    RefreshIrqLineLocked(channel_index, c);
}

uint32_t Sa1110Dma::ReadRegLocked(uint32_t off) {
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

void Sa1110Dma::WriteRegLocked(uint32_t off, uint32_t value) {
    uint32_t ch, reg;
    if (!DecodeOffset(off, ch, reg)) return;
#if CERF_DEV_MODE
    emu_.Get<RateProbe>().Inc(RateProbe::Counter::DmaWrites);
#endif
    Channel& c = ch_[ch];
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
                LOG(Periph, "[Sa1110Dma] ch=%u W1C 0x%08X cleared 0x%08X "
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

uint8_t Sa1110Dma::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    uint32_t ch, reg;
    if (!DecodeOffset(base, ch, reg)) HaltUnsupportedAccess("ReadByte", addr, 0);
    std::lock_guard<std::mutex> lk(state_mtx_);
    return static_cast<uint8_t>((ReadRegLocked(base) >> shift) & 0xFFu);
}

uint16_t Sa1110Dma::ReadHalf(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x2u) * 8;
    uint32_t ch, reg;
    if (!DecodeOffset(base, ch, reg)) HaltUnsupportedAccess("ReadHalf", addr, 0);
    std::lock_guard<std::mutex> lk(state_mtx_);
    return static_cast<uint16_t>((ReadRegLocked(base) >> shift) & 0xFFFFu);
}

uint32_t Sa1110Dma::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t ch, reg;
    if (!DecodeOffset(off, ch, reg)) HaltUnsupportedAccess("ReadWord", addr, 0);
    std::lock_guard<std::mutex> lk(state_mtx_);
    return ReadRegLocked(off);
}

void Sa1110Dma::WriteHalf(uint32_t addr, uint16_t value) {
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

void Sa1110Dma::WriteByte(uint32_t addr, uint8_t value) {
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

void Sa1110Dma::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    uint32_t ch, reg;
    if (!DecodeOffset(off, ch, reg)) HaltUnsupportedAccess("WriteWord", addr, value);
    std::lock_guard<std::mutex> lk(state_mtx_);
    WriteRegLocked(off, value);
}

REGISTER_SERVICE(Sa1110Dma);
