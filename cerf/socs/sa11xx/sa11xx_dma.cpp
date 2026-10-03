#include "sa11xx_dma.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../core/rate_probe.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../cpu/emulated_memory.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "sa11xx_dma_port.h"
#include "sa11xx_intc.h"

#include <algorithm>
#include <vector>

using namespace sa11xx_dma;

namespace {

constexpr uint32_t kIrqLevelBits = kDoneA | kDoneB | kError;

constexpr uint32_t kOffDdar     = 0x00;
constexpr uint32_t kOffDcsrSet  = 0x04;
constexpr uint32_t kOffDcsrClr  = 0x08;
constexpr uint32_t kOffDcsrRo   = 0x0C;
constexpr uint32_t kOffDbsa     = 0x10;
constexpr uint32_t kOffDbta     = 0x14;
constexpr uint32_t kOffDbsb     = 0x18;
constexpr uint32_t kOffDbtb     = 0x1C;

constexpr uint32_t kIntcBitDmaCh0 = 20;

/* SA-1110 Developer's Manual §11.6.1.1 DDARn: RW 0, E 1, BS 2, DW 3, DS 7:4, DA 31:8. */
constexpr uint32_t kDdarRw = 1u << 0;
constexpr uint32_t kDdarBs = 1u << 2;
constexpr uint32_t kDdarDw = 1u << 3;

/* §11.6.1.1 (printed 11-7): DDAR reset row 0 in bits 31..26; §11.6.1.4 / §11.6.1.6 (printed
   11-12): DBTx bits 31..13 "are reserved and read as zeros. Writes to this field have no effect". */
constexpr uint32_t kDdarResetKeep = 0x03FFFFFFu;
constexpr uint32_t kDbtMask       = 0x00001FFFu;

/* §11.6.1.2 (printed 11-10 / 11-11): DCSR bits 31..8 "Writes to this field have no effect"; BIU
   "is never cleared except on reset (hardware, software, or sleep)". */
constexpr uint32_t kDcsrWritable  = 0x000000FFu;
constexpr uint32_t kDcsrClearable = kRun | kIe | kError | kDoneA | kStrtA | kDoneB | kStrtB;

}

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
    clock_ = &emu_.Get<GuestCycleClock>();
    for (uint32_t ch = 0; ch < kChannelCount; ++ch) {
        done_[ch] = clock_->Add([this] { Update(); });
    }
    hooks_.transmit = [this](uint32_t ddar, uint32_t pa, uint32_t bytes,
                             GuestCycleClock::Rate rate) { Transmit(ddar, pa, bytes, rate); };
    hooks_.receive = [this](uint32_t ddar, uint32_t pa, uint32_t bytes,
                            GuestCycleClock::Rate rate) { Receive(ddar, pa, bytes, rate); };
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) { OnResetLine(); });
    emu_.Get<PeripheralDispatcher>().Register(this);
}

/* §9.6: software reset "applies reset to the majority of the SA-1110", watchdog "identical to
   software reset", sleep reset "does not affect the power manager, RTC, or GPIO wake-up
   register"; §11.6.1.2: BIU "is cleared by all reset sources (hard, sleep, watchdog, or software)". */
void Sa11xxDma::OnResetLine() {
    for (uint32_t ch = 0; ch < kChannelCount; ++ch) {
        Sa11xxDmaChannelRegs& c = ch_[ch];
        const Sa11xxDmaPort* port = stream_[ch].Port();
        if (port != nullptr && !port->Receive() && (c.dcsr & kRun) != 0u) {
            for (Sa11xxDmaTransmitObserver* o : transmit_) o->OnTransmitStop(c.ddar);
        }
        stream_[ch].Reset();
        clock_->Disarm(done_[ch]);
        c.dcsr &= ~kBiu;
        c.ddar &= kDdarResetKeep;
        c.dbta &= kDbtMask;
        c.dbtb &= kDbtMask;
    }
}

void Sa11xxDma::RegisterPort(uint32_t device_select, Sa11xxDmaPort* port) {
    ports_[device_select & 0xFu] = port;
}

void Sa11xxDma::RegisterTransmitObserver(Sa11xxDmaTransmitObserver* observer) {
    transmit_.push_back(observer);
}

void Sa11xxDma::RegisterReceiveSource(Sa11xxDmaReceiveSource* source) {
    receive_.push_back(source);
}

/* Table 11-6: DS / DW / RW per device; Table 11-1: MCP and SSP DMA burst 8 bytes; §11.6.1.1:
   BS 0 = "Four datums per burst"; SA-1100 TRM Table 11-6 (printed 11-9): BS 0 for the UARTs, the
   MCP and the SSP; Linux DDAR_Ser4SSPWr / DDAR_Ser4MCP0Wr: DDAR_Brst4. */
Sa11xxDmaPort* Sa11xxDma::PortFor(uint32_t ddar) const {
    Sa11xxDmaPort* port = ports_[(ddar >> 4) & 0xFu];
    if (port == nullptr) return nullptr;
    const bool receive   = (ddar & kDdarRw) != 0u;
    const bool half_word = (ddar & kDdarDw) != 0u;
    if ((ddar >> 8) != port->DeviceAddress() || half_word != (port->DatumBytes() == 2u) ||
        (ddar & kDdarBs) != 0u || receive != port->Receive()) {
        return nullptr;
    }
    return port;
}

bool Sa11xxDma::SelectsPort(uint32_t ddar) const {
    return ports_[(ddar >> 4) & 0xFu] != nullptr;
}

void Sa11xxDma::RequireSupportedTransfer(uint32_t ch, uint32_t dcsr) const {
    const uint32_t ddar = ch_[ch].ddar;
    if ((dcsr & kRun) == 0u || (dcsr & (kStrtA | kStrtB)) == 0u) return;
    if (!SelectsPort(ddar) || PortFor(ddar) != nullptr) return;
    emu_.Get<Fatal>().Die("Sa11xxDma ch%u: DDAR 0x%08X selects a modelled serial device with an "
                          "address, datum width, burst size or direction this model does not "
                          "support", ch, ddar);
}

void Sa11xxDma::Bind(uint32_t ch, Sa11xxDmaPort* port) {
    if (stream_[ch].Port() == port) return;
    if (stream_[ch].Active()) {
        emu_.Get<Fatal>().Die("Sa11xxDma ch%u: DDAR 0x%08X changes the device of an active "
                              "transfer", ch, ch_[ch].ddar);
    }
    for (uint32_t other = 0; port != nullptr && other < kChannelCount; ++other) {
        if (other == ch || stream_[other].Port() != port) continue;
        if (stream_[other].Active() || (ch_[other].dcsr & kRun) != 0u) {
            emu_.Get<Fatal>().Die("Sa11xxDma ch%u: DDAR 0x%08X selects the device that running "
                                  "ch%u serves; not modelled", ch, ch_[ch].ddar, other);
        }
        stream_[other].Bind(nullptr);
    }
    stream_[ch].Bind(port);
}

void Sa11xxDma::RequireBuffers(uint32_t ch) const {
    const Sa11xxDmaChannelRegs& c = ch_[ch];
    const uint32_t datum = stream_[ch].Port()->DatumBytes();
    const uint32_t burst = Sa11xxDmaStream::kBurstDatums * datum;
    const bool     both  = (c.dcsr & (kStrtA | kStrtB)) == (kStrtA | kStrtB);
    for (const bool b : {false, true}) {
        if ((c.dcsr & Strt(b)) == 0u) continue;
        const uint32_t bytes = Sa11xxDmaStream::Count(c, b);
        if (!Sa11xxDmaStream::BufferValid(c, b, datum)) {
            emu_.Get<Fatal>().Die("Sa11xxDma ch%u: buffer %c at 0x%08X with %u bytes; a zero count, "
                                  "a count that is not a whole number of %u-byte datums or an "
                                  "unaligned start is not modelled", ch, b ? 'B' : 'A',
                                  Sa11xxDmaStream::Start(c, b), bytes, datum);
        }
        if (both && bytes % burst != 0u) {
            emu_.Get<Fatal>().Die("Sa11xxDma ch%u: buffer %c of %u bytes ends in a partial %u-byte "
                                  "burst while both buffers are started; a burst across the two "
                                  "buffers is not modelled", ch, b ? 'B' : 'A', bytes, burst);
        }
    }
}

void Sa11xxDma::RefreshIrqLine(uint32_t ch) {
    const Sa11xxDmaChannelRegs& c = ch_[ch];
    const bool want = (c.dcsr & kIe) != 0u && (c.dcsr & kIrqLevelBits) != 0u;
    auto& intc = emu_.Get<Sa11xxIntc>();
    if (want) intc.AssertSource  (kIntcBitDmaCh0 + ch);
    else      intc.DeassertSource(kIntcBitDmaCh0 + ch);
}

void Sa11xxDma::ArmDone(uint32_t ch) {
    uint64_t cycle = 0;
    if (stream_[ch].Port() != nullptr && stream_[ch].DoneCycle(cycle)) {
        clock_->Arm(done_[ch], cycle);
    } else {
        clock_->Disarm(done_[ch]);
    }
}

void Sa11xxDma::Update() {
    const uint64_t now = clock_->Cycles();
    for (uint32_t ch = 0; ch < kChannelCount; ++ch) {
        if (stream_[ch].Port() == nullptr) continue;
        RequireBuffers(ch);
        const uint32_t before = ch_[ch].dcsr;
        stream_[ch].Evaluate(now, ch_[ch], hooks_);
        if (ch_[ch].dcsr != before) {
            LOG(Periph, "[Sa11xxDma] ch=%u DCSR %08X -> %08X\n", ch, before, ch_[ch].dcsr);
        }
    }
    for (uint32_t ch = 0; ch < kChannelCount; ++ch) {
        if (stream_[ch].Port() == nullptr) continue;
        ArmDone(ch);
        RefreshIrqLine(ch);
    }
}

void Sa11xxDma::OnPortChange() {
    Update();
}

void Sa11xxDma::Transmit(uint32_t ddar, uint32_t pa, uint32_t bytes,
                         GuestCycleClock::Rate rate) {
    for (Sa11xxDmaTransmitObserver* o : transmit_) o->OnTransmitBlock(ddar, pa, bytes, rate);
}

void Sa11xxDma::Receive(uint32_t ddar, uint32_t pa, uint32_t bytes, GuestCycleClock::Rate rate) {
    for (Sa11xxDmaReceiveSource* s : receive_) {
        if (s->FillReceived(ddar, pa, bytes, rate)) return;
    }
    const std::vector<uint8_t> silence(bytes, 0u);
    emu_.Get<EmulatedMemory>().CopyIn(pa, silence.data(), bytes);
}

void Sa11xxDma::KickUnbound(uint32_t ch, uint32_t newly_set) {
    Sa11xxDmaChannelRegs& c = ch_[ch];
    const uint32_t before = c.dcsr;
    if (newly_set & kStrtA) c.dcsr &= ~kDoneA;
    if (newly_set & kStrtB) c.dcsr &= ~kDoneB;
    if ((c.dcsr & kRun) == 0u) {
        if (c.dcsr != before) RefreshIrqLine(ch);
        return;
    }
    const uint32_t starting = (newly_set & kRun) ? (c.dcsr & (kStrtA | kStrtB))
                                                 : (newly_set & (kStrtA | kStrtB));
    if (starting != 0u && (c.ddar & kDdarRw) == 0u) {
        emu_.Get<Fatal>().Die("Sa11xxDma ch%u: transmit DMA with DDAR 0x%08X to a device whose "
                              "transmit FIFO is not modelled", ch, c.ddar);
    }
    if (starting != 0u) {
        LOG(Periph, "[Sa11xxDma] ch=%u KICK strt=0x%02X DCSR %08X -> %08X DDAR=%08X DBSA=%08X "
                    "DBTA=%u DBSB=%08X DBTB=%u\n", ch, starting, before, c.dcsr, c.ddar,
            c.dbsa, c.dbta, c.dbsb, c.dbtb);
    }
    RefreshIrqLine(ch);
}

/* §11.6.1.1: "Writes to this register are blocked if the RUN bit in the DCSRn is one." */
void Sa11xxDma::WriteDdar(uint32_t ch, uint32_t value) {
    Sa11xxDmaChannelRegs& c = ch_[ch];
    if ((c.dcsr & kRun) != 0u) return;
    c.ddar = value;
}

/* §11.6.1.2: DONEA "is cleared by writing a one to it or by setting the STRTA bit"; ERROR "is
   cleared by software through setting the RUN bit". */
void Sa11xxDma::WriteDcsrSet(uint32_t ch, uint32_t value) {
    Sa11xxDmaChannelRegs& c = ch_[ch];
    value &= kDcsrWritable;
    RequireSupportedTransfer(ch, c.dcsr | value);
    Sa11xxDmaPort* port = PortFor(c.ddar);
    Bind(ch, port);
    if (port == nullptr) {
        const uint32_t newly_set = value & ~c.dcsr;
        c.dcsr |= value;
        KickUnbound(ch, newly_set);
        return;
    }
    /* §11.6.3 (printed 11-13): DCSR at +0x04 "Write ones to set." */
    const uint32_t strt_after = c.dcsr | value;
    if ((value & ~(kRun | kIe | kStrtA | kStrtB | kDoneA | kDoneB)) != 0u ||
        ((value & kDoneA) != 0u && (strt_after & kStrtA) != 0u) ||
        ((value & kDoneB) != 0u && (strt_after & kStrtB) != 0u)) {
        emu_.Get<Fatal>().Die("Sa11xxDma ch%u: DCSR set 0x%08X on a port-bound channel with DCSR "
                              "0x%08X sets ERROR, BIU or the DONE bit of a started buffer; not "
                              "modelled", ch, value, c.dcsr);
    }
    stream_[ch].Evaluate(clock_->Cycles(), c, hooks_);
    const uint32_t newly_set = value & ~c.dcsr;
    c.dcsr |= value;
    for (const bool b : {false, true}) {
        if ((newly_set & Strt(b)) == 0u) continue;
        c.dcsr &= ~Done(b);
        if (!stream_[ch].ArmBuffer(c, b)) {
            emu_.Get<Fatal>().Die("Sa11xxDma ch%u: STRT%c set again on a buffer abandoned "
                                  "mid-transfer; not modelled", ch, b ? 'B' : 'A');
        }
    }
    if (newly_set & kRun) c.dcsr &= ~kError;
    Update();
}

void Sa11xxDma::WriteDcsrClear(uint32_t ch, uint32_t value) {
    Sa11xxDmaChannelRegs& c = ch_[ch];
    value &= kDcsrClearable;
    Sa11xxDmaPort* port = PortFor(c.ddar);
    Bind(ch, port);
    if (port == nullptr) {
        const uint32_t cleared = c.dcsr & value;
        c.dcsr &= ~value;
        if (cleared != 0u) {
            LOG(Periph, "[Sa11xxDma] ch=%u W1C 0x%08X cleared 0x%08X -> DCSR %08X\n",
                ch, value, cleared, c.dcsr);
            RefreshIrqLine(ch);
        }
        return;
    }
    const uint64_t now = clock_->Cycles();
    stream_[ch].Evaluate(now, c, hooks_);
    const uint32_t cleared = c.dcsr & value;
    c.dcsr &= ~value;
    const Sa11xxDmaStream& s = stream_[ch];
    if (s.Active() && (cleared & Strt(s.ActiveBuffer())) != 0u) {
        if ((c.dcsr & kRun) != 0u) {
            emu_.Get<Fatal>().Die("Sa11xxDma ch%u: STRT%c cleared on the active buffer with RUN "
                                  "set; not modelled", ch, s.ActiveBuffer() ? 'B' : 'A');
        }
        stream_[ch].Abandon(now, c, hooks_);
    }
    if ((cleared & kRun) != 0u && !port->Receive()) {
        for (Sa11xxDmaTransmitObserver* o : transmit_) o->OnTransmitStop(c.ddar);
    }
    Update();
}

/* §11.6.1.3: DBSAn "may be written only when STRTA is zero"; §11.6.1.4: DBTAn "may be written
   only when the STRTA bit for this channel is a zero". */
void Sa11xxDma::WriteBuffer(uint32_t ch, uint32_t reg, uint32_t value) {
    Sa11xxDmaChannelRegs& c = ch_[ch];
    const bool buffer_b = reg == kOffDbsb || reg == kOffDbtb;
    if ((c.dcsr & Strt(buffer_b)) != 0u && PortFor(c.ddar) != nullptr) {
        emu_.Get<Fatal>().Die("Sa11xxDma ch%u: buffer %c register +0x%02X written with STRT%c "
                              "set on a port-bound channel; not modelled", ch,
                              buffer_b ? 'B' : 'A', reg, buffer_b ? 'B' : 'A');
    }
    switch (reg) {
        case kOffDbsa: c.dbsa = value; break;
        case kOffDbta: c.dbta = value & kDbtMask; break;
        case kOffDbsb: c.dbsb = value; break;
        default:       c.dbtb = value & kDbtMask; break;
    }
    stream_[ch].Rewind(buffer_b);
}

uint32_t Sa11xxDma::StoredReg(uint32_t off) const {
    uint32_t ch, reg;
    if (!DecodeOffset(off, ch, reg)) return 0;
    const Sa11xxDmaChannelRegs& c = ch_[ch];
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

uint32_t Sa11xxDma::ReadReg(uint32_t off) {
    uint32_t ch, reg;
    if (!DecodeOffset(off, ch, reg)) return 0;
    if (reg >= kOffDbsa && stream_[ch].Port() != nullptr) return ReadBuffer(ch, reg);
    return StoredReg(off);
}

uint32_t Sa11xxDma::ReadBuffer(uint32_t ch, uint32_t reg) {
    Update();
    const Sa11xxDmaChannelRegs& c = ch_[ch];
    const bool     buffer_b = reg == kOffDbsb || reg == kOffDbtb;
    const bool     count    = reg == kOffDbta || reg == kOffDbtb;
    const uint32_t moved    = stream_[ch].WordsMoved(buffer_b);
    if (moved == 0u) return count ? (buffer_b ? c.dbtb : c.dbta) : (buffer_b ? c.dbsb : c.dbsa);
    if (count) {
        emu_.Get<Fatal>().Die("Sa11xxDma ch%u: DBT%c read after %u words of its buffer moved; the "
                              "live transfer count is not modelled", ch, buffer_b ? 'B' : 'A', moved);
    }
    stream_[ch].FlushReceived(c, hooks_);
    const uint32_t start = Sa11xxDmaStream::Start(c, buffer_b);
    const uint32_t bytes = Sa11xxDmaStream::Count(c, buffer_b);
    return start + std::min<uint32_t>(moved * stream_[ch].Port()->DatumBytes(), bytes);
}

void Sa11xxDma::WriteReg(uint32_t off, uint32_t value) {
    uint32_t ch, reg;
    if (!DecodeOffset(off, ch, reg)) return;
#if CERF_DEV_MODE
    emu_.Get<RateProbe>().Inc(RateProbe::Counter::DmaWrites);
    LOG(Periph, "[Sa11xxDma] ch=%u W +0x%02X = 0x%08X\n", ch, reg, value);
#endif
    switch (reg) {
        case kOffDdar:    WriteDdar(ch, value); break;
        case kOffDcsrSet: WriteDcsrSet(ch, value); break;
        case kOffDcsrClr: WriteDcsrClear(ch, value); break;
        case kOffDcsrRo:  break;
        case kOffDbsa: case kOffDbta: case kOffDbsb: case kOffDbtb:
            WriteBuffer(ch, reg, value);
            break;
        default:          break;
    }
}

uint8_t Sa11xxDma::ReadByte(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    uint32_t ch, reg;
    if (!DecodeOffset(base, ch, reg)) HaltUnsupportedAccess("ReadByte", addr, 0);
    return static_cast<uint8_t>((ReadReg(base) >> shift) & 0xFFu);
}

uint16_t Sa11xxDma::ReadHalf(uint32_t addr) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x2u) * 8;
    uint32_t ch, reg;
    if (!DecodeOffset(base, ch, reg)) HaltUnsupportedAccess("ReadHalf", addr, 0);
    return static_cast<uint16_t>((ReadReg(base) >> shift) & 0xFFFFu);
}

uint32_t Sa11xxDma::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t ch, reg;
    if (!DecodeOffset(off, ch, reg)) HaltUnsupportedAccess("ReadWord", addr, 0);
    return ReadReg(off);
}

void Sa11xxDma::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x2u) * 8;
    uint32_t ch, reg;
    if (!DecodeOffset(base, ch, reg)) HaltUnsupportedAccess("WriteHalf", addr, value);
    const uint32_t cur     = StoredReg(base);
    const uint32_t cleared = cur & ~(0xFFFFu << shift);
    WriteReg(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Sa11xxDma::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off   = addr - MmioBase();
    const uint32_t base  = off & ~0x3u;
    const uint32_t shift = (off & 0x3u) * 8;
    uint32_t ch, reg;
    if (!DecodeOffset(base, ch, reg)) HaltUnsupportedAccess("WriteByte", addr, value);
    const uint32_t cur     = StoredReg(base);
    const uint32_t cleared = cur & ~(0xFFu << shift);
    WriteReg(base, cleared | (static_cast<uint32_t>(value) << shift));
}

void Sa11xxDma::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    uint32_t ch, reg;
    if (!DecodeOffset(off, ch, reg)) HaltUnsupportedAccess("WriteWord", addr, value);
    WriteReg(off, value);
}

void Sa11xxDma::SaveState(StateWriter& w) {
    static_assert(StateVisitCoversAllBytes<Sa11xxDmaChannelRegs>(
                      [](Sa11xxDmaChannelRegs& c, StateFieldBytes& f) { VisitChannel(c, f); }),
                  "Sa11xxDma::VisitChannel must name or skip every field of the channel");
    StateWriteField field(w);
    for (uint32_t ch = 0; ch < kChannelCount; ++ch) {
        uint8_t bound_ds = kUnbound;
        for (uint32_t ds = 0; ds < 16u; ++ds) {
            if (stream_[ch].Port() != nullptr && ports_[ds] == stream_[ch].Port()) {
                bound_ds = static_cast<uint8_t>(ds);
            }
        }
        VisitChannel(ch_[ch], field);
        w.Write<uint8_t>("bound_ds", bound_ds);
        stream_[ch].Save(w);
    }
}

void Sa11xxDma::RestoreState(StateReader& r) {
    StateReadField field(r);
    for (uint32_t ch = 0; ch < kChannelCount; ++ch) {
        uint8_t bound_ds = kUnbound;
        VisitChannel(ch_[ch], field);
        r.Read("bound_ds", bound_ds);
        stream_[ch].Bind(bound_ds < 16u ? ports_[bound_ds] : nullptr);
        stream_[ch].Restore(r);
        clock_->Disarm(done_[ch]);
    }
    for (Sa11xxDmaTransmitObserver* o : transmit_) o->OnTransmitRestored();
}

void Sa11xxDma::PostRestore() {
    Update();
}

REGISTER_SERVICE(Sa11xxDma);
