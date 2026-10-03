#include "sa11xx_dma_stream.h"

#include "../../state/state_stream.h"
#include "sa11xx_dma_port.h"

#include <algorithm>

using namespace sa11xx_dma;

namespace {

/* SA-1110 Developer's Manual §11.6.1.4 / §11.6.1.6: DBTx count 12:0 "in bytes". */
constexpr uint32_t kCountMask = 0x1FFFu;

}

uint32_t Sa11xxDmaStream::Count(const Sa11xxDmaChannelRegs& r, bool b) {
    return (b ? r.dbtb : r.dbta) & kCountMask;
}

bool Sa11xxDmaStream::BufferValid(const Sa11xxDmaChannelRegs& r, bool b, uint32_t datum) {
    const uint32_t bytes = Count(r, b);
    return bytes != 0u && (bytes % datum) == 0u && (Start(r, b) & 0x3u) == 0u;
}

uint32_t Sa11xxDmaStream::Datum() const {
    return port_->DatumBytes();
}

uint32_t Sa11xxDmaStream::Words(const Sa11xxDmaChannelRegs& r, bool b) const {
    return Count(r, b) / Datum();
}

/* §11.6.1.3: DBSAn "contains the starting memory address for buffer A"; §11.6.1.4: DBTAn
   "contains the current transfer count in bytes for buffer A". */
bool Sa11xxDmaStream::ArmBuffer(const Sa11xxDmaChannelRegs& r, bool b) {
    const uint32_t i = b ? 1u : 0u;
    if (moved_[i] == 0u) return true;
    if (moved_[i] < Words(r, b)) return false;
    Rewind(b);
    return true;
}

uint64_t Sa11xxDmaStream::Supply(const Sa11xxDmaChannelRegs& r) const {
    if ((r.dcsr & kRun) == 0u || !active_) return 0u;
    uint64_t words = end_ - std::min(end_, port_->Moved());
    const bool other = !cur_b_;
    if ((r.dcsr & Strt(other)) != 0u) words += Words(r, other) - moved_[other ? 1 : 0];
    return words;
}

/* §11.6 (printed 11-6): "buffer A and buffer B, can be chained together so that when a transfer
   to (or from) one buffer completes, the transfer to (or from) the other begins immediately." */
void Sa11xxDmaStream::Begin(Sa11xxDmaChannelRegs& r, const Hooks& hooks) {
    cur_b_ = (r.dcsr & kBiu) != 0u;
    const uint32_t words = Words(r, cur_b_);
    origin_ = chained_ ? end_ : port_->Moved();
    end_    = origin_ + words;
    active_ = true;
    if (!port_->Receive()) {
        hooks.transmit(r.ddar, Start(r, cur_b_), words * Datum(), port_->WordRate());
    }
}

void Sa11xxDmaStream::WriteReceived(const Sa11xxDmaChannelRegs& r, const Hooks& hooks,
                                    uint32_t upto) {
    uint32_t& written = written_[cur_b_ ? 1 : 0];
    if (upto <= written) return;
    hooks.receive(r.ddar, Start(r, cur_b_) + written * Datum(), (upto - written) * Datum(),
                  port_->WordRate());
    written = upto;
}

/* §11.6.1.2: DONEA "indicates that the transfer into or out of buffer A has completed";
   "When DONEA is set, STRTA is cleared"; BIU: "This bit is toggled by the DMA controller when
   DONEA or DONEB are set." */
void Sa11xxDmaStream::Complete(Sa11xxDmaChannelRegs& r, const Hooks& hooks) {
    const uint32_t words = static_cast<uint32_t>(end_ - origin_);
    if (port_->Receive()) WriteReceived(r, hooks, words);
    moved_[cur_b_ ? 1 : 0] = words;
    r.dcsr |= Done(cur_b_);
    r.dcsr &= ~Strt(cur_b_);
    r.dcsr ^= kBiu;
    active_  = false;
    chained_ = true;
}

void Sa11xxDmaStream::Evaluate(uint64_t now, Sa11xxDmaChannelRegs& r, const Hooks& hooks) {
    port_->Settle(now);
    for (;;) {
        for (;;) {
            if (active_ && port_->Moved() >= end_) {
                Complete(r, hooks);
                continue;
            }
            if (!active_ && (r.dcsr & kRun) != 0u &&
                (r.dcsr & Strt((r.dcsr & kBiu) != 0u)) != 0u) {
                Begin(r, hooks);
                continue;
            }
            break;
        }
        port_->SetSupply(now, Supply(r));
        if (!active_ || port_->Moved() < end_) break;
    }
    if (active_) moved_[cur_b_ ? 1 : 0] = static_cast<uint32_t>(port_->Moved() - origin_);
}

void Sa11xxDmaStream::FlushReceived(const Sa11xxDmaChannelRegs& r, const Hooks& hooks) {
    if (active_ && port_->Receive()) WriteReceived(r, hooks, moved_[cur_b_ ? 1 : 0]);
}

void Sa11xxDmaStream::Abandon(uint64_t now, Sa11xxDmaChannelRegs& r, const Hooks& hooks) {
    Evaluate(now, r, hooks);
    if (!active_) return;
    if (port_->Receive()) WriteReceived(r, hooks, moved_[cur_b_ ? 1 : 0]);
    active_  = false;
    chained_ = false;
    port_->SetSupply(now, 0u);
}

void Sa11xxDmaStream::Reset() {
    port_    = nullptr;
    active_  = false;
    chained_ = false;
    cur_b_   = false;
    origin_ = 0u;
    end_    = 0u;
    Rewind(false);
    Rewind(true);
}

void Sa11xxDmaStream::Rewind(bool buffer_b) {
    moved_[buffer_b ? 1 : 0]   = 0u;
    written_[buffer_b ? 1 : 0] = 0u;
}

bool Sa11xxDmaStream::DoneCycle(uint64_t& cycle) const {
    return active_ && port_->CycleOfMoved(end_, cycle);
}

void Sa11xxDmaStream::Save(StateWriter& w) const {
    w.Write<uint8_t>("stream_active", active_ ? 1u : 0u);
    w.Write<uint8_t>("stream_chained", chained_ ? 1u : 0u);
    w.Write<uint8_t>("stream_buffer_b", cur_b_ ? 1u : 0u);
    w.Write<uint64_t>("stream_origin", origin_);
    w.Write<uint64_t>("stream_end", end_);
    w.Write<uint32_t>("stream_moved_a", moved_[0]);
    w.Write<uint32_t>("stream_moved_b", moved_[1]);
    w.Write<uint32_t>("stream_written_a", written_[0]);
    w.Write<uint32_t>("stream_written_b", written_[1]);
}

void Sa11xxDmaStream::Restore(StateReader& r) {
    uint8_t active = 0, chained = 0, buffer_b = 0;
    r.Read("stream_active", active);
    r.Read("stream_chained", chained);
    r.Read("stream_buffer_b", buffer_b);
    r.Read("stream_origin", origin_);
    r.Read("stream_end", end_);
    r.Read("stream_moved_a", moved_[0]);
    r.Read("stream_moved_b", moved_[1]);
    r.Read("stream_written_a", written_[0]);
    r.Read("stream_written_b", written_[1]);
    active_  = active != 0u;
    chained_ = chained != 0u;
    cur_b_   = buffer_b != 0u;
}
