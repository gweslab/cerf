#include "pxa2xx_dma_channel.h"

#include "../../state/state_stream.h"
#include "pxa2xx_dma_port.h"

#include <algorithm>

void Pxa2xxDmaChannel::Bind(Pxa2xxDmaPort* port) {
    if (port != port_) chained_ = false;
    port_ = port;
}

void Pxa2xxDmaChannel::Unbind() {
    port_    = nullptr;
    active_  = false;
    chained_ = false;
}

/* Intel PXA255 Developer's Manual section 5.1.4.2 (page 5-7): "The next descriptor is fetched
   immediately after the previous descriptor is serviced." */
void Pxa2xxDmaChannel::Begin(uint32_t words, uint32_t burst) {
    origin_  = chained_ ? end_ : port_->Moved();
    end_     = origin_ + words;
    burst_   = burst;
    written_ = 0u;
    active_  = true;
}

void Pxa2xxDmaChannel::Finish() {
    active_  = false;
    chained_ = true;
}

void Pxa2xxDmaChannel::Stop() {
    active_  = false;
    chained_ = false;
}

uint64_t Pxa2xxDmaChannel::Remaining() const {
    if (!active_) return 0u;
    return end_ - std::min(end_, port_->Moved());
}

uint32_t Pxa2xxDmaChannel::WordsMoved() const {
    if (!active_) return 0u;
    return static_cast<uint32_t>(std::min(end_, port_->Moved()) - origin_);
}

bool Pxa2xxDmaChannel::DoneCycle(uint64_t& cycle) const {
    return active_ && port_->CycleOfMoved(end_, cycle);
}

void Pxa2xxDmaChannel::Save(StateWriter& w) const {
    w.Write<uint8_t>("chan_active", active_ ? 1u : 0u);
    w.Write<uint8_t>("chan_chained", chained_ ? 1u : 0u);
    w.Write<uint32_t>("chan_burst", burst_);
    w.Write<uint32_t>("chan_written", written_);
    w.Write<uint64_t>("chan_origin", origin_);
    w.Write<uint64_t>("chan_end", end_);
}

void Pxa2xxDmaChannel::Restore(StateReader& r) {
    uint8_t active = 0, chained = 0;
    r.Read("chan_active", active);
    r.Read("chan_chained", chained);
    r.Read("chan_burst", burst_);
    r.Read("chan_written", written_);
    r.Read("chan_origin", origin_);
    r.Read("chan_end", end_);
    active_  = active != 0u;
    chained_ = chained != 0u;
}
