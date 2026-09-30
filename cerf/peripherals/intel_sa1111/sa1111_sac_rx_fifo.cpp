#include "sa1111_sac_rx_fifo.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "sa1111_sac_tx_stream.h"
#include "../../state/state_stream.h"

bool Sa1111SacRxFifo::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Jornada720;
}

/* SA-1111 Developer's Manual §7.3.2.2: "Each phase of the Left/Right signal is accompanied
   by one serial audio data sample on the data pins SDATA_IN and SDATA_OUT". */
uint64_t Sa1111SacRxFifo::Received(uint64_t pos) const {
    return running_ ? level0_ + (pos - pos0_) : level0_;
}

uint32_t Sa1111SacRxFifo::Level(uint64_t pos) const {
    const uint64_t received = Received(pos);
    return received < Sa1111SacTxStream::kFifoDepth ? static_cast<uint32_t>(received)
                                                    : Sa1111SacTxStream::kFifoDepth;
}

/* Table 7-10 ROR: "1 - Attempted data write to full Receive FIFO". */
bool Sa1111SacRxFifo::Overrun(uint64_t pos) const {
    return overrun_ || Received(pos) > Sa1111SacTxStream::kFifoDepth;
}

/* Table 7-10 RFS: "0 - Receive FIFO level below RFL threshold, or SAC disabled". */
bool Sa1111SacRxFifo::ServiceRequest(uint64_t pos, bool enabled, uint32_t threshold) const {
    return enabled && Level(pos) >= threshold;
}

/* Table 7-10: RNE bit 1, RFS bit 4, ROR bit 6, RFL 15:12 "Number of entries in Receive
   FIFO". */
uint32_t Sa1111SacRxFifo::StatusBits(uint64_t pos, bool enabled, uint32_t threshold) const {
    const uint32_t level = Level(pos);
    uint32_t bits = (level & 0xFu) << 12;
    if (level != 0u)                             bits |= 1u << 1;
    if (ServiceRequest(pos, enabled, threshold)) bits |= 1u << 4;
    if (Overrun(pos))                            bits |= 1u << 6;
    return bits;
}

void Sa1111SacRxFifo::Start(uint64_t pos) {
    pos0_    = pos;
    running_ = true;
}

void Sa1111SacRxFifo::Stop(uint64_t pos) {
    overrun_ = Overrun(pos);
    level0_  = Level(pos);
    running_ = false;
}

void Sa1111SacRxFifo::Clear(uint64_t pos) {
    level0_  = 0u;
    pos0_    = pos;
    overrun_ = false;
}

void Sa1111SacRxFifo::ClearOverrun(uint64_t pos) {
    level0_  = Level(pos);
    pos0_    = pos;
    overrun_ = false;
}

void Sa1111SacRxFifo::Save(StateWriter& w, uint64_t pos) const {
    w.Write<uint32_t>("rx_running", running_ ? 1u : 0u);
    w.Write<uint32_t>("rx_fifo_level", Level(pos));
    w.Write<uint32_t>("rx_overrun", Overrun(pos) ? 1u : 0u);
}

void Sa1111SacRxFifo::Restore(StateReader& r, uint64_t pos) {
    uint32_t running = 0u, level = 0u, overrun = 0u;
    r.Read("rx_running", running);
    r.Read("rx_fifo_level", level);
    r.Read("rx_overrun", overrun);
    running_ = running != 0u;
    level0_  = level;
    overrun_ = overrun != 0u;
    pos0_    = pos;
}

REGISTER_SERVICE(Sa1111SacRxFifo);
