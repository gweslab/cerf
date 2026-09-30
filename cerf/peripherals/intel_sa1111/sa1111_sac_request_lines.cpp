#include "sa1111_sac_request_lines.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "sa1111_intc.h"
#include "sa1111_sac_l3.h"
#include "sa1111_sac_rx_fifo.h"
#include "sa1111_sac_tx_stream.h"

bool Sa1111SacRequestLines::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Jornada720;
}

void Sa1111SacRequestLines::OnReady() {
    intc_   = &emu_.Get<Sa1111Intc>();
    stream_ = &emu_.Get<Sa1111SacTxStream>();
    rx_     = &emu_.Get<Sa1111SacRxFifo>();
    l3_     = &emu_.Get<Sa1111SacL3>();
}

Sa1111SacRequestLines::Levels Sa1111SacRequestLines::Sample(uint64_t now, bool enabled,
                                                            uint32_t tx_threshold,
                                                            uint32_t rx_threshold) const {
    const uint64_t pos = stream_->Position(now);
    Levels levels;
    levels.tfs      = stream_->ServiceRequest(now, enabled, tx_threshold);
    levels.requests = stream_->Requests();
    levels.rfs      = rx_->ServiceRequest(pos, enabled, rx_threshold);
    levels.tur      = stream_->Underrun(now);
    levels.ror      = rx_->Overrun(pos);
    levels.dts      = l3_->DataSent(now);
    return levels;
}

/* SA-1111 Developer's Manual §11.3 (printed 11-4): the INT pin "can be cleared by clearing the
   appropriate interrupt bit and the corresponding interrupt bit in the peripheral module";
   §7.2.2: "When the complete block is transferred, it sets the appropriate DMA_Done bit". */
void Sa1111SacRequestLines::DriveDone(uint8_t source, bool level, bool& published,
                                      bool completed) {
    if (completed && published) intc_->SetSourceLevel(source, false);
    if (completed || level != published) intc_->SetSourceLevel(source, level);
    published = level;
}

void Sa1111SacRequestLines::PublishDone(bool done_a, bool done_b, uint8_t completed) {
    DriveDone(kSrcDoneA, done_a, done_a_, completed == kSrcDoneA);
    DriveDone(kSrcDoneB, done_b, done_b_, completed == kSrcDoneB);
}

void Sa1111SacRequestLines::BaselineDone(bool done_a, bool done_b) {
    done_a_ = done_a;
    done_b_ = done_b;
}

void Sa1111SacRequestLines::Baseline(uint64_t now, bool enabled, uint32_t tx_threshold,
                                     uint32_t rx_threshold) {
    pub_ = Sample(now, enabled, tx_threshold, rx_threshold);
}

/* SA-1111 Developer's Manual Table 7-10 TFS: "1 - Transmit FIFO level is at or below TFL
   threshold (Interruptible)"; §7.2.2: "After a transfer burst, the SAC must give up its
   request". */
void Sa1111SacRequestLines::Publish(uint64_t now, bool enabled, uint32_t tx_threshold,
                                    uint32_t rx_threshold) {
    const Levels next = Sample(now, enabled, tx_threshold, rx_threshold);
    const uint64_t requests = next.requests - pub_.requests;
    if (requests != 0u) {
        if (!pub_.tfs) intc_->SetSourceLevel(kSrcTfsr, true);
        intc_->SetSourceLevel(kSrcTfsr, false);
        if (requests > 1u) {
            intc_->SetSourceLevel(kSrcTfsr, true);
            intc_->SetSourceLevel(kSrcTfsr, false);
        }
        pub_.tfs = false;
    }
    if (next.tfs != pub_.tfs) intc_->SetSourceLevel(kSrcTfsr, next.tfs);
    if (next.rfs != pub_.rfs) intc_->SetSourceLevel(kSrcRfsr, next.rfs);
    if (next.tur != pub_.tur) intc_->SetSourceLevel(kSrcTur,  next.tur);
    if (next.ror != pub_.ror) intc_->SetSourceLevel(kSrcRor,  next.ror);
    if (next.dts != pub_.dts) intc_->SetSourceLevel(kSrcDts,  next.dts);
    pub_ = next;
}

REGISTER_SERVICE(Sa1111SacRequestLines);
