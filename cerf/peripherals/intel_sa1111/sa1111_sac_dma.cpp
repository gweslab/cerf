#include "sa1111_sac_dma.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../../cpu/emulated_memory.h"
#include "sa1111_reset_line.h"
#include "sa1111_sac_host_output.h"
#include "sa1111_sac_request_lines.h"
#include "sa1111_sac_tx_stream.h"
#include "sa1111_sbi.h"
#include "sa1111_system_controller.h"
#include "../../host/audio_activity_widget.h"
#include "../../state/state_stream.h"

#include <vector>

namespace {

constexpr uint32_t kTfthModelled = 7u;

/* SA-1111 Developer's Manual Table 3-3 note 1: "All reserved bits are read back as zero."
   Tables 7-21 / 7-23 / 7-26 / 7-28 count 12:0; Table 7-24 SADRCS RDIE bit 1. */
constexpr uint32_t kCountMask = 0x1FFFu;
constexpr uint32_t kRden      = 1u << 0;
constexpr uint32_t kRdie      = 1u << 1;
constexpr uint32_t kRdsta     = 1u << 4;
constexpr uint32_t kRdstb     = 1u << 6;

}

bool Sa1111SacDma::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Jornada720;
}

void Sa1111SacDma::OnReady() {
    stream_     = &emu_.Get<Sa1111SacTxStream>();
    lines_      = &emu_.Get<Sa1111SacRequestLines>();
    host_       = &emu_.Get<Sa1111SacHostOutput>();
    sbi_        = &emu_.Get<Sa1111Sbi>();
    reset_line_ = &emu_.Get<Sa1111ResetLine>();
    clock_      = &emu_.Get<GuestCycleClock>();
    done_ev_    = clock_->Add([this] { OnDoneEvent(); });
    sbi_->RegisterGrantListener([this] { OnGrantChange(); });
    sbi_->RegisterClkInputListener([this] { Evaluate(clock_->Cycles()); });
}

void Sa1111SacDma::SetFifoControlReader(std::function<FifoControl()> read) {
    fifo_ = std::move(read);
}

uint32_t Sa1111SacDma::ReadRegister(uint32_t off) {
    switch (off) {
        case 0x34: Evaluate(clock_->Cycles()); return sadtcs_;
        case 0x38: return sadtsa_;
        case 0x3C: return sadtca_;
        case 0x40: return sadtsb_;
        case 0x44: return sadtcb_;
        case 0x48: return sadrcs_;
        case 0x4C: return sadrsa_;
        case 0x50: return sadrca_;
        case 0x54: return sadrsb_;
        case 0x58: return sadrcb_;
    }
    emu_.Get<Fatal>().Die("Sa1111SacDma: read of SAC register +0x%02X is not modelled", off);
}

void Sa1111SacDma::WriteRegister(uint32_t off, uint32_t value) {
    switch (off) {
        case 0x34: WriteSadtcs(value); return;
        case 0x38: sadtsa_ = value; return;
        case 0x3C: sadtca_ = value & kCountMask; return;
        case 0x40: sadtsb_ = value; return;
        case 0x44: sadtcb_ = value & kCountMask; return;
        case 0x48: WriteSadrcs(value); return;
        case 0x4C: sadrsa_ = value; return;
        case 0x50: sadrca_ = value & kCountMask; return;
        case 0x54: sadrsb_ = value; return;
        case 0x58: sadrcb_ = value & kCountMask; return;
    }
    emu_.Get<Fatal>().Die("Sa1111SacDma: write 0x%08X to SAC register +0x%02X is not modelled",
                          value, off);
}

void Sa1111SacDma::WriteSadrcs(uint32_t value) {
    if (value & (kRden | kRdsta | kRdstb)) {
        emu_.Get<Fatal>().Die("Sa1111SacDma: audio DMA receive start (SADRCS=0x%08X) is not "
                              "modelled", value);
    }
    sadrcs_ = value & kRdie;
}

/* SA-1111 Developer's Manual Table 7-19 (printed 7-18): TDIE "Serial Audio DMA Transmit Interrupt
   Enable (Done A or Done B)." */
void Sa1111SacDma::WriteSadtcs(uint32_t value) {
    const uint64_t now = clock_->Cycles();
    if (tx_running_) Evaluate(now);
    sadtcs_ &= ~(value & (kTdbda | kTdbdb));
    sadtcs_  = (sadtcs_ & ~(kTden | kTdie)) | (value & (kTden | kTdie));
    sadtcs_ |= value & (kTdsta | kTdstb);
    if (!(sadtcs_ & kTden)) sadtcs_ &= ~(kTdsta | kTdstb | kTbiu);
    if (!(sadtcs_ & kTdie) || !(sadtcs_ & kTdbda)) done_irq_a_ = false;
    if (!(sadtcs_ & kTdie) || !(sadtcs_ & kTdbdb)) done_irq_b_ = false;
    PublishDone(0u);
#if CERF_DEV_MODE
    LOG(Periph, "[Sa1111Sac] SADTCS W 0x%08X -> 0x%08X (running=%d buf=%c)\n",
        value, sadtcs_, tx_running_ ? 1 : 0, tx_buffer_b_ ? 'B' : 'A');
#endif
    if (!(sadtcs_ & kTden)) {
        StopTransmit();
        host_->End();
        return;
    }
    if (!tx_running_) {
        stream_->SetGrant(now, sbi_->Grant(), false);
        TryStartNext(now);
    }
    Evaluate(now);
}

void Sa1111SacDma::StopTransmit() {
    tx_running_ = false;
    words_left_ = 0u;
    clock_->Disarm(done_ev_);
}

void Sa1111SacDma::Reset() {
    StopTransmit();
    sadtcs_ = sadtsa_ = sadtca_ = sadtsb_ = sadtcb_ = 0u;
    sadrcs_ = sadrsa_ = sadrca_ = sadrsb_ = sadrcb_ = 0u;
    done_irq_a_ = done_irq_b_ = false;
    PublishDone(0u);
    host_->End();
}

uint32_t Sa1111SacDma::Threshold() const {
    const uint32_t level = fifo_().threshold_level;
    if (level != kTfthModelled + 1u) {
        emu_.Get<Fatal>().Die("Sa1111SacDma: transmit DMA with SACR0 TFTH %u; only TFTH %u is "
                              "modelled", level - 1u, kTfthModelled);
    }
    return level;
}

/* § 7.2.2 (printed 7-5): "When the complete block is transferred, it sets the appropriate
   DMA_Done bit in the status register." */
void Sa1111SacDma::CatchUp(uint64_t now) {
    for (;;) {
        if (tx_running_ && words_left_ != 0u) stream_->Fill(now, Threshold(), words_left_);
        if (!tx_running_ || words_left_ != 0u || (sadtcs_ & kTdie) != 0u) break;
        const uint64_t done = stream_->LandedCycle();
        if (done > now) break;
        CompleteBlock(done, now);
    }
    stream_->Settle(now);
}

void Sa1111SacDma::TryStartNext(uint64_t now) {
    if (sadtcs_ & kTdsta)      StartBlock(now, false);
    else if (sadtcs_ & kTdstb) StartBlock(now, true);
    else                       sadtcs_ &= ~kTbiu;
}

/* Tables 7-20 / 7-21: "The LSB 2 bits must be 00. Data Transfer unit is four bytes"; §7.2.2:
   the transfer size "can be specified to byte-level resolution". §7.3.1: one 32-bit word
   holds the left (15:0) and right (31:16) samples. */
void Sa1111SacDma::StartBlock(uint64_t now, bool buffer_b) {
    RequireClocks();
    if (!fifo_().enabled) {
        emu_.Get<Fatal>().Die("Sa1111SacDma: transmit DMA start on buffer %c with the SAC "
                              "disabled (SACR0 ENB clear or RST set) is not modelled",
                              buffer_b ? 'B' : 'A');
    }
    if (stream_->Grant() == Sa1111Sbi::BusGrant::Undetermined) {
        emu_.Get<Fatal>().Die("Sa1111SacDma: transmit DMA start on buffer %c with the MBGNT input "
                              "undetermined is not modelled", buffer_b ? 'B' : 'A');
    }
    const uint32_t pa    = buffer_b ? sadtsb_ : sadtsa_;
    const uint32_t bytes = buffer_b ? sadtcb_ : sadtca_;
    if (((pa | bytes) & 0x3u) != 0u) {
        emu_.Get<Fatal>().Die("Sa1111SacDma: transmit DMA start on buffer %c at 0x%08X with %u "
                              "bytes, not word-aligned, is not modelled",
                              buffer_b ? 'B' : 'A', pa, bytes);
    }
    if (bytes == 0u) {
        emu_.Get<Fatal>().Die("Sa1111SacDma: transmit DMA start on buffer %c with a zero byte "
                              "count is not modelled", buffer_b ? 'B' : 'A');
    }
    tx_running_  = true;
    tx_buffer_b_ = buffer_b;
    sadtcs_      = (sadtcs_ & ~kTbiu) | (buffer_b ? kTbiu : 0u);
    host_->Begin();
    std::vector<uint8_t> block(bytes);
    emu_.Get<EmulatedMemory>().CopyOut(pa, block.data(), bytes);
    host_->Queue(block.data(), bytes);
    words_left_ = bytes / 4u;
#if CERF_DEV_MODE
    LOG(Periph, "[Sa1111Sac] TX start buf=%c pa=0x%08X bytes=%u SADTCS=0x%08X cyc=%llu\n",
        buffer_b ? 'B' : 'A', pa, bytes, sadtcs_, static_cast<unsigned long long>(now));
#endif
    stream_->StartBlock(now);
}

void Sa1111SacDma::Evaluate(uint64_t now) {
    CatchUp(now);
    if (tx_running_ && (sadtcs_ & kTdie) != 0u && words_left_ == 0u &&
        stream_->LandedCycle() <= now) {
        CompleteBlock(now, now);
        CatchUp(now);
    }
    ArmDone();
}

/* Table 7-19 TDIE; § 7.2.2: "An interrupt will be signaled to the system processor if it's
   enabled." */
void Sa1111SacDma::ArmDone() {
    uint64_t cycle = 0;
    if (tx_running_ && (sadtcs_ & kTdie) != 0u &&
        stream_->DoneCycle(clock_->Cycles(), Threshold(), words_left_, cycle)) {
        clock_->Arm(done_ev_, cycle);
    } else {
        clock_->Disarm(done_ev_);
    }
}

void Sa1111SacDma::OnDoneEvent() { Evaluate(clock_->Cycles()); }

void Sa1111SacDma::OnGrantChange() {
    const Sa1111Sbi::BusGrant grant = sbi_->Grant();
    if (grant == stream_->Grant()) return;
    const uint64_t now = clock_->Cycles();
    Evaluate(now);
    stream_->SetGrant(now, grant, tx_running_ && !reset_line_->PowerOnHoldPending() &&
                                  !sbi_->ClockDisturbed());
    Evaluate(now);
}

void Sa1111SacDma::PublishDone(uint8_t completed) {
    lines_->PublishDone(done_irq_a_, done_irq_b_, completed);
}

/* SA-1111 Developer's Manual § 7.2.2 (printed 7-5): "When the complete block is transferred, it
   sets the appropriate DMA_Done bit in the status register. An interrupt will be signaled to
   the system processor if it's enabled." */
void Sa1111SacDma::CompleteBlock(uint64_t at, uint64_t seen) {
    const bool buffer_b = tx_buffer_b_;
    if (sbi_->ClockDisturbed()) {
        emu_.Get<Fatal>().Die("Sa1111SacDma: transmit DMA completion on buffer %c after the SA-1111 "
                              "CLK input changed outside reset is not modelled",
                              buffer_b ? 'B' : 'A');
    }
    tx_running_ = false;
    sadtcs_ |= buffer_b ? kTdbdb : kTdbda;
    sadtcs_ &= ~(buffer_b ? kTdstb : kTdsta);
    const bool raise = (sadtcs_ & kTdie) != 0u;
    if (raise) (buffer_b ? done_irq_b_ : done_irq_a_) = true;
#if CERF_DEV_MODE
    LOG(Periph, "[Sa1111Sac] TX done buf=%c SADTCS=0x%08X cyc=%llu land=%llu seen=%llu\n",
        buffer_b ? 'B' : 'A', sadtcs_, static_cast<unsigned long long>(at),
        static_cast<unsigned long long>(stream_->LandedCycle()),
        static_cast<unsigned long long>(seen));
#else
    (void)seen;
#endif
    emu_.Get<AudioActivityWidget>().MarkTx();
    if (raise) {
        PublishDone(buffer_b ? Sa1111SacRequestLines::kSrcDoneB
                             : Sa1111SacRequestLines::kSrcDoneA);
    }
    if (sadtcs_ & kTden) TryStartNext(at);
    else                 sadtcs_ &= ~kTbiu;
}

/* SA-1111 Developer's Manual §2.2 (printed 2-3): the dividers after the VCO give the DMA bus "a
   clock (DCLK) of 48 MHz". */
void Sa1111SacDma::RequireClocks() const {
    const auto& sc  = emu_.Get<Sa1111SystemController>();
    if (sc.DmaClockEnabled() && sbi_->BusClocksEnabled() && sc.PllRunningAtResetRate()) return;
    emu_.Get<Fatal>().Die("Sa1111SacDma: transmit DMA with SKPCR DCLKEn or SKCR RCLKEn clear, "
                          "SKCR 0x%08X (PLL bypassed, VCO off, Sleep or Doze), no 3.6864 MHz CLK "
                          "input, or SKCDR 0x%08X (a PLL rate other than the reset one) is not "
                          "modelled", sbi_->Skcr(), sc.Skcdr());
}

void Sa1111SacDma::OnClockChange() const {
    if (tx_running_) RequireClocks();
}

void Sa1111SacDma::Save(StateWriter& w, uint64_t now) {
    CatchUp(now);
    w.Write("sadtcs", sadtcs_); w.Write("sadtsa", sadtsa_); w.Write("sadtca", sadtca_); w.Write("sadtsb", sadtsb_); w.Write("sadtcb", sadtcb_);
    w.Write("sadrcs", sadrcs_); w.Write("sadrsa", sadrsa_); w.Write("sadrca", sadrca_); w.Write("sadrsb", sadrsb_); w.Write("sadrcb", sadrcb_);
    w.Write<uint32_t>("tx_running", tx_running_ ? 1u : 0u);
    w.Write<uint32_t>("tx_buffer_b", tx_buffer_b_ ? 1u : 0u);
    w.Write<uint32_t>("tx_words_left", words_left_);
    w.Write<uint8_t>("tx_done_irq_a", done_irq_a_ ? 1u : 0u);
    w.Write<uint8_t>("tx_done_irq_b", done_irq_b_ ? 1u : 0u);
}

void Sa1111SacDma::Restore(StateReader& r) {
    r.Read("sadtcs", sadtcs_); r.Read("sadtsa", sadtsa_); r.Read("sadtca", sadtca_); r.Read("sadtsb", sadtsb_); r.Read("sadtcb", sadtcb_);
    r.Read("sadrcs", sadrcs_); r.Read("sadrsa", sadrsa_); r.Read("sadrca", sadrca_); r.Read("sadrsb", sadrsb_); r.Read("sadrcb", sadrcb_);
    uint32_t running = 0u, buffer_b = 0u, words = 0u;
    r.Read("tx_running", running);
    r.Read("tx_buffer_b", buffer_b);
    r.Read("tx_words_left", words);
    uint8_t irq_a = 0u, irq_b = 0u;
    r.Read("tx_done_irq_a", irq_a);
    r.Read("tx_done_irq_b", irq_b);
    tx_running_  = running != 0u;
    tx_buffer_b_ = buffer_b != 0u;
    words_left_  = words;
    done_irq_a_  = irq_a != 0u;
    done_irq_b_  = irq_b != 0u;
    clock_->Disarm(done_ev_);
    host_->Drop();
}

void Sa1111SacDma::PostRestore() {
    stream_->SetGrant(clock_->Cycles(), sbi_->Grant(), false);
    lines_->BaselineDone(done_irq_a_, done_irq_b_);
    if (!tx_running_) return;
    host_->Begin();
    ArmDone();
}

REGISTER_SERVICE(Sa1111SacDma);
