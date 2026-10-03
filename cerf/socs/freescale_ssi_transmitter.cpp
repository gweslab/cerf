#include "freescale_ssi_transmitter.h"

#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../state/state_stream.h"

#include <algorithm>
#include <bit>

namespace ssi = cerf_freescale_ssi;

void FreescaleSsiTransmitter::Attach() {
    clock_ = &emu_.Get<GuestCycleClock>();
    grid_.Attach(1u, 1u);
    underrun_event_ = clock_->Add([this] { OnUnderrun(); });
}

void FreescaleSsiTransmitter::Reset() {
    enabled_ = grid_on_ = te_ = irq_tue0_ = underrun_ = false;
    tdmae_ = tfen0_ = dma_request_ = false;
    shape_     = FreescaleSsiFrameShape{};
    tfwm_      = 0u;
    settled_   = 0u;
    tx_start_  = kNever;
    tx_stop_   = kNever;
    fifo_.Configure(depth_, 0u, 0u);
    fifo_.Clear();
    fifo_.ResetMoved();
    UpdateSupply();
    clock_->Disarm(underrun_event_);
}

void FreescaleSsiTransmitter::UpdateSupply() {
    fifo_.SetSupply(DmaOn() ? DmaBurstFifo::kUnlimited : 0u);
}

bool FreescaleSsiTransmitter::ShapeKnown(const FreescaleSsiFrameShape& shape) {
    return shape.frame_hz != 0u && shape.slots != 0u && shape.slots <= 32u && shape.bits != 0u;
}

uint64_t FreescaleSsiTransmitter::DataSlotsBefore(uint64_t slot) const {
    const uint32_t s    = shape_.slots;
    const uint32_t part = static_cast<uint32_t>(slot % s);
    return (slot / s) * static_cast<uint64_t>(std::popcount(shape_.data)) +
           static_cast<uint64_t>(std::popcount(shape_.data & ((1u << part) - 1u)));
}

uint64_t FreescaleSsiTransmitter::TxDataSlots(uint64_t from, uint64_t to) const {
    if (tx_start_ == kNever) return 0u;
    const uint64_t lo = std::max(from, tx_start_);
    const uint64_t hi = std::min(to, tx_stop_);
    return hi > lo ? DataSlotsBefore(hi) - DataSlotsBefore(lo) : 0u;
}

uint64_t FreescaleSsiTransmitter::NthDataSlot(uint64_t from, uint64_t n) const {
    const uint32_t per = static_cast<uint32_t>(std::popcount(shape_.data));
    if (tx_start_ == kNever || per == 0u || n == 0u) return kNever;
    const uint64_t target = DataSlotsBefore(std::max(from, tx_start_)) + n - 1u;
    uint32_t bits = shape_.data;
    for (uint32_t r = static_cast<uint32_t>(target % per); r != 0u; --r) bits &= bits - 1u;
    const uint64_t slot = (target / per) * shape_.slots +
                          static_cast<uint64_t>(std::countr_zero(bits));
    return slot < tx_stop_ ? slot : kNever;
}

uint64_t FreescaleSsiTransmitter::NextFrame(uint64_t slot) const {
    return (slot + shape_.slots - 1u) / shape_.slots * shape_.slots;
}

/* MCIMX51RM Table 56-12 TE: "SSI expects 4 setup clock cycles before arrival of frame-sync for
   frame-sync to be accepted by SSI. In case of fewer clock cycles, there is high probability of
   the frame-sync to get missed." */
uint64_t FreescaleSsiTransmitter::AcceptedFrame(uint64_t frame_slot, uint64_t now_bit) const {
    if (setup_clocks_ == 0u || frame_slot * shape_.bits >= now_bit + 1u + setup_clocks_) {
        return frame_slot;
    }
    return frame_slot + shape_.slots;
}

uint64_t FreescaleSsiTransmitter::CycleOfSlot(uint64_t slot) {
    return grid_.CycleOf(slot * shape_.bits);
}

/* MCIMX31RM Table 45-7: STX data "is transferred to the transmit shift register (TXSR), when
   shifting of the previous data is complete"; §40.12.3.5 NOTE: a channel "reads or writes a
   number of data that matches the watermark level", repeated while the request stays set. */
void FreescaleSsiTransmitter::Settle() {
    if (!enabled_ || !grid_on_) return;
    const uint64_t end = grid_.Now() / shape_.bits + 1u;
    if (end <= settled_) return;
    const uint64_t n = TxDataSlots(settled_, end);
    settled_ = end;
    if (fifo_.Take(n) != 0u) underrun_ = true;
    if (tx_stop_ != kNever && settled_ >= tx_stop_) tx_start_ = tx_stop_ = kNever;
    fifo_.Refill();
}

/* Table 45-9 SSIEN: "When disabled, all SSI status bits are preset to the same state
   produced by the power-on reset ... the contents of transmit and receive FIFOs are
   cleared. When SSI is disabled, all internal clocks are disabled". */
void FreescaleSsiTransmitter::Enable(const FreescaleSsiFrameShape& shape) {
    enabled_  = true;
    fifo_.Clear();
    settled_  = 0u;
    underrun_ = false;
    tx_start_ = tx_stop_ = kNever;
    shape_    = shape;
    grid_on_  = ShapeKnown(shape);
    if (grid_on_) {
        grid_.SetOscRate(shape.frame_hz * shape.slots * shape.bits, 1u);
        grid_.Rebase();
    }
    if (te_) {
        if (!grid_on_) {
            emu_.Get<Fatal>().Die("SSI %08X: transmit enabled with a frame clock this model "
                                  "cannot place", base_);
        }
        tx_start_ = AcceptedFrame(0u, grid_.Now());
    }
    RequireDmaTarget();
    fifo_.Refill();
}

void FreescaleSsiTransmitter::Disable() {
    enabled_  = false;
    grid_on_  = false;
    fifo_.Clear();
    settled_  = 0u;
    underrun_ = false;
    tx_start_ = tx_stop_ = kNever;
    RequireDmaTarget();
}

/* MCIMX31RM §45.1.2.2.1: "transmission starts from the next frame boundary"; Table 45-9 TE:
   "the transmitter continues to send data until the end of the current frame and then stops". */
void FreescaleSsiTransmitter::SetTransmit(bool on) {
    te_ = on;
    if (!enabled_) return;
    const uint64_t now_bit = grid_.Now();
    if (on) {
        if (!grid_on_) {
            emu_.Get<Fatal>().Die("SSI %08X: transmit enabled with a frame clock this model "
                                  "cannot place", base_);
        }
        if (tx_start_ != kNever) {
            /* Table 45-9 / Table 56-12 TE: "set again before the second to last bit of the last
               time slot in the current frame, data transmission continues without interruption" */
            if (now_bit + 2u >= tx_stop_ * shape_.bits) {
                emu_.Get<Fatal>().Die("SSI %08X: TE set again within the last two bit clocks of the "
                                      "frame its clear stops; the restart is not modeled", base_);
            }
            tx_stop_ = kNever;
            return;
        }
        tx_start_ = AcceptedFrame(NextFrame(settled_), now_bit);
        tx_stop_  = kNever;
        return;
    }
    if (tx_start_ == kNever) return;
    if (tx_start_ >= settled_) {
        if (AcceptedFrame(tx_start_, now_bit) == tx_start_) {
            tx_start_ = kNever;
        } else {
            tx_stop_ = tx_start_ + shape_.slots;
        }
        return;
    }
    tx_stop_ = AcceptedFrame(NextFrame(settled_), now_bit);
}

void FreescaleSsiTransmitter::WriteScr(uint32_t old_scr, uint32_t scr,
                                       const FreescaleSsiFrameShape& shape) {
    Settle();
    const bool was_on = (old_scr & ssi::kScrSsien) != 0u;
    const bool on     = (scr & ssi::kScrSsien) != 0u;
    const bool te     = (scr & ssi::kScrTe) != 0u;
    if ((scr & ssi::kScrTchEn) != 0u && on && te) {
        emu_.Get<Fatal>().Die("SSI %08X: SCR 0x%08X transmits in two-channel mode; FIFO 1 is "
                              "not modeled", base_, scr);
    }
    if (was_on && !on) Disable();
    if (!was_on && on) {
        te_ = te;
        Enable(shape);
    } else if (on) {
        SetShape(shape);
        if (te != te_) SetTransmit(te);
    } else {
        te_ = te;
    }
    ArmUnderrun();
}

void FreescaleSsiTransmitter::SetShape(const FreescaleSsiFrameShape& shape) {
    Settle();
    if (!enabled_) {
        shape_ = shape;
        return;
    }
    const bool known = ShapeKnown(shape);
    if (!grid_on_) {
        if (known) {
            emu_.Get<Fatal>().Die("SSI %08X: the frame clock became known while the SSI runs; "
                                  "its phase since SSIEN is not modeled", base_);
        }
        shape_ = shape;
        return;
    }
    if (!known || shape.slots != shape_.slots || shape.bits != shape_.bits) {
        emu_.Get<Fatal>().Die("SSI %08X: the frame changes from %u slots of %u bits at %llu Hz to "
                              "%u slots of %u bits at %llu Hz while the SSI runs", base_,
                              shape_.slots, shape_.bits,
                              static_cast<unsigned long long>(shape_.frame_hz), shape.slots,
                              shape.bits, static_cast<unsigned long long>(shape.frame_hz));
    }
    if (shape.frame_hz != shape_.frame_hz) {
        grid_.SetOscRate(shape.frame_hz * shape.slots * shape.bits, 1u);
    }
    shape_ = shape;
    ArmUnderrun();
}

void FreescaleSsiTransmitter::OnCpuRate() {
    if (!enabled_ || !grid_on_) return;
    grid_.Rescale();
    ArmUnderrun();
}

/* MCIMX31RM Table 45-11 TDMAE: "DMA requests are generated when any of the TFE0/1 bits in the
   SISR are set and if the corresponding TFEN bit is also set"; Table 45-16 TFWM0. */
void FreescaleSsiTransmitter::WriteDmaControl(uint32_t sier, uint32_t stcr, uint32_t sfcsr) {
    Settle();
    if ((sier & ssi::kSierTie) != 0u &&
        (sier & ssi::kSierTxIrqEnables & ~ssi::kSierTue0En) != 0u) {
        emu_.Get<Fatal>().Die("SSI %08X: SIER 0x%08X enables transmit interrupts this model "
                              "does not raise", base_, sier);
    }
    irq_tue0_    = (sier & ssi::kSierTie) != 0u && (sier & ssi::kSierTue0En) != 0u;
    tdmae_       = (sier & ssi::kSierTdmae) != 0u;
    tfen0_       = (stcr & ssi::kStcrTfen0) != 0u;
    dma_request_ = tdmae_ && tfen0_;
    tfwm_        = sfcsr & ssi::kSfcsrTfwm0Mask;
    fifo_.Configure(depth_, tfwm_ <= depth_ ? depth_ - tfwm_ : 0u, fifo_.Burst());
    UpdateSupply();
    RequireDmaTarget();
    fifo_.Refill();
    ArmUnderrun();
}

void FreescaleSsiTransmitter::RequireDmaTarget() const {
    const uint32_t burst = fifo_.Burst();
    if (burst == 0u) return;
    if (tdmae_ && !tfen0_) {
        emu_.Get<Fatal>().Die("SSI %08X: TDMAE with transmit FIFO 0 disabled; the TDE-driven "
                              "DMA request is not modeled", base_);
    }
    if (!dma_request_) return;
    if (!enabled_) {
        emu_.Get<Fatal>().Die("SSI %08X: a transmit DMA request with SSIEN clear is not "
                              "modeled", base_);
    }
    if (tfwm_ == 0u || tfwm_ > depth_) {
        emu_.Get<Fatal>().Die("SSI %08X: TFWM0 %u is reserved", base_, tfwm_);
    }
    if (burst > tfwm_) {
        emu_.Get<Fatal>().Die("SSI %08X: a %u-word DMA burst exceeds the %u empty slots TFWM0 "
                              "guarantees; the overflow is not modeled", base_, burst, tfwm_);
    }
}

/* MCIMX31RM p.45-27 NOTE: "Enable SSI (SSIEN=1) before writing to SSI transmit data
   registers"; Table 45-7: past the eighth word "Data9 is discarded". */
void FreescaleSsiTransmitter::WriteStx0(uint32_t scr, uint32_t stcr) {
    if ((scr & ssi::kScrSsien) == 0u || (stcr & ssi::kStcrTfen0) == 0u) {
        emu_.Get<Fatal>().Die("SSI %08X: STX0 write with SCR 0x%08X STCR 0x%08X; a write to a "
                              "disabled SSI or a disabled transmit FIFO 0 is not modeled",
                              base_, scr, stcr);
    }
    Settle();
    fifo_.Put();
    ArmUnderrun();
}

void FreescaleSsiTransmitter::SetDmaBurst(uint32_t words) {
    Settle();
    fifo_.Configure(depth_, fifo_.Threshold(), words);
    fifo_.ResetMoved();
    UpdateSupply();
    RequireDmaTarget();
    fifo_.Refill();
    ArmUnderrun();
}

uint32_t FreescaleSsiTransmitter::Level() {
    Settle();
    return fifo_.Level();
}

bool FreescaleSsiTransmitter::Transmitting() {
    Settle();
    return enabled_ && tx_start_ != kNever;
}

void FreescaleSsiTransmitter::ClearUnderrun() {
    Settle();
    underrun_ = false;
    ArmUnderrun();
}

uint64_t FreescaleSsiTransmitter::DmaWords() {
    Settle();
    return fifo_.Moved();
}

bool FreescaleSsiTransmitter::CycleOfDmaWords(uint64_t words, uint64_t& cycle) {
    Settle();
    if (words <= fifo_.Moved()) {
        cycle = clock_->Cycles();
        return true;
    }
    if (!DmaOn() || !enabled_ || !grid_on_) return false;
    uint64_t takes = 0;
    if (!fifo_.TakesToMove(words, takes)) return false;
    const uint64_t slot = NthDataSlot(settled_, takes);
    if (slot == kNever) return false;
    cycle = CycleOfSlot(slot);
    return true;
}

bool FreescaleSsiTransmitter::CycleOfUnderrun(uint64_t& cycle) {
    if (DmaOn() || !enabled_ || !grid_on_) return false;
    const uint64_t slot = NthDataSlot(settled_, fifo_.TakesBeforeEmpty() + 1u);
    if (slot == kNever) return false;
    cycle = CycleOfSlot(slot);
    return true;
}

void FreescaleSsiTransmitter::ArmUnderrun() {
    if (!irq_tue0_ || !enabled_) {
        clock_->Disarm(underrun_event_);
        return;
    }
    Settle();
    if (underrun_) OnUnderrun();
    uint64_t cycle = 0;
    if (CycleOfUnderrun(cycle)) {
        clock_->Arm(underrun_event_, cycle);
    } else {
        clock_->Disarm(underrun_event_);
    }
}

void FreescaleSsiTransmitter::OnUnderrun() {
    emu_.Get<Fatal>().Die("SSI %08X: transmit underrun with TIE and TUE0_EN set; the SSI "
                          "interrupt is not modeled", base_);
}

void FreescaleSsiTransmitter::Save(StateWriter& w) {
    Settle();
    w.Write<uint8_t>("tx_enabled", enabled_ ? 1u : 0u);
    w.Write<uint8_t>("tx_grid_on", grid_on_ ? 1u : 0u);
    w.Write<uint8_t>("tx_te", te_ ? 1u : 0u);
    w.Write<uint8_t>("tx_irq_tue0", irq_tue0_ ? 1u : 0u);
    w.Write<uint8_t>("tx_underrun", underrun_ ? 1u : 0u);
    w.Write<uint8_t>("tx_tdmae", tdmae_ ? 1u : 0u);
    w.Write<uint8_t>("tx_tfen0", tfen0_ ? 1u : 0u);
    w.Write<uint64_t>("tx_frame_hz", shape_.frame_hz);
    w.Write<uint32_t>("tx_slots", shape_.slots);
    w.Write<uint32_t>("tx_data", shape_.data);
    w.Write<uint32_t>("tx_bits", shape_.bits);
    w.Write<uint32_t>("tx_tfwm", tfwm_);
    w.Write<uint32_t>("tx_level", fifo_.Level());
    w.Write<uint64_t>("tx_settled", settled_);
    w.Write<uint64_t>("tx_start", tx_start_);
    w.Write<uint64_t>("tx_stop", tx_stop_);
    w.Write<uint32_t>("tx_burst", fifo_.Burst());
    w.Write<uint64_t>("tx_dma_words", fifo_.Moved());
    grid_.Save(w);
}

void FreescaleSsiTransmitter::Restore(StateReader& r) {
    uint8_t enabled = 0, grid_on = 0, te = 0, irq = 0, underrun = 0, tdmae = 0, tfen0 = 0;
    uint32_t level = 0, burst = 0;
    uint64_t moved = 0;
    r.Read("tx_enabled", enabled);
    r.Read("tx_grid_on", grid_on);
    r.Read("tx_te", te);
    r.Read("tx_irq_tue0", irq);
    r.Read("tx_underrun", underrun);
    r.Read("tx_tdmae", tdmae);
    r.Read("tx_tfen0", tfen0);
    r.Read("tx_frame_hz", shape_.frame_hz);
    r.Read("tx_slots", shape_.slots);
    r.Read("tx_data", shape_.data);
    r.Read("tx_bits", shape_.bits);
    r.Read("tx_tfwm", tfwm_);
    r.Read("tx_level", level);
    r.Read("tx_settled", settled_);
    r.Read("tx_start", tx_start_);
    r.Read("tx_stop", tx_stop_);
    r.Read("tx_burst", burst);
    r.Read("tx_dma_words", moved);
    grid_.Restore(r);
    enabled_     = enabled != 0u;
    grid_on_     = grid_on != 0u;
    te_          = te != 0u;
    irq_tue0_    = irq != 0u;
    underrun_    = underrun != 0u;
    tdmae_       = tdmae != 0u;
    tfen0_       = tfen0 != 0u;
    dma_request_ = tdmae_ && tfen0_;
    fifo_.Configure(depth_, tfwm_ <= depth_ ? depth_ - tfwm_ : 0u, burst);
    fifo_.Restore(level, moved);
    UpdateSupply();
    clock_->Disarm(underrun_event_);
}

void FreescaleSsiTransmitter::PostRestore() { ArmUnderrun(); }
