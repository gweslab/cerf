#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <mutex>

/* SA-1110 Dev Man §9.1.1: GPSR (+0x8) and GPCR (+0xC) are W-O set/clear
   commands updating the output shadow read via GPLR (+0x0); GEDR (+0x18)
   is W1C. §9.1.1.5/§9.2.1.1: a GRER/GFER-matched edge latches GEDR, GPIO
   0..10 are ICPR sources 0..10, GPIO 27..11 OR into source 11. */
class Sa11xxGpio : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x90040000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    /* Board peripherals drive external input pins here (any thread).
       Level changes on input-configured pins latch GEDR per GRER/GFER
       and update the INTC sources. */
    void DriveInputPin(uint32_t pin, bool level);

    /* §9.5.7.4: "For a GPIO to serve as a wake-up source, it must be
       programmed as an input in the GPDR." */
    uint32_t InputEdges() const;

    void LoadSleepOutputs(uint32_t pgsr);

private:
    static constexpr uint32_t kPinMask = 0x0FFFFFFFu;  /* bits 27:0 */

    /* Guards pin/edge state - DriveInputPin runs on peripheral/host
       threads concurrently with JIT-thread register access. */
    mutable std::mutex mtx_;

    /* Output-pin shadow (driven by GPSR/GPCR writes for output-
       configured pins). Input pins read from input_state_. */
    uint32_t output_state_ = 0;
    uint32_t input_state_  = 0;
    uint32_t gpdr_         = 0;
    uint32_t grer_         = 0x3u;
    uint32_t gfer_         = 0x3u;
    uint32_t gedr_         = 0;
    uint32_t gafr_         = 0;

    uint32_t ReadGplrLocked() const {
        return ((output_state_ & gpdr_) | (input_state_ & ~gpdr_)) & kPinMask;
    }

    uint32_t ReadReg(uint32_t off);
    void     WriteReg(uint32_t off, uint32_t value);
    void     PublishEdgeSourcesLocked();
};
