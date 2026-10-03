#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

/* SA-1110 Dev Man §11.13: PPC peripheral-pin control, 22 pins. Register block:
   PPDR (+0x0) pin direction (0=input/1=output, reset 0=all input), PPSR (+0x4)
   pin state, PPAR/PSDR/PPFR (+0x8..+0x10); MCCR1 (+0x30, MCP) shares the block,
   +0x28 a reserved HPIrDA poke. */
class Sa11xxPpc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x90060000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    /* Board peripherals drive external PPC input-pin levels here (any thread),
       e.g. an OEM boot-mode strap on an otherwise-unused LDD line that the OAL
       samples via PPSR before the LCD is enabled. A level on a pin configured
       as output in PPDR has no effect on PPSR reads (§11.13.4). */
    void DriveInputPin(uint32_t pin, bool level);

    uint32_t Mccr1() const { return mccr1_; }
    uint32_t Ppar() const;
    void     RegisterMccr1Listener(std::function<void()> fn);
    void     RegisterPparListener(std::function<void()> fn);

private:
    void WriteMccr1(uint32_t value);
    void NotifyIfPpar(uint32_t index);

    std::vector<std::function<void()>> mccr1_listeners_;
    std::vector<std::function<void()>> ppar_listeners_;
    static constexpr uint32_t kPparIndex        = 2u;
    static constexpr uint32_t kReservedIrdaPoke = 0x28u;  /* HPIrDA sub_EE4B88. */
    static constexpr uint32_t kMccr1Offset      = 0x30u;  /* SA-1110 Dev Man: MCCR1 R/W. */
    static constexpr uint32_t kPpsrIndex        = 1u;     /* PPSR = +0x4. */
    static constexpr uint32_t kPinMask          = 0x003FFFFFu;  /* bits 21:0 (22 pins). */

    /* Guards PPSR pin state - DriveInputPin runs on peripheral/host threads
       concurrently with JIT-thread register access. */
    mutable std::mutex mtx_;

    /* PPDR (0), PPSR-output-shadow (1), PPAR (2), PSDR (3), PPFR (4). PPSR
       writes land in regs_[1] as the output-pin shadow; PPSR reads combine it
       with input_state_ via the PPDR direction mask. */
    uint32_t regs_[5]      = {};
    uint32_t input_state_  = 0;   /* board-driven external input-pin levels. */
    uint32_t mccr1_        = 0;

    uint32_t ReadPpsrLocked() const {
        const uint32_t ppdr = regs_[0];
        return ((regs_[kPpsrIndex] & ppdr) | (input_state_ & ~ppdr)) & kPinMask;
    }

    static bool OffsetToIndex(uint32_t off, uint32_t* index_out) {
        if (off > 0x10 || (off & 0x3u) != 0) return false;
        *index_out = off / 4u;
        return true;
    }
};
