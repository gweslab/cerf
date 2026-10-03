#pragma once

#include "../jit/guest_cycle_clock.h"
#include "dma_burst_fifo.h"
#include "oscillator_ticks.h"

#include <cstdint>

class CerfEmulator;
class StateReader;
class StateWriter;

/* MCIMX31RM Table 45-9 SCR, Figure 45-27 SIER, Figure 45-28 STCR, Table 45-16 SFCSR,
   Table 45-10 SISR; MCIMX51RM Table 56-12, Figure 56-29, Table 56-20, Table 56-13: the same
   bit positions. */
namespace cerf_freescale_ssi {
constexpr uint32_t kScrSsien         = 1u << 0;
constexpr uint32_t kScrTe            = 1u << 1;
constexpr uint32_t kScrNet           = 1u << 3;
constexpr uint32_t kScrI2sShift      = 5;
constexpr uint32_t kScrTchEn         = 1u << 8;
constexpr uint32_t kI2sMaster        = 1u;
constexpr uint32_t kI2sSlave         = 2u;
constexpr uint32_t kSierTdmae        = 1u << 20;
constexpr uint32_t kSierTie          = 1u << 19;
constexpr uint32_t kSierTue0En       = 1u << 8;
constexpr uint32_t kSierTxIrqEnables = 0x000033A3u;
constexpr uint32_t kStcrTfen0        = 1u << 7;
constexpr uint32_t kSfcsrTfwm0Mask   = 0xFu;
constexpr uint32_t kSfcsrTfcnt0Shift = 8;
constexpr uint32_t kSisrTue0         = 1u << 8;
}

struct FreescaleSsiFrameShape {
    uint64_t frame_hz = 0;
    uint32_t slots    = 0;
    uint32_t data     = 0;
    uint32_t bits     = 0;
};

class FreescaleSsiTransmitter {
public:
    FreescaleSsiTransmitter(CerfEmulator& emu, uint32_t base, uint32_t depth,
                            uint32_t frame_sync_setup_clocks)
        : emu_(emu), base_(base), depth_(depth), setup_clocks_(frame_sync_setup_clocks),
          grid_(emu, false) {}

    void Attach();
    void Reset();
    void WriteScr(uint32_t old_scr, uint32_t scr, const FreescaleSsiFrameShape& shape);
    void SetShape(const FreescaleSsiFrameShape& shape);
    void OnCpuRate();
    void WriteDmaControl(uint32_t sier, uint32_t stcr, uint32_t sfcsr);
    void WriteStx0(uint32_t scr, uint32_t stcr);
    void SetDmaBurst(uint32_t words);

    uint32_t Level();
    bool     Transmitting();
    void     ClearUnderrun();
    uint64_t DmaWords();
    bool     CycleOfDmaWords(uint64_t words, uint64_t& cycle);

    void Save(StateWriter& w);
    void Restore(StateReader& r);
    void PostRestore();

private:
    static constexpr uint64_t kNever = UINT64_MAX;

    static bool ShapeKnown(const FreescaleSsiFrameShape& shape);

    void     Settle();
    void     UpdateSupply();
    bool     DmaOn() const { return dma_request_ && fifo_.Burst() != 0u; }
    uint64_t DataSlotsBefore(uint64_t slot) const;
    uint64_t TxDataSlots(uint64_t from, uint64_t to) const;
    uint64_t NthDataSlot(uint64_t from, uint64_t n) const;
    uint64_t NextFrame(uint64_t slot) const;
    uint64_t AcceptedFrame(uint64_t frame_slot, uint64_t now_bit) const;
    uint64_t CycleOfSlot(uint64_t slot);
    void     Enable(const FreescaleSsiFrameShape& shape);
    void     Disable();
    void     SetTransmit(bool on);
    void     RequireDmaTarget() const;
    bool     CycleOfUnderrun(uint64_t& cycle);
    void     ArmUnderrun();
    void     OnUnderrun();

    CerfEmulator&           emu_;
    const uint32_t          base_;
    const uint32_t          depth_;
    const uint32_t          setup_clocks_;
    OscillatorTicks         grid_;
    GuestCycleClock*        clock_          = nullptr;
    GuestCycleClock::Event* underrun_event_ = nullptr;
    FreescaleSsiFrameShape  shape_;
    bool     enabled_     = false;
    bool     grid_on_     = false;
    bool     te_          = false;
    bool     irq_tue0_    = false;
    bool     underrun_    = false;
    bool     tdmae_       = false;
    bool     tfen0_       = false;
    bool     dma_request_ = false;
    uint32_t tfwm_        = 0;
    uint64_t settled_     = 0;
    uint64_t tx_start_    = kNever;
    uint64_t tx_stop_     = kNever;
    DmaBurstFifo fifo_;
};
