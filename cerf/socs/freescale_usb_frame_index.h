#pragma once

#include "../jit/guest_cycle_clock.h"
#include "cycle_anchored_counter.h"

#include <array>
#include <cstdint>

class CerfEmulator;
class StateReader;
class StateWriter;

class FreescaleUsbFrameIndex {
public:
    static constexpr uint32_t kCores  = 4u;
    static constexpr uint32_t kStsFri = 1u << 3;
    static constexpr uint32_t kStsSri = 1u << 7;
    static constexpr uint64_t kNever  = ~0ull;

    explicit FreescaleUsbFrameIndex(CerfEmulator& emu) : emu_(emu) {}

    static uint32_t FrameListSizeCode(uint32_t usbcmd);
    static uint32_t FrameListElements(uint32_t fs) { return 1024u >> fs; }

    void     Attach();
    void     Rescale();
    void     SetRunning(uint32_t core, bool running, bool host);
    void     SetFrameListSize(uint32_t core, uint32_t fs);
    bool     Running(uint32_t core) const { return running_[core]; }
    void     SetClocked(uint32_t core, bool on);
    bool     Clocked(uint32_t core) const { return clocked_[core]; }
    uint32_t Frindex(uint32_t core);
    void     WriteFrindex(uint32_t core, uint32_t value);
    void     Reset(uint32_t core);
    void     ResetAll();
    uint32_t Status(uint32_t core);
    void     ClearStatus(uint32_t core, uint32_t bits);
    uint64_t NextFrameCycle(uint32_t core);
    uint64_t NextStatusCycle(uint32_t core, uint32_t bits);

    void Save(StateWriter& w);
    void Restore(StateReader& r);

private:
    uint32_t Now() const;
    bool     Counting(uint32_t core) const { return running_[core] && clocked_[core]; }
    uint32_t FrindexAt(uint32_t core, uint32_t now) const;
    uint32_t StatusAt(uint32_t core, uint32_t now) const;
    void     Latch(uint32_t core, uint32_t now);

    CerfEmulator&                emu_;
    GuestCycleClock*             clock_ = nullptr;
    CycleAnchoredCounter         uframes_;
    std::array<bool, kCores>     clocked_{};
    std::array<bool, kCores>     running_{};
    std::array<bool, kCores>     host_{};
    std::array<uint8_t, kCores>  fs_{};
    std::array<uint32_t, kCores> frindex_{};
    std::array<uint32_t, kCores> mark_{};
    std::array<uint32_t, kCores> latched_{};
};
