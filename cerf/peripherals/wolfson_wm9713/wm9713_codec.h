#pragma once

#include "../ac97_codec.h"

#include <cstdint>
#include <deque>
#include <mutex>

/* symbol_mk500 touch.dll FUN_02238118 @0x02238118 names this part
   "WM9713/14" and matches it on device ID 0x4C13. */
class Wm9713Codec : public Ac97Codec {
public:
    using Ac97Codec::Ac97Codec;

    bool ShouldRegister() override;
    void OnReady() override;

    uint16_t ReadReg(uint32_t reg) override;
    void     WriteReg(uint32_t reg, uint16_t value) override;
    bool     PopModemSlot(uint16_t& word) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    /* symbol_mk500 touch.dll FUN_02237380 @0x02237380 pulls one tagged word per
       enabled channel out of MODR. */
    void SetPen(bool down, uint16_t raw_x, uint16_t raw_y);

private:
    uint16_t MakeWord(uint16_t sel, bool down, uint16_t raw_x, uint16_t raw_y);
    void     PushLocked(uint16_t word);

    static constexpr uint32_t kNumRegs = 0x80u;
    /* Intel PXA27x Developer's Manual 280000-001 section 13.6.5 (page 13-18):
       "Modem receive FIFO, with sixteen 32-bit entries (upper 16 bits are
       always 0)". */
    static constexpr size_t kModemRxDepth = 16u;

    uint16_t             reg_[kNumRegs] = {};
    std::mutex           mutex_;
    std::deque<uint16_t> modem_rx_;
    bool                 pen_down_ = false;
    uint16_t             raw_x_ = 0, raw_y_ = 0;
};
