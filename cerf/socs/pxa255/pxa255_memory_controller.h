#pragma once

#include "../../peripherals/peripheral_base.h"
#include "../guest_cpu_reset.h"

#include <cstdint>
#include <functional>
#include <vector>

/* PXA255 Memory Controller (§6.13 Table 6-43, base 0x48000000). */
class Pxa255MemoryController : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x48000000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override { PublishSdclk2(); }

    uint64_t Sdclk2Hz() const;
    void     RegisterSdclk2Listener(std::function<void()> fn);

private:
    static constexpr uint32_t kMdrefr   = 0x04u;
    static constexpr uint32_t kBootDef  = 0x44u;
    static constexpr uint32_t kLastReg  = 0x58u;

    void OnResetLine(ResetLineKind kind);
    void ResetRegisters();
    void PublishSdclk2();

    uint32_t regs_[(kLastReg / 4u) + 1u] = {};
    uint64_t published_sdclk2_hz_ = 0;
    std::vector<std::function<void()>> sdclk2_listeners_;
};
