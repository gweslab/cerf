#pragma once

#include "../../core/service.h"
#include "../../cpu/sm501_8051/sm501_8051_core.h"

#include <atomic>
#include <cstdint>
#include <mutex>

class StateReader;
class StateWriter;

namespace siemens_mp377 {

class SiemensMp377Sm501Regs;
class SiemensMp377Sm501Ac97;

// SM501 Databook ch. 12 controller: 8051 core, SRAM ownership and the
// CPU/8051 protocol mailbox used by the MP377 VGXaudio firmware.
class SiemensMp377Sm501AudioMcu : public Service, private sm501_8051::Bus {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    static bool IsControlRegister(uint32_t offset);
    static bool IsSram(uint32_t offset);
    static constexpr uint32_t kOutputIrqBit = 1u << 10;
    static constexpr uint32_t kSramBase = 0x0C0000u;
    static constexpr uint32_t kSramLimit = 0x0C4000u;

    uint32_t ReadControl(uint32_t address, uint32_t offset);
    uint32_t ReadSramWord(uint32_t address, uint32_t offset);
    void WriteControl(uint32_t offset, uint32_t old_value, uint32_t value);
    void WriteSramWord(uint32_t address, uint32_t offset, uint32_t old_value, uint32_t value);
    uint8_t ReadSramByte(uint32_t offset) const;
    void WriteSramByte(uint32_t offset, uint8_t value);
    void RunMmioSlice(uint32_t budget);
    void SignalAc97Interrupt();
    void RunAc97Frames(uint32_t frames);
    void SaveState(StateWriter& writer) const;
    void RestoreState(StateReader& reader);

private:
    static constexpr uint32_t kControlBase = 0x0B0000u;
    static constexpr uint32_t kControlEnd = 0x0B0010u;
    static constexpr uint32_t kProgramBase = kSramBase;
    static constexpr uint32_t kProgramEnd = 0x0C3000u;
    static constexpr uint32_t kSramEnd = kSramLimit;
    static constexpr uint32_t kResetReg = 0x0B0000u;
    static constexpr uint32_t kModeReg = 0x0B0004u;
    static constexpr uint32_t kToCpuIrqReg = 0x0B0008u;
    static constexpr uint32_t kFromCpuIrqReg = 0x0B000Cu;
    static constexpr uint32_t kMailboxCmd = 0x0C3FF0u;
    static constexpr uint32_t kMailboxStatus = 0x0C3FF1u;
    static constexpr uint32_t kMailboxArg0 = 0x0C3FF2u;
    static constexpr uint32_t kMailboxBusy = 0x0C3FFDu;
    static constexpr uint32_t kMailboxReady = 0x0C3FFFu;

    bool IsEnabled() const;
    static bool IsProgramSram(uint32_t offset);
    void Reset();
    void ResetDevice();
    void RunSlice(uint32_t budget, bool clock_ac97);
    uint32_t StepCore(bool clock_ac97 = true);
    void RunOneAc97Frame();
    void RunUntilMailboxReady(uint8_t target);
    void RunUntilMailboxBusy();
    void RunMailboxCommand();
    uint8_t AudioByte(uint32_t offset) const;
    void SetAudioByte(uint32_t offset, uint8_t value);
    void ClearProtocolInterrupt();

    uint8_t FetchCode(uint16_t address) const override;
    uint8_t ReadExternal(uint16_t address) override;
    void WriteExternal(uint16_t address, uint8_t value) override;
    [[noreturn]] void Fault(const char* what, uint32_t detail) override;

    sm501_8051::Core core_;
    std::atomic<bool> enabled_{false};
    std::atomic<bool> from_cpu_irq_pending_{false};
    std::atomic<bool> to_cpu_irq_pending_{false};
    std::atomic<uint32_t> to_cpu_token_{0u};
    std::atomic<uint32_t> from_cpu_token_{0u};
    mutable std::recursive_mutex core_mutex_;
};

} // namespace siemens_mp377
