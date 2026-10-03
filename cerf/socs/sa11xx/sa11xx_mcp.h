#pragma once

#include "../../peripherals/peripheral_base.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <functional>
#include <vector>

class Sa11xxDma;
class Sa11xxMcpAudioStream;

class Sa11xxMcp : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x80060000u; }
    uint32_t MmioSize() const override { return 0x00000060u; }

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    uint32_t Mccr0() const { return mccr0_; }
    void     RegisterControlListener(std::function<void()> fn);

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

private:
    static constexpr uint64_t kNever = UINT64_MAX;

    void     RouteCodecCommand(uint32_t cmd);
    void     ControlChanged();
    void     SettleCommand(uint64_t now);
    void     ArmCommand(uint64_t now);
    void     ClearCompletion(uint64_t now);
    uint64_t CompletionOffset(bool write) const;

    std::vector<std::function<void()>> control_listeners_;
    Sa11xxMcpAudioStream*   audio_  = nullptr;
    GuestCycleClock*        clock_  = nullptr;
    GuestCycleClock::Event* cmd_ev_ = nullptr;
    Sa11xxDma*              dma_    = nullptr;
    uint32_t mccr0_      = 0;
    bool     cmd_valid_  = false;
    bool     cmd_write_  = false;
    bool     cmd_sent_   = false;
    bool     cmd_applied_ = false;
    uint8_t  cmd_reg_    = 0;
    uint16_t cmd_value_  = 0;
    uint32_t cmd_run_    = 0;
    uint64_t cmd_first_  = kNever;
    uint64_t cmd_clear_  = 0;
    bool     cwc_        = false;
    bool     crc_        = false;
    uint32_t mcdr2_      = 0;
};
