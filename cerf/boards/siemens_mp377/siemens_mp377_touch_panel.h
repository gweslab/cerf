#pragma once

#include "../../core/service.h"

#include <atomic>
#include <cstdint>

class StateReader;
class StateWriter;

namespace siemens_mp377 {

class SiemensMp377TouchPanel : public Service {
public:
    using Service::Service;

    /* siemens_mp377_v1040 touch.dll TouchPanelEnable/sub_29E1F08 calls
       InterruptInitialize for SYSINTR 0x1B; nk.exe sub_80445460 maps it to IRQ 0x23. */
    static constexpr int kTouchIrqSource = 0x23;

    bool ShouldRegister() override;
    void OnReady() override;

    bool QueueSmiCommand(uint16_t cmd);
    bool HasPendingSmiResponse() const;
    uint32_t PendingSmiResponseCount() const;
    uint32_t ReadSmiSampleWord();
    uint32_t ReadPenDetectReg();
    void UpdateHostPointer(int x, int y, bool down);
    void CaptureLost();

    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);
    void PostRestore();

private:
    void ResetTransport();
    void RecomputePenIrq();
    bool EffectiveTouchDown() const;
    uint16_t PopSmiResponse();
    uint16_t AdcResponseForControl(uint8_t control) const;
    void HostPointToTouchRaw(uint32_t x, uint32_t y, uint16_t* raw_x, uint16_t* raw_y) const;

    std::atomic<uint32_t> smi_last_cmd_{0u};
    std::atomic<uint32_t> penirq_enabled_{0u};
    std::atomic<uint32_t> touch_down_{0};
    std::atomic<uint32_t> touch_x_{0};
    std::atomic<uint32_t> touch_y_{0};
    double touch_affine_[6]{};

    uint16_t smi_response_q_[16] = {};
    uint32_t smi_response_head_ = 0;
    uint32_t smi_response_tail_ = 0;
};

} // namespace siemens_mp377
