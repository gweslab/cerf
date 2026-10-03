#pragma once

#include "../../socs/irq_controller.h"

#include <cstdint>
#include <mutex>

class StateWriter;
class StateReader;

constexpr int kSourceSystemIntr        = 0;
constexpr int kSourceLcdIntr           = 2;
constexpr int kSourceProdSerialIntr    = 3;
constexpr int kSourceTouchAudioAdcIntr = 5;
constexpr int kSourceKeybIntr          = 6;
constexpr int kSourceIrIntr            = 7;
constexpr int kSourceEtherIntr         = 8;

class OdoArm720BoardIntc : public IrqController {
public:
    using IrqController::IrqController;

    bool ShouldRegister() override;
    void OnReady() override;

    void AssertIrq   (int source_bit)                          override;
    void AssertSubIrq(int main_source_bit, int sub_source_bit) override;
    void DeAssertIrq (int source_bit)                          override;

    void SetTimerIrqLevel(bool level);

    uint32_t ReadReg32 (uint32_t offset);
    uint16_t ReadReg16 (uint32_t offset);
    void     WriteReg32(uint32_t offset, uint32_t value);
    void     WriteReg16(uint32_t offset, uint16_t value);

    /* State image: cpuIsr + cpuMr are the whole INTC state. */
    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);
    void PostRestore();

private:
    bool HasPendingUnmaskedLocked() const;
    void NotifyJitInterruptState();
    void PublishIrqLineLocked();

    std::mutex state_mutex_;
    uint32_t   cpu_isr_ = 0;
    uint32_t   cpu_mr_  = 0;
    bool       timer_irq_level_ = false;
};
