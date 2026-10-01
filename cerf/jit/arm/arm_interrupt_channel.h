#pragma once

#include <atomic>
#include <cstdint>

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/service.h"

struct ArmCpuState;

class GuestCycleClock;
class HostRequestChannel;

class ArmInterruptChannel : public Service {
public:
    using Service::Service;
    ~ArmInterruptChannel() override;

    void OnReady() override;
    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Arm;
    }

    void SetInterruptPending();
    void ClearInterruptPending();
    void SetIdleWake(bool level);

    uint32_t Level() const { return irq_line_.load(std::memory_order_acquire); }

    struct IrqGate {
        uint32_t level;
        bool     raise;
    };

    IrqGate EvaluateGate() const;

    /* DDI 0406C.c B1.9.10 (p. B1-1219): "If SCTLR.FI == 0, IRQ exception entry
       is precise to an instruction boundary." */
    bool BackOutForIrq(uint32_t guest_pc);

    static uint32_t __cdecl BackOutForIrqHelper(ArmInterruptChannel* channel,
                                                uint32_t guest_pc);

    void Wake();

    void RequestHostService();
    bool TakeHostRequest();

    void WaitForInterrupt();

    static void __fastcall WfiHelper(ArmInterruptChannel* channel);

private:
    std::atomic<uint32_t> irq_line_{0};
    std::atomic<uint32_t> idle_wake_line_{0};
    std::atomic<uint32_t> host_request_{0};
    void*                 idle_event_ = nullptr;

    ArmCpuState*        cpu_state_     = nullptr;
    GuestCycleClock*    clock_         = nullptr;
    HostRequestChannel* host_requests_ = nullptr;
};
