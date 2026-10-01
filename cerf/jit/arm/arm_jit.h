#pragma once

#include <cstdint>
#include <optional>

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../tracing/trace_manager.h"
#include "../guest_engine.h"
#include "cpu_state.h"

struct ArmMmuState;

class ArmBlockCompiler;
class ArmCpu;
class ArmInterruptChannel;
class ArmMmu;
class ArmMmuProbe;
class ArmPageWalker;
class ArmTranslationCache;
class GuestCycleClock;
class HostRequestChannel;

class ArmJit : public GuestEngine {
public:
    using GuestEngine::GuestEngine;

    void OnReady() override;
    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Arm;
    }

    ArmCpuState* CpuState() { return cpu_state_; }

    void SetInterruptPending();
    void ClearInterruptPending();
    void SetIdleWake(bool level);

    static void __cdecl Dispatch(void*        native_pc,
                                 ArmCpuState* cpu_state,
                                 ArmMmuState* mmu_state);

    void     Run() override;
    bool     DeepSleep()    const override { return cpu_state_->deep_sleep != 0; }
    bool     ResetPending() const override { return cpu_state_->reset_pending != 0; }

    bool GuestIrqMasked() const override {
        return cpu_state_->cpsr.bits.irq_disable != 0u;
    }
    uint32_t Pc()           const override { return cpu_state_->gprs[ArmGpr::kR15]; }
    void     PrintFatalDump() override;
    void     DispatchTraceIter() override {
#if CERF_DEV_MODE
        emu_.Get<TraceManager>().DispatchRunLoopIter(cpu_state_->gprs,
                                                     ArmPackCpsr(*cpu_state_));
#endif
    }

    std::optional<uint8_t*> PeekGuestVa(uint32_t va) override;
    uint8_t* ResolveGuestVaToHost(uint32_t va) override;
    bool     ResolveGuestVaToPa(uint32_t va, uint32_t* pa) override;

    void SaveCpuState(StateWriter& w)    override;
    void RestoreCpuState(StateReader& r) override;
    void SaveMmuState(StateWriter& w)    override;
    void RestoreMmuState(StateReader& r) override;

    void FlushTranslationCache() override;
    void SetResetPending(bool is_resume) override;
    void SetHostChainExit(bool requested) override;
    void EnterDeepSleep() override;
    void ExitDeepSleep() override;
    void EnterIdleWait() override;
    void SetInjectionBand(uint32_t va, uint32_t pa, uint32_t size) override;
    void SetDmaRegion(uint32_t pa, uint32_t size) override;

private:
    ArmCpuState* cpu_state_ = nullptr;

    ArmCpu*              cpu_      = nullptr;
    ArmMmu*              mmu_      = nullptr;
    ArmMmuProbe*         probe_    = nullptr;
    ArmPageWalker*       walker_   = nullptr;
    uint32_t             predecessor_va_ = 0;
    ArmTranslationCache* cache_    = nullptr;
    ArmBlockCompiler*    compiler_ = nullptr;
    ArmInterruptChannel* channel_  = nullptr;
    GuestCycleClock*     clock_    = nullptr;
    HostRequestChannel*  host_requests_ = nullptr;
};
