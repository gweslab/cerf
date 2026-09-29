#pragma once

#include <cstdint>
#include <optional>

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../tracing/trace_manager.h"
#include "../guest_engine.h"
#include "mips_cpu_state.h"

class GuestCycleClock;
class HostRequestChannel;
class MipsBlockCompiler;
class MipsCp0Ops;
class MipsCpu;
class MipsExceptionDelivery;
class MipsExceptionModel;
class MipsInterruptChannel;
class MipsMemoryAccess;
class MipsMmu;
class MipsTranslationCache;
class EmulatedMemory;

class MipsJit : public GuestEngine {
public:
    using GuestEngine::GuestEngine;

    void OnReady() override;
    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Mips;
    }

    MipsCpuState* CpuState() { return cpu_state_; }

    void SetExternalInterruptLevel(uint32_t ip_mask);

    static void __cdecl Dispatch(void* native_pc, MipsCpuState* state);

    void     Run() override;
    bool     DeepSleep()    const override { return cpu_state_->deep_sleep != 0; }
    bool     ResetPending() const override;
    void     SetHostChainExit(bool requested) override;

    bool     GuestIrqMasked() const override;
    uint32_t Pc()           const override { return cpu_state_->pc; }
    void     PrintFatalDump() override;
    uint32_t PhysAddrMask() const override { return cpu_state_->phys_addr_mask; }
    void     DispatchTraceIter() override {
#if CERF_DEV_MODE
        emu_.Get<TraceManager>().DispatchRunLoopIterMips(cpu_state_);
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
    void EnterDeepSleep() override;
    void ExitDeepSleep() override;
    void EnterIdleWait() override;
    void SetInjectionBand(uint32_t va, uint32_t pa, uint32_t size) override;
    void SetDmaRegion(uint32_t pa, uint32_t size) override;

private:
    void DeliverReset();

    MipsCpuState* cpu_state_ = nullptr;

    MipsCpu*               cpu_        = nullptr;
    MipsMmu*               mmu_        = nullptr;
    EmulatedMemory*        memory_     = nullptr;
    MipsTranslationCache*  cache_      = nullptr;
    MipsBlockCompiler*     compiler_   = nullptr;
    MipsInterruptChannel*  channel_    = nullptr;
    MipsMemoryAccess*      mem_access_ = nullptr;
    MipsCp0Ops*            cp0_ops_    = nullptr;
    MipsExceptionDelivery* exceptions_ = nullptr;
    MipsExceptionModel*    exc_model_  = nullptr;
    GuestCycleClock*       clock_      = nullptr;
    HostRequestChannel*    host_requests_ = nullptr;
};
