#pragma once

#include <cstdint>

#include "../../core/service.h"
#include "cpu_state.h"

class StateWriter;
class StateReader;

class ArmCpu : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;

    ArmCpuState* State() { return &state_; }

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);

    void UpdateCpsrWithFlags(ArmPsrFull psr);

    uint32_t ReturnFromException(uint32_t new_cpsr_word, uint32_t new_pc);

    uint32_t*   BankedSp(uint32_t mode);
    ArmPsrFull* BankedSpsr(uint32_t mode);

    void SetInitialStackPointer(uint32_t sp);

    void SetPendingResumeVector(uint32_t pc);
    void SetPendingResumeMmu(uint32_t control, uint32_t ttbr0, uint32_t dacr);

    void RaiseUndefinedException(uint32_t guest_pc);
    void RaiseAbortDataException(uint32_t guest_pc);
    void RaiseAbortPrefetchException(uint32_t guest_pc);
    void RaiseIrqException(uint32_t guest_pc);
    void RaiseSwiException(uint32_t guest_pc);
    void RaiseResetException(uint32_t initial_pc, bool initial_thumb);
    void RaiseResetException();

    static void __cdecl RaiseUndefinedExceptionHelper(ArmCpu* cpu, uint32_t guest_pc);
    static void __cdecl RaiseSwiExceptionHelper(ArmCpu* cpu, uint32_t guest_pc);
    static void __cdecl UpdateNzcvOnlyHelper(ArmCpu* cpu, uint32_t nzcv_source);

    static void __cdecl WriteCpsrByInstrHelper(ArmCpu* cpu, uint32_t value,
                                               uint32_t mask_user,
                                               uint32_t mask_priv,
                                               uint32_t state_trip_mask,
                                               uint32_t sctlr);
    static void __cdecl WriteSpsrByInstrHelper(ArmCpu* cpu, uint32_t value,
                                               uint32_t mask);
    static uint32_t __cdecl ReadSpsrHelper(ArmCpu* cpu);

    static uint32_t __cdecl ReadUserRegHelper(ArmCpu* cpu, uint32_t reg);
    static void     __cdecl WriteUserRegHelper(ArmCpu* cpu, uint32_t reg,
                                               uint32_t value);
    static uint32_t __cdecl ExceptionReturnHelper(ArmCpu* cpu, uint32_t new_pc);

    static void __fastcall EnterDeepSleepHelper(ArmCpu* cpu);

private:
    template <typename F>
    static constexpr void VisitState(ArmCpuState& s, F& field);
    void     SwitchModeBanks(uint32_t old_mode, uint32_t new_mode);
    void     EnterException(uint32_t target_mode, uint32_t new_lr_value,
                            uint32_t vect_offset, bool set_async_abort_mask);
    uint32_t ReturnAddress(uint32_t guest_pc, int32_t thumb_sub, int32_t arm_sub);
    uint32_t ExcVectorBase();
    void     ApplySctlrExecutionState();

    ArmCpuState state_{};

    uint32_t pending_resume_pc_      = 0;
    bool     pending_resume_pc_set_  = false;
    uint32_t pending_resume_control_ = 0;
    uint32_t pending_resume_ttbr0_   = 0;
    uint32_t pending_resume_dacr_    = 0;
    bool     pending_resume_mmu_set_ = false;
    uint32_t initial_pc_             = 0;
    bool     initial_thumb_          = false;
    uint32_t initial_sp_             = 0;
};
