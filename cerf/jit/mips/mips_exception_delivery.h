#pragma once

#include <cstdint>

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/service.h"
#include "mips_mmu.h"

struct MipsCpuState;

class MipsExceptionModel;

class MipsExceptionDelivery : public Service {
public:
    using Service::Service;

    void OnReady() override;
    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Mips;
    }

    static constexpr uint32_t kGuestExceptionCode = 0xE0000001u;

    void EnterException(uint32_t cause, bool refill_eligible);

    /* QEMU target/mips raise_mmu_exception CP0 register setup. */
    void SetMmuFaultRegs(uint32_t va);

    void RaiseTlbException(uint32_t va, MipsAccess acc, MipsTlbResult res);
    void DeliverFetchTlbException(uint32_t va, MipsTlbResult res);
    void DeliverFetchAddressError(uint32_t va);
    void RaiseAddressError(uint32_t va, MipsAccess acc);
    void RaiseOverflowException();
    [[noreturn]] void LeaveBlock();

    /* QEMU target/mips internal.h enabled/pending gates. */
    bool InterruptReady() const;

    void DeliverInterrupt();

    static void __fastcall SyscallHelper(MipsExceptionDelivery* ex);
    static void __fastcall BreakHelper(MipsExceptionDelivery* ex);

    static void __cdecl ArithOverflowHelper(MipsExceptionDelivery* ex, uint32_t pc);

private:
    MipsCpuState*       cpu_state_ = nullptr;
    MipsExceptionModel* model_     = nullptr;
};
