#include "mips_exception_delivery.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "mips_cpu.h"
#include "mips_cpu_state.h"
#include "mips_exception_model.h"

REGISTER_SERVICE(MipsExceptionDelivery);

void MipsExceptionDelivery::OnReady() {
    cpu_state_ = emu_.Get<MipsCpu>().State();
    model_     = &emu_.Get<MipsExceptionModel>();
}

void MipsExceptionDelivery::EnterException(uint32_t cause, bool refill_eligible) {
    model_->Enter(cpu_state_, cause, refill_eligible);
}

void MipsExceptionDelivery::SetMmuFaultRegs(uint32_t va) {
    model_->SetMmuFaultRegs(cpu_state_, va);
}

void MipsExceptionDelivery::RaiseTlbException(uint32_t va, MipsAccess acc,
                                              MipsTlbResult res) {
    SetMmuFaultRegs(va);

    uint32_t cause = 0;
    bool nomatch = false;
    switch (res) {
        case MipsTlbResult::kNoMatch:   /* TLBRET_NOMATCH: TLBL/TLBS + refill vector */
            cause = (acc == MipsAccess::kWrite) ? MipsExcCode::kTLBS : MipsExcCode::kTLBL;
            nomatch = true;
            break;
        case MipsTlbResult::kInvalid:   /* TLBRET_INVALID: TLBL/TLBS, general vector */
            cause = (acc == MipsAccess::kWrite) ? MipsExcCode::kTLBS : MipsExcCode::kTLBL;
            break;
        case MipsTlbResult::kModified:  /* TLBRET_DIRTY: EXCP_LTLBL (TLB Modified) */
            cause = MipsExcCode::kMod;
            break;
        case MipsTlbResult::kMatch:
            LOG(Caution, "MipsExceptionDelivery::RaiseTlbException: kMatch is not a "
                    "fault (va=0x%08X)\n", va);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            return;
    }

    EnterException(cause, nomatch);
    RaiseException(kGuestExceptionCode, 0, 0, nullptr);
}

void MipsExceptionDelivery::DeliverFetchTlbException(uint32_t va,
                                                     MipsTlbResult res) {
    /* QEMU target/mips raise_mmu_exception MMU_INST_FETCH -> EXCP_TLBL; refill
       vector when NOMATCH. */
    SetMmuFaultRegs(va);
    EnterException(MipsExcCode::kTLBL, /*refill_eligible=*/res == MipsTlbResult::kNoMatch);
}

void MipsExceptionDelivery::DeliverFetchAddressError(uint32_t va) {
    /* QEMU target/mips mips_cpu_do_unaligned_access MMU_INST_FETCH -> EXCP_AdEL
       (op_helper.c:311-323); cause 4, general vector. */
    cpu_state_->cp0_badvaddr = va;
    EnterException(MipsExcCode::kAdEL, /*refill_eligible=*/false);
}

void MipsExceptionDelivery::RaiseAddressError(uint32_t va, MipsAccess acc) {
    /* QEMU target/mips mips_cpu_do_unaligned_access (op_helper.c:303): BadVAddr
       only (no Context / EntryHi), AdES for a store else AdEL. General vector. */
    cpu_state_->cp0_badvaddr = va;
    const uint32_t cause = (acc == MipsAccess::kWrite) ? MipsExcCode::kAdES
                                                       : MipsExcCode::kAdEL;
    EnterException(cause, false);
    RaiseException(kGuestExceptionCode, 0, 0, nullptr);
}

void MipsExceptionDelivery::RaiseOverflowException() {
    EnterException(MipsExcCode::kOv, false);
    RaiseException(kGuestExceptionCode, 0, 0, nullptr);
}

void MipsExceptionDelivery::LeaveBlock() {
    RaiseException(kGuestExceptionCode, 0, 0, nullptr);
    emu_.Get<Fatal>().Die("MipsExceptionDelivery::LeaveBlock: the guest-exception unwind returned");
}

bool MipsExceptionDelivery::InterruptReady() const {
    const MipsCpuState& s = *cpu_state_;
    if (!model_->InterruptsEnabled(s)) return false;
    /* pending = (Cause.IP & Status.IM) over bits 8..15 (QEMU target/mips
       internal.h). Both cores place IntMask and the Int/Sw pending bits at 15:8
       (TMPR39xx-um §6.2.3). */
    return (s.cp0_cause & s.cp0_status & 0x0000FF00u) != 0u;
}

void MipsExceptionDelivery::DeliverInterrupt() {
    EnterException(MipsExcCode::kInt, false);
}

void __fastcall MipsExceptionDelivery::SyscallHelper(MipsExceptionDelivery* ex) {
    /* QEMU target/mips SYSCALL -> Sys, cause 8, general vector
       (tlb_helper.c do_interrupt:1234). */
    ex->EnterException(MipsExcCode::kSys, false);
    RaiseException(kGuestExceptionCode, 0, 0, nullptr);
}

void __fastcall MipsExceptionDelivery::BreakHelper(MipsExceptionDelivery* ex) {
    /* QEMU target/mips BREAK -> Bp, cause 9, general vector
       (tlb_helper.c do_interrupt:1238). */
    ex->EnterException(MipsExcCode::kBp, false);
    RaiseException(kGuestExceptionCode, 0, 0, nullptr);
}

void __cdecl MipsExceptionDelivery::ArithOverflowHelper(MipsExceptionDelivery* ex,
                                                        uint32_t /* pc */) {
    ex->RaiseOverflowException();
}
