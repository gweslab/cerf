#include "mips_jit.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../host/guest_deep_sleep.h"
#include "../../host/guest_power_notifier.h"
#include "../../socs/guest_cpu_reset.h"
#include "../guest_cycle_clock.h"
#include "../host_request_channel.h"
#include "mips_block_compiler.h"
#include "mips_cp0_ops.h"
#include "mips_cpu.h"
#include "mips_exception_delivery.h"
#include "mips_exception_model.h"
#include "mips_interrupt_channel.h"
#include "mips_memory_access.h"
#include "mips_mmu.h"
#include "mips_translation_cache.h"

REGISTER_SERVICE_AS(MipsJit, GuestEngine);

namespace {

int MipsDispatchFaultFilter(EXCEPTION_POINTERS* ep, uint32_t guest_pc,
                            bool* host_fault) {
    const DWORD code = ep->ExceptionRecord->ExceptionCode;
    if (code == MipsExceptionDelivery::kGuestExceptionCode) {
        *host_fault = false;
        return EXCEPTION_EXECUTE_HANDLER;
    }
    *host_fault = true;
    LOG(Caution,
        "MipsJit: host exception 0x%08lX at host addr %p while running guest PC 0x%08X\n",
        code, ep->ExceptionRecord->ExceptionAddress, guest_pc);
    return EXCEPTION_EXECUTE_HANDLER;
}

}

void MipsJit::OnReady() {
    cpu_        = &emu_.Get<MipsCpu>();
    cpu_state_  = cpu_->State();
    mmu_        = &emu_.Get<MipsMmu>();
    memory_     = &emu_.Get<EmulatedMemory>();
    cache_      = &emu_.Get<MipsTranslationCache>();
    compiler_   = &emu_.Get<MipsBlockCompiler>();
    channel_    = &emu_.Get<MipsInterruptChannel>();
    mem_access_ = &emu_.Get<MipsMemoryAccess>();
    cp0_ops_    = &emu_.Get<MipsCp0Ops>();
    exceptions_ = &emu_.Get<MipsExceptionDelivery>();
    exc_model_  = &emu_.Get<MipsExceptionModel>();
    clock_      = &emu_.Get<GuestCycleClock>();
    host_requests_ = &emu_.Get<HostRequestChannel>();

    LOG(Jit, "MipsJit::OnReady: entry VA=0x%08X\n", cpu_state_->pc);
}

bool MipsJit::GuestIrqMasked() const {
    return !exc_model_->InterruptsEnabled(*cpu_state_);
}

__declspec(naked) void __cdecl MipsJit::Dispatch(void* /* native_pc */,
                                                 MipsCpuState* /* state */) {
    __asm {
        push ebp
        push ebx
        push esi
        push edi
        mov  ecx, [esp + 20]
        mov  esi, [esp + 24]
        call ecx
        pop  edi
        pop  esi
        pop  ebx
        pop  ebp
        ret
    }
}

void MipsJit::PrintFatalDump() {
    const auto& g = cpu_state_->gpr;
    LOG(Caution, "      guest PC=0x%08X  hi=0x%016llX  lo=0x%016llX\n",
        cpu_state_->pc,
        static_cast<unsigned long long>(cpu_state_->hi),
        static_cast<unsigned long long>(cpu_state_->lo));
    for (uint32_t i = 0; i < kMipsNumGpr; i += 4)
        LOG(Caution, "      r%-2u=0x%016llX  r%-2u=0x%016llX  "
                     "r%-2u=0x%016llX  r%-2u=0x%016llX\n",
            i,     static_cast<unsigned long long>(g[i]),
            i + 1, static_cast<unsigned long long>(g[i + 1]),
            i + 2, static_cast<unsigned long long>(g[i + 2]),
            i + 3, static_cast<unsigned long long>(g[i + 3]));
}

bool MipsJit::ResetPending() const { return channel_->ResetRequested(); }

void MipsJit::SetHostChainExit(bool requested) { channel_->SetHostExit(requested); }

void MipsJit::Run() {
    if (cpu_state_->idle_wait != MipsIdle::kNone && !channel_->ResumeIdle()) return;

    if (channel_->DispatchRequests() != 0u) {
        const uint32_t req = channel_->TakeDispatchRequests();
        if (req & MipsInterruptChannel::kDispatchHostClock) host_requests_->ServiceRequests();
        if (req & MipsInterruptChannel::kDispatchReset) {
            DeliverReset();
            return;
        }
    }

    mem_access_->DeliverDueClockEvents();

    const uint32_t device_mask = channel_->DeviceIpMask();
    cpu_state_->cp0_cause = (cpu_state_->cp0_cause & ~device_mask) |
                            (channel_->Level() & device_mask);

    if (cpu_state_->branch_state == MipsBranch::kNone &&
        exceptions_->InterruptReady()) {
        exceptions_->DeliverInterrupt();
    }

    const uint32_t pc     = cpu_state_->pc;
    void*          native = compiler_->FindBlockNativeStart(pc);
    if (!native) {
        native = compiler_->Compile(pc);
        if (!native) return;
    }

    bool host_fault = false;
    __try {
        Dispatch(native, cpu_state_);
    } __except (MipsDispatchFaultFilter(GetExceptionInformation(), pc, &host_fault)) {
        if (host_fault) {
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }
}

void MipsJit::DeliverReset() {
    emu_.Get<GuestCpuReset>().OnResetDelivered();
    cpu_->ResetState();
    cp0_ops_->OnCpuReset();
    cache_->ContextSwitchFlush();
}

void MipsJit::SetExternalInterruptLevel(uint32_t ip_mask) {
    channel_->SetExternalInterruptLevel(ip_mask);
}

void MipsJit::SetResetPending(bool is_resume) {
    emu_.Get<GuestCpuReset>().SetPendingResume(is_resume);
    channel_->RequestDispatch(MipsInterruptChannel::kDispatchReset);
    if (is_resume) return;
    emu_.Get<GuestDeepSleep>().ClearWakeCause();
    emu_.Get<GuestPowerNotifier>().NotifyReboot();
}

void MipsJit::EnterDeepSleep() { cpu_state_->deep_sleep = 1; }

void MipsJit::ExitDeepSleep() {
    cpu_state_->deep_sleep = 0;
    channel_->SignalIdleWake();
}

void MipsJit::EnterIdleWait() { channel_->StopCpuAfterAccess(); }

void MipsJit::SaveCpuState(StateWriter& w) {
    cpu_state_->reset_pending = channel_->ResetRequested() ? 1u : 0u;
    cp0_ops_->SaveCount();
    cpu_->SaveState(w);
}
void MipsJit::RestoreCpuState(StateReader& r) {
    cpu_->RestoreState(r);
    channel_->SetResetRequest(cpu_state_->reset_pending != 0u);
    clock_->OnCyclesRestored();
    channel_->OnCpuStateRestored();
    cp0_ops_->OnCpuStateRestored();
    cpu_->NotifyRestored();
}
void MipsJit::SaveMmuState(StateWriter& w)    { mmu_->SaveState(w); }
void MipsJit::RestoreMmuState(StateReader& r) { mmu_->RestoreState(r); }

void MipsJit::FlushTranslationCache() { cache_->Flush(); }

void MipsJit::SetInjectionBand(uint32_t va, uint32_t pa, uint32_t size) {
    mmu_->SetInjectionBand(va, pa, size);
    cache_->SetInjectionBandHost(pa, size);
}

void MipsJit::SetDmaRegion(uint32_t pa, uint32_t size) {
    cache_->AddDmaRegion(pa, size);
}

std::optional<uint8_t*> MipsJit::PeekGuestVa(uint32_t va) {
    uint32_t pa = 0;
    if (mmu_->Translate(cpu_state_, va, MipsAccess::kRead, &pa) !=
        MipsTlbResult::kMatch) {
        return std::nullopt;
    }
    uint8_t* host = memory_->TryTranslate(pa);
    if (!host) return std::nullopt;
    return host;
}

uint8_t* MipsJit::ResolveGuestVaToHost(uint32_t va) {
    uint32_t pa = 0;
    if (mmu_->Translate(cpu_state_, va, MipsAccess::kRead, &pa) !=
        MipsTlbResult::kMatch) {
        return nullptr;
    }
    uint8_t* w = memory_->TryTranslateWrite(pa);
    return w ? w : memory_->TryTranslate(pa);
}

bool MipsJit::ResolveGuestVaToPa(uint32_t va, uint32_t* pa) {
    return mmu_->Translate(cpu_state_, va, MipsAccess::kRead, pa) ==
           MipsTlbResult::kMatch;
}
