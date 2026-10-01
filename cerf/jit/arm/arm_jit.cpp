#include "arm_jit.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <atomic>
#include <cstdio>

#include "../../boot/boot_mode.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../host/guest_deep_sleep.h"
#include "../../host/guest_power_notifier.h"
#include "../guest_cycle_clock.h"
#include "../host_request_channel.h"
#include "../jit_code_arena.h"
#include "arm_block_compiler.h"
#include "arm_cpu.h"
#include "arm_interrupt_channel.h"
#include "arm_injection_band.h"
#include "arm_mmu.h"
#include "arm_mmu_probe.h"
#include "arm_mmu_state.h"
#include "arm_page_walker.h"
#include "arm_translation_cache.h"

REGISTER_SERVICE_AS(ArmJit, GuestEngine);

namespace {

constexpr uintptr_t kFaultWindowBytes = 16;

void LogEmittedBytesAroundFault(const JitCodeArena& arena, uintptr_t fault) {
    const uintptr_t base = reinterpret_cast<uintptr_t>(arena.RegionBase());
    const uintptr_t size = static_cast<uintptr_t>(arena.MaxSize());
    if (size == 0 || fault < base || fault >= base + size) {
        return;
    }

    const uintptr_t lo = (fault - base >= kFaultWindowBytes)
                             ? fault - kFaultWindowBytes : base;
    const uintptr_t hi = ((base + size) - fault > kFaultWindowBytes)
                             ? fault + kFaultWindowBytes : base + size;

    char line[128];
    int  n = 0;
    for (uintptr_t p = lo; p < hi; ++p) {
        const int written =
            _snprintf_s(line + n, sizeof(line) - static_cast<size_t>(n),
                        _TRUNCATE, "%02X ",
                        *reinterpret_cast<const uint8_t*>(p));
        if (written <= 0) break;
        n += written;
    }
    LOG(Caution, "ArmJit:   emitted 0x%08lX..0x%08lX (fault at +0x%lX): %s\n",
        static_cast<unsigned long>(lo), static_cast<unsigned long>(hi),
        static_cast<unsigned long>(fault - lo), line);
}

int ArmDispatchFaultFilter(EXCEPTION_POINTERS*  ep,
                           uint32_t             guest_pc,
                           const ArmCpuState*   state,
                           const JitCodeArena&  arena) {
    const EXCEPTION_RECORD* rec = ep->ExceptionRecord;
    const CONTEXT*          ctx = ep->ContextRecord;

    LOG(Caution, "ArmJit: host exception 0x%08lX at host address %p while "
            "running guest PC 0x%08X (CPSR=0x%08X)\n",
        rec->ExceptionCode, rec->ExceptionAddress, guest_pc,
        ArmPackCpsr(*state));

    char symbol[512];
    if (Log::SymbolizeAddress(rec->ExceptionAddress, symbol, sizeof(symbol))) {
        LOG(Caution, "ArmJit:   host symbol %s\n", symbol);
    }

    LOG(Caution, "ArmJit:   eax=%08lX ecx=%08lX edx=%08lX ebx=%08lX\n",
        ctx->Eax, ctx->Ecx, ctx->Edx, ctx->Ebx);
    LOG(Caution, "ArmJit:   esp=%08lX ebp=%08lX esi=%08lX edi=%08lX\n",
        ctx->Esp, ctx->Ebp, ctx->Esi, ctx->Edi);
    LOG(Caution, "ArmJit:   eip=%08lX eflags=%08lX\n", ctx->Eip, ctx->EFlags);

    LogEmittedBytesAroundFault(
        arena, reinterpret_cast<uintptr_t>(rec->ExceptionAddress));

    for (uint32_t i = 0; i < 16u; i += 4u) {
        LOG(Caution, "ArmJit:   r%u=0x%08X r%u=0x%08X r%u=0x%08X r%u=0x%08X\n",
            i, state->gprs[i], i + 1u, state->gprs[i + 1u],
            i + 2u, state->gprs[i + 2u], i + 3u, state->gprs[i + 3u]);
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

}

void ArmJit::OnReady() {
    cpu_       = &emu_.Get<ArmCpu>();
    cpu_state_ = cpu_->State();
    mmu_       = &emu_.Get<ArmMmu>();
    probe_     = &emu_.Get<ArmMmuProbe>();
    walker_    = &emu_.Get<ArmPageWalker>();
    cache_     = &emu_.Get<ArmTranslationCache>();
    compiler_  = &emu_.Get<ArmBlockCompiler>();
    channel_   = &emu_.Get<ArmInterruptChannel>();
    clock_     = &emu_.Get<GuestCycleClock>();
    host_requests_ = &emu_.Get<HostRequestChannel>();

    BootMode&      boot       = emu_.Get<BootMode>();
    const uint32_t cold_entry = boot.ColdEntryPa();
    const uint32_t cold_stack = boot.ColdStackPa();
    cpu_->SetInitialStackPointer(cold_stack);
    cpu_->RaiseResetException(cold_entry, boot.ColdEntryThumb());

    LOG(Jit, "ArmJit::OnReady: cold entry PA 0x%08X (%s), cold stack PA 0x%08X\n",
        cold_entry, boot.ColdEntryThumb() ? "Thumb" : "ARM", cold_stack);
}

__declspec(naked) void __cdecl ArmJit::Dispatch(void*, ArmCpuState*, ArmMmuState*) {
    __asm {
        push ebp
        push ebx
        push esi
        push edi
        mov  ecx, [esp + 20]
        mov  esi, [esp + 24]
        mov  ebx, [esp + 28]
        call ecx
        pop  edi
        pop  esi
        pop  ebx
        pop  ebp
        ret
    }
}

void ArmJit::Run() {
    mmu_->SynchronizeSctlr();

    if (cpu_state_->reset_pending != 0u) {
        std::atomic_ref<uint32_t>(cpu_state_->chain_exit_request)
            .fetch_and(~kChainExitReset, std::memory_order_acq_rel);
        emu_.Get<GuestCpuReset>().OnResetDelivered();
        cpu_->RaiseResetException();
        cache_->Flush();
        return;
    }

    if (channel_->TakeHostRequest()) host_requests_->ServiceRequests();
    clock_->OnDispatch();

    /* QEMU accel/tcg/cpu-exec.c cpu_handle_interrupt: "Clear the interrupt
       flag now since we're processing cpu->interrupt_request and
       cpu->exit_request." */
    {
        std::atomic_ref<uint32_t> word(cpu_state_->chain_exit_request);
        if ((word.load(std::memory_order_acquire) & kChainExitIrq) != 0u) {
            word.fetch_and(~kChainExitIrq, std::memory_order_acq_rel);
        }
    }
    const ArmInterruptChannel::IrqGate gate = channel_->EvaluateGate();
    cpu_state_->irq_interrupt_pending = gate.level;
    if (gate.raise) {
        cpu_->RaiseIrqException(cpu_state_->gprs[ArmGpr::kR15]);
    }

    const uint32_t pc = cpu_state_->gprs[ArmGpr::kR15];
    const uint32_t folded = ArmFcseFold(pc, mmu_->State()->fcse_fold_id);
    void*          native =
        cache_->Lookup(cpu_state_->cpsr.bits.thumb_mode != 0u, folded);
    if (native == nullptr) {
        compiler_->SetPredecessor(predecessor_va_);
        native = compiler_->Compile(pc);
        if (native == nullptr) {
            return;
        }
    }
    predecessor_va_ = folded;

    __try {
        Dispatch(native, cpu_state_, mmu_->State());
    } __except (ArmDispatchFaultFilter(GetExceptionInformation(), pc,
                                       cpu_state_, cache_->Arena())) {
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
}

void ArmJit::SetHostChainExit(bool requested) {
    std::atomic_ref<uint32_t> word(cpu_state_->chain_exit_request);
    if (requested) {
        word.fetch_or(kChainExitHost, std::memory_order_acq_rel);
    } else {
        word.fetch_and(~kChainExitHost, std::memory_order_acq_rel);
    }
}

void ArmJit::SetInterruptPending()   { channel_->SetInterruptPending(); }
void ArmJit::ClearInterruptPending() { channel_->ClearInterruptPending(); }
void ArmJit::SetIdleWake(bool level) { channel_->SetIdleWake(level); }

void ArmJit::EnterDeepSleep() {
    /* SA-1110 §9.5.3: PMCR.SF halts the CPU until a wake reset. */
    cpu_state_->deep_sleep = 1;
}

void ArmJit::ExitDeepSleep() {
    cpu_state_->deep_sleep = 0;
    channel_->Wake();
}

void ArmJit::EnterIdleWait() { channel_->WaitForInterrupt(); }

void ArmJit::SetResetPending(bool is_resume) {
    emu_.Get<GuestCpuReset>().SetPendingResume(is_resume);
    std::atomic_ref<uint32_t>(cpu_state_->chain_exit_request)
        .fetch_or(kChainExitReset, std::memory_order_acq_rel);
    cpu_state_->reset_pending = 1u;
    channel_->Wake();
    if (is_resume) return;
    emu_.Get<GuestDeepSleep>().ClearWakeCause();
    emu_.Get<GuestPowerNotifier>().NotifyReboot();
}

void ArmJit::PrintFatalDump() {
    const auto& r = cpu_state_->gprs;
    LOG(Caution, "      guest PC=0x%08X  CPSR=0x%08X\n",
        r[ArmGpr::kR15], ArmPackCpsr(*cpu_state_));
    LOG(Caution, "      R0=0x%08X  R1=0x%08X  R2=0x%08X  R3=0x%08X "
                 "R4=0x%08X  R5=0x%08X  R6=0x%08X  R7=0x%08X\n",
        r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
    LOG(Caution, "      R8=0x%08X  R9=0x%08X  R10=0x%08X R11=0x%08X "
                 "R12=0x%08X SP=0x%08X  LR=0x%08X\n",
        r[8], r[9], r[10], r[11], r[12], r[13], r[14]);
}

void ArmJit::SaveCpuState(StateWriter& w)    { cpu_->SaveState(w); }
void ArmJit::RestoreCpuState(StateReader& r) {
    cpu_->RestoreState(r);
    clock_->OnCyclesRestored();
}
void ArmJit::SaveMmuState(StateWriter& w)    { mmu_->SaveState(w); }
void ArmJit::RestoreMmuState(StateReader& r) { mmu_->RestoreState(r); }

void ArmJit::FlushTranslationCache() { cache_->Flush(); }

void ArmJit::SetInjectionBand(uint32_t va, uint32_t pa, uint32_t size) {
    emu_.Get<ArmInjectionBand>().Set(va, pa, size);
}

void ArmJit::SetDmaRegion(uint32_t /*pa*/, uint32_t /*size*/) {}

std::optional<uint8_t*> ArmJit::PeekGuestVa(uint32_t va) {
    return probe_->PeekDataTlb(va);
}

uint8_t* ArmJit::ResolveGuestVaToHost(uint32_t va) {
    return probe_->PeekVaToHost(va);
}

bool ArmJit::ResolveGuestVaToPa(uint32_t va, uint32_t* pa) {
    return probe_->PeekVaToPa(va, pa);
}
