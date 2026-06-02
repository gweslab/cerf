#include "arm_jit.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>
#include <cstring>
#include <intrin.h>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../cpu/arm_processor_config.h"
#include "../cpu/emulated_memory.h"
#include "../peripherals/peripheral_dispatcher.h"
#include "arm_cpu_exceptions.h"
#include "arm_cpu_ops.h"
#include "arm_jit_runtime.h"
#include "arm_mmu.h"
#include "arm_mmu_state.h"
#include "place_fns.h"
#include "x86_emit.h"

void ArmJit::InitializeRaiseAbortDataHelper() {
    raise_abort_data_helper_ = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!raise_abort_data_helper_) {
        LOG(Caution, "ArmJit: VirtualAlloc(RaiseAbortDataHelper) failed gle=%lu\n",
            GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    using namespace x86;
    uint8_t* p = raise_abort_data_helper_;

    EmitPushReg(p, kEcx);
    EmitPushReg(p, kEsi);
    EmitPush32 (p, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(this)));
    EmitCall   (p, reinterpret_cast<void*>(&ArmCpuRaiseAbortDataException));
    EmitAddRegImm32(p, kEsp, 12);
    EmitTestRegReg (p, kEax, kEax);
    uint8_t* not_in_cache = EmitJzLabel(p);
    EmitJmpReg(p, kEax);
    FixupLabel(not_in_cache, p);
    EmitRetn(p, 0);

    FlushInstructionCache(GetCurrentProcess(), raise_abort_data_helper_,
                          static_cast<SIZE_T>(p - raise_abort_data_helper_));
}
