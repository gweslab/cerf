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

void ArmJit::InitializeInterruptCheck() {
    interrupt_check_ = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!interrupt_check_) {
        LOG(Caution, "ArmJit: VirtualAlloc(InterruptCheck) failed gle=%lu\n",
            GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    using namespace x86;
    uint8_t* p = interrupt_check_;

    Emit8(p, 0xC3);

    EmitPopReg(p, kEax);
    EmitPushReg(p, kEcx);
    EmitPushReg(p, kEsi);
    EmitPush32 (p, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(this)));
    EmitCall   (p, reinterpret_cast<void*>(&InterruptDeliveryHelper));
    EmitAddRegImm32(p, kEsp, 12);
    EmitTestRegReg (p, kEax, kEax);
    /* JZ short — skip exactly the JMP EAX (2 bytes). */
    Emit8(p, 0x74);
    Emit8(p, 0x02);
    EmitJmpReg(p, kEax);
    /* RETN reached when EAX==0. */
    Emit8(p, 0xC3);

    /* Make the freshly-emitted bytes visible to the CPU's
       instruction-fetch pipeline. */
    FlushInstructionCache(GetCurrentProcess(), interrupt_check_,
                          static_cast<SIZE_T>(p - interrupt_check_));
}
