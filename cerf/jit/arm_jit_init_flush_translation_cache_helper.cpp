#include "arm_jit.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "x86_emit.h"

void ArmJit::InitializeFlushTranslationCacheHelper() {
    flush_translation_cache_helper_ = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
    if (!flush_translation_cache_helper_) {
        LOG(Caution, "ArmJit: VirtualAlloc(FlushTranslationCacheHelper) failed gle=%lu\n",
            GetLastError());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    using namespace x86;
    uint8_t* p = flush_translation_cache_helper_;

    EmitPushReg(p, kEdx);
    EmitPushReg(p, kEcx);
    EmitPush32 (p, static_cast<uint32_t>(reinterpret_cast<uintptr_t>(this)));
    EmitCall   (p, reinterpret_cast<void*>(&ArmJit::FlushTranslationCacheStaticHelper));
    EmitAddRegImm32(p, kEsp, 12);
    EmitRetn(p, 0);

    FlushInstructionCache(GetCurrentProcess(), flush_translation_cache_helper_,
                          static_cast<SIZE_T>(p - flush_translation_cache_helper_));
}
