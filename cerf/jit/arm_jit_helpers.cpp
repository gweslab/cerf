#include "arm_jit.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <cstddef>
#include <cstring>
#include <intrin.h>

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../core/rate_probe.h"
#include "../cpu/arm_processor_config.h"
#include "../cpu/emulated_memory.h"
#include "../peripherals/peripheral_dispatcher.h"
#include "arm_cpu.h"
#include "arm_cpu_exceptions.h"
#include "arm_cpu_ops.h"
#include "arm_jit_runtime.h"
#include "arm_mmu.h"
#include "arm_mmu_state.h"
#include "place_fns.h"
#include "x86_emit.h"

void* __cdecl ArmJit::FindBlockNativeStartHelper(ArmJit*  jit,
                                                 uint32_t guest_pc) {
    return jit->FindBlockNativeStart(guest_pc);
}

uint8_t* __fastcall ArmJit::TranslateReadHelper(uint32_t va, ArmJit* jit) {
#if CERF_DEV_MODE
    const uint64_t t0 = __rdtsc();
    uint8_t* result = jit->mmu_->TranslateRead(jit->CpuState(), va);
    auto& probe = jit->emu_.Get<RateProbe>();
    probe.AddTsc(RateProbe::TimeCounter::MmuXlate, __rdtsc() - t0);
    probe.Inc(RateProbe::Counter::MmuXlateCalls);
    return result;
#else
    return jit->mmu_->TranslateRead(jit->CpuState(), va);
#endif
}

uint8_t* __fastcall ArmJit::TranslateWriteHelper(uint32_t va, ArmJit* jit) {
#if CERF_DEV_MODE
    const uint64_t t0 = __rdtsc();
    uint8_t* result = jit->mmu_->TranslateWrite(jit->CpuState(), va);
    auto& probe = jit->emu_.Get<RateProbe>();
    probe.AddTsc(RateProbe::TimeCounter::MmuXlate, __rdtsc() - t0);
    probe.Inc(RateProbe::Counter::MmuXlateCalls);
    return result;
#else
    return jit->mmu_->TranslateWrite(jit->CpuState(), va);
#endif
}

uint8_t* __fastcall ArmJit::TranslateReadWriteHelper(uint32_t va, ArmJit* jit) {
#if CERF_DEV_MODE
    const uint64_t t0 = __rdtsc();
    uint8_t* result = jit->mmu_->TranslateReadWrite(jit->CpuState(), va);
    auto& probe = jit->emu_.Get<RateProbe>();
    probe.AddTsc(RateProbe::TimeCounter::MmuXlate, __rdtsc() - t0);
    probe.Inc(RateProbe::Counter::MmuXlateCalls);
    return result;
#else
    return jit->mmu_->TranslateReadWrite(jit->CpuState(), va);
#endif
}

uint8_t* __fastcall ArmJit::MapGuestPhysicalToHostRamHelper(uint32_t paddr, ArmJit* jit) {
    /* TTBR-write reachability check. Page tables must live in writable
       host RAM — TryTranslateWrite returns nullptr for both unmapped
       PAs and read-only (flash/ROM) regions, matching the reference's
       BoardMapGuestPhysicalToHostRAM semantics. */
    return jit->memory_->TryTranslateWrite(paddr);
}

uint8_t* __fastcall ArmJit::MapGuestPhysicalToHostHelper(uint32_t paddr, ArmJit* jit) {
    uint8_t* host = jit->memory_->TryTranslate(paddr);
    if (host) {
        return host;
    }
    *jit->mmu_->IoPendingAddressPtr() = paddr;
    return nullptr;
}

void __cdecl ArmJit::RaiseAlignmentExceptionHelper(ArmJit* jit, uint32_t va) {
    /* Sets FAR + FSR.status = kAlignment; the emitted
       RaiseAbortDataExceptionHelper that follows signals the abort. */
    jit->mmu_->RaiseAlignmentFault(va);
}

void __fastcall ArmJit::BlockDataTransferIOLoadHelper(uint32_t register_list, ArmJit* jit) {
    if (jit->mmu_->io_pending_address() != *jit->StartIoAddressPtr()) {
        LOG(Caution,
            "ArmJit::BlockDataTransferIOLoadHelper: io_pending_address (0x%08X)"
            " != start_io_address (0x%08X) on entry\n",
            jit->mmu_->io_pending_address(), *jit->StartIoAddressPtr());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    int8_t io_index_hint = 0;
    for (uint32_t reg_num = 0; reg_num <= 14u; ++reg_num) {
        if (register_list & (1u << reg_num)) {
            jit->CpuState()->gprs[reg_num] =
                PeripheralDispatcher::JitIoReadWord(&io_index_hint, jit->Peripheral());
            *jit->mmu_->IoPendingAddressPtr() += 4;
        }
    }
}

void __fastcall ArmJit::BlockDataTransferIOStoreHelper(uint32_t register_list, ArmJit* jit) {
    if (jit->mmu_->io_pending_address() != *jit->StartIoAddressPtr()) {
        LOG(Caution,
            "ArmJit::BlockDataTransferIOStoreHelper: io_pending_address (0x%08X)"
            " != start_io_address (0x%08X) on entry\n",
            jit->mmu_->io_pending_address(), *jit->StartIoAddressPtr());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    int8_t io_index_hint = 0;
    for (uint32_t reg_num = 0; reg_num <= 14u; ++reg_num) {
        if (register_list & (1u << reg_num)) {
            PeripheralDispatcher::JitIoWriteWord(&io_index_hint, jit->Peripheral(),
                                                 jit->CpuState()->gprs[reg_num]);
            *jit->mmu_->IoPendingAddressPtr() += 4;
        }
    }
}

void __fastcall ArmJit::BlockDataTransferIOHelperSlow(uint32_t register_list_and_flags,
                                                       ArmJit*  jit,
                                                       uint32_t instruction_address) {
    const uint32_t register_list = register_list_and_flags & 0xFFFFu;
    const bool fSBit      = (register_list_and_flags & kLdmStmS)     != 0;
    const bool fSpans     = (register_list_and_flags & kLdmStmSpans) != 0;
    const bool fLoad      = (register_list_and_flags & kLdmStmLoad)  != 0;
    const bool fWriteBack = (register_list_and_flags & kLdmStmW)     != 0;
    bool fFirst = true;
    int8_t io_index_hint = 0;

    ArmCpu*      cpu   = jit->Cpu();
    ArmCpuState* state = cpu->State();

    /* Reset the IO walk to the start of the range (PBDT emit set
       both StartIOAddress and the live io_pending_address before
       this CALL; the slow helper resets per spec since the
       fast-path helpers above this branch already advanced things). */
    *jit->mmu_->IoPendingAddressPtr() = *jit->StartIoAddressPtr();

    for (uint32_t reg_num = 0; reg_num <= 15u; ++reg_num) {
        if ((register_list & (1u << reg_num)) == 0) {
            continue;
        }

        if (fLoad) {
            if (fSBit && (register_list & 0x8000u) == 0 &&
                reg_num >= 8u && reg_num < 15u) {
                /* LDM with S-bit and R15 not in list: R8..R14 load
                   into the user-bank view of the register. */
                *cpu->GetUserModeRegisterAddress(static_cast<int>(reg_num)) =
                    PeripheralDispatcher::JitIoReadWord(&io_index_hint, jit->Peripheral());
            } else if (reg_num == 15u) {
                cpu->UpdateCpsrWithFlags(state->spsr);
                uint32_t value = PeripheralDispatcher::JitIoReadWord(&io_index_hint, jit->Peripheral());
                if (state->cpsr.bits.thumb_mode) {
                    value &= ~1u;
                } else {
                    value &= ~3u;
                }
                state->gprs[ArmGpr::kR15] = value;
            } else {
                state->gprs[reg_num] =
                    PeripheralDispatcher::JitIoReadWord(&io_index_hint, jit->Peripheral());
            }
        } else {
            /* STM */
            if (fSBit && reg_num >= 8u && reg_num < 15u) {
                PeripheralDispatcher::JitIoWriteWord(&io_index_hint, jit->Peripheral(),
                    *cpu->GetUserModeRegisterAddress(static_cast<int>(reg_num)));
            } else if (reg_num == 15u) {
                PeripheralDispatcher::JitIoWriteWord(&io_index_hint, jit->Peripheral(),
                    instruction_address + jit->ProcessorConfig()->PcStoreOffset());
            } else {
                PeripheralDispatcher::JitIoWriteWord(&io_index_hint, jit->Peripheral(),
                    state->gprs[reg_num]);
            }
        }

        *jit->mmu_->IoPendingAddressPtr() += 4;

        if (fFirst) {
            fFirst = false;
            if (fWriteBack) {
                /* Writeback to the base register encoded in the high
                   8 bits of register_list_and_flags. */
                state->gprs[register_list_and_flags >> 24] =
                    *jit->EndEffectiveAddressPtr();
            }
        }

        if (fSpans) {
            if (jit->mmu_->io_pending_address() == *jit->StartPageIoAddressEndPtr()) {
                *jit->mmu_->IoPendingAddressPtr() = *jit->NextPageIoAddressPtr();
            }
        }
    }
}

void ArmJit::FlushTranslationCache(uint32_t va, uint32_t length) {
    const uint32_t cache_line_size = processor_config_->CacheLineSize();

    if (length != 0xFFFFFFFFu) {
        va     = va & ~(cache_line_size - 1u);
        length = (length + (cache_line_size - 1u) +
                  (va & (cache_line_size - 1u)))
                 & ~(cache_line_size - 1u);
    }

    if (length == 0xFFFFFFFFu ||
        blocks_arm_  .ContainsRange(va, va + length) ||
        blocks_thumb_.ContainsRange(va, va + length)) {
        FlushNativeAddrCache();
        /* Shadow-stack entries cache native destinations for guest
           return addresses — after a TC flush those native pointers
           are stale (point into freed arena memory). Drop the whole
           stack with one count reset; the next BL emit refills. */
        shadow_stack_count_ = 0;
        blocks_arm_  .FlushAll();
        blocks_thumb_.FlushAll();
        arena_.Flush();
        /* All translations gone — reset SMC tracking so the next I-cache
           invalidate no-ops until code is written again. */
        std::memset(mmu_->State()->code_xlat_bitmap, 0,
                    mmu_->State()->code_word_bitmap_bytes);
        std::memset(mmu_->State()->code_page_dirty, 0,
                    mmu_->State()->code_page_dirty_bytes);
    }
}

void __cdecl ArmJit::FlushTranslationCacheStaticHelper(ArmJit*  jit,
                                                       uint32_t va,
                                                       uint32_t length) {
    jit->FlushTranslationCache(va, length);
}
