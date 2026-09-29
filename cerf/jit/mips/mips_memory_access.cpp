#include "mips_memory_access.h"

#include <cstring>

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../cycle_deadline.h"
#include "../guest_cycle_clock.h"
#include "mips_cpu.h"
#include "mips_cpu_state.h"
#include "mips_exception_delivery.h"
#include "mips_mmu.h"
#include "mips_translation_cache.h"

REGISTER_SERVICE(MipsMemoryAccess);

void MipsMemoryAccess::OnReady() {
    cpu_state_  = emu_.Get<MipsCpu>().State();
    mmu_        = &emu_.Get<MipsMmu>();
    memory_     = &emu_.Get<EmulatedMemory>();
    peripheral_ = &emu_.Get<PeripheralDispatcher>();
    exceptions_ = &emu_.Get<MipsExceptionDelivery>();
    cache_      = &emu_.Get<MipsTranslationCache>();
    clock_      = &emu_.Get<GuestCycleClock>();
}

void MipsMemoryAccess::DeliverDueClockEvents() {
    if (CycleDeadlineReached(cpu_state_->guest_cycle_counter,
                             cpu_state_->guest_cycle_deadline)) {
        clock_->OnDispatch();
    }
}

uint32_t MipsMemoryAccess::MmioRead(uint32_t va, uint32_t pa, uint32_t width, const char* who) {
    if (peripheral_->IsPeripheralAddress(pa)) {
        DeliverDueClockEvents();
        switch (width) {
            case 1:  return peripheral_->ReadByte(pa);
            case 2:  return peripheral_->ReadHalf(pa);
            default: return peripheral_->ReadWord(pa);
        }
    }
    LOG(Caution, "%s: unmapped MMIO read va=0x%08X pa=0x%08X pc=0x%08X (no peripheral registered)\n",
        who, va, pa, cpu_state_->pc);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

void MipsMemoryAccess::LeaveBlockIfCpuStopped() {
    if (cpu_state_->idle_wait != MipsIdle::kNone) exceptions_->LeaveBlock();
}

void MipsMemoryAccess::MmioWrite(uint32_t va, uint32_t pa, uint32_t value, uint32_t width, const char* who) {
    if (peripheral_->IsPeripheralAddress(pa)) {
        DeliverDueClockEvents();
        switch (width) {
            case 1:  peripheral_->WriteByte(pa, static_cast<uint8_t>(value));  break;
            case 2:  peripheral_->WriteHalf(pa, static_cast<uint16_t>(value)); break;
            default: peripheral_->WriteWord(pa, value);                        break;
        }
        LeaveBlockIfCpuStopped();
        return;
    }
    LOG(Caution, "%s: unmapped MMIO write va=0x%08X pa=0x%08X val=0x%08X pc=0x%08X (no peripheral "
        "registered)\n", who, va, pa, value, cpu_state_->pc);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

void __fastcall MipsMemoryAccess::StoreWordHelper(uint32_t va, uint32_t value, MipsMemoryAccess* mem) {
    if (va & 3u) {                        /* SW requires a 4-byte-aligned EA */
        mem->exceptions_->RaiseAddressError(va, MipsAccess::kWrite);   /* AdES; SEH unwind */
    }
    uint32_t pa = 0;
    const MipsTlbResult r =
        mem->mmu_->Translate(mem->cpu_state_, va, MipsAccess::kWrite, &pa);
    if (r != MipsTlbResult::kMatch) {
        mem->exceptions_->RaiseTlbException(va, MipsAccess::kWrite, r);  /* TLBS/Mod; SEH unwind */
    }
    if (uint8_t* host = mem->memory_->TryTranslateWrite(pa)) {
        mem->cache_->InvalidateOnRamWrite(host, 4u);
        std::memcpy(host, &value, sizeof(value));
        return;
    }
    mem->MmioWrite(va, pa, value, 4, "MipsMemoryAccess::StoreWordHelper");
}

void __fastcall MipsMemoryAccess::StoreHalfHelper(uint32_t va, uint32_t value, MipsMemoryAccess* mem) {
    if (va & 1u) {                        /* SH requires a 2-byte-aligned EA */
        mem->exceptions_->RaiseAddressError(va, MipsAccess::kWrite);   /* AdES; SEH unwind */
    }
    uint32_t pa = 0;
    const MipsTlbResult r =
        mem->mmu_->Translate(mem->cpu_state_, va, MipsAccess::kWrite, &pa);
    if (r != MipsTlbResult::kMatch) {
        mem->exceptions_->RaiseTlbException(va, MipsAccess::kWrite, r);  /* TLBS/Mod; SEH unwind */
    }
    if (uint8_t* host = mem->memory_->TryTranslateWrite(pa)) {
        mem->cache_->InvalidateOnRamWrite(host, 2u);
        const uint16_t h = static_cast<uint16_t>(value);
        std::memcpy(host, &h, sizeof(h));
        return;
    }
    mem->MmioWrite(va, pa, value, 2, "MipsMemoryAccess::StoreHalfHelper");
}

void __fastcall MipsMemoryAccess::StoreByteHelper(uint32_t va, uint32_t value, MipsMemoryAccess* mem) {
    StoreByteXlate(mem, va, static_cast<uint8_t>(value), "MipsMemoryAccess::StoreByteHelper");
}

uint32_t __fastcall MipsMemoryAccess::LoadWordHelper(uint32_t va, MipsMemoryAccess* mem) {
    if (va & 3u) {                        /* LW requires a 4-byte-aligned EA */
        mem->exceptions_->RaiseAddressError(va, MipsAccess::kRead);    /* AdEL; SEH unwind */
    }
    uint32_t pa = 0;
    const MipsTlbResult r =
        mem->mmu_->Translate(mem->cpu_state_, va, MipsAccess::kRead, &pa);
    if (r != MipsTlbResult::kMatch) {
        mem->exceptions_->RaiseTlbException(va, MipsAccess::kRead, r);  /* TLBL; SEH unwind */
    }
    if (const uint8_t* host = mem->memory_->TryTranslate(pa)) {
        uint32_t value = 0;
        std::memcpy(&value, host, sizeof(value));
        return value;
    }
    return mem->MmioRead(va, pa, 4, "MipsMemoryAccess::LoadWordHelper");
}

uint32_t __fastcall MipsMemoryAccess::LoadByteHelper(uint32_t va, MipsMemoryAccess* mem) {
    uint32_t pa = 0;                      /* a byte EA is always aligned */
    const MipsTlbResult r =
        mem->mmu_->Translate(mem->cpu_state_, va, MipsAccess::kRead, &pa);
    if (r != MipsTlbResult::kMatch) {
        mem->exceptions_->RaiseTlbException(va, MipsAccess::kRead, r);  /* TLBL; SEH unwind */
    }
    if (const uint8_t* host = mem->memory_->TryTranslate(pa)) {
        return *host;
    }
    return mem->MmioRead(va, pa, 1, "MipsMemoryAccess::LoadByteHelper");
}

uint32_t __fastcall MipsMemoryAccess::LoadHalfHelper(uint32_t va, MipsMemoryAccess* mem) {
    if (va & 1u) {                        /* LH/LHU require a 2-byte-aligned EA */
        mem->exceptions_->RaiseAddressError(va, MipsAccess::kRead);    /* AdEL; SEH unwind */
    }
    uint32_t pa = 0;
    const MipsTlbResult r =
        mem->mmu_->Translate(mem->cpu_state_, va, MipsAccess::kRead, &pa);
    if (r != MipsTlbResult::kMatch) {
        mem->exceptions_->RaiseTlbException(va, MipsAccess::kRead, r);  /* TLBL; SEH unwind */
    }
    if (const uint8_t* host = mem->memory_->TryTranslate(pa)) {
        uint16_t value = 0;
        std::memcpy(&value, host, sizeof(value));
        return value;                     /* zero-extended into the uint32 return */
    }
    return mem->MmioRead(va, pa, 2, "MipsMemoryAccess::LoadHalfHelper");
}

uint64_t __fastcall MipsMemoryAccess::LoadDwordHelper(uint32_t va, MipsMemoryAccess* mem) {
    if (va & 7u) {                        /* LD requires an 8-byte-aligned EA */
        mem->exceptions_->RaiseAddressError(va, MipsAccess::kRead);    /* AdEL; SEH unwind */
    }
    uint32_t pa = 0;
    const MipsTlbResult r =
        mem->mmu_->Translate(mem->cpu_state_, va, MipsAccess::kRead, &pa);
    if (r != MipsTlbResult::kMatch) {
        mem->exceptions_->RaiseTlbException(va, MipsAccess::kRead, r);  /* TLBL; SEH unwind */
    }
    if (const uint8_t* host = mem->memory_->TryTranslate(pa)) {
        uint64_t value = 0;
        std::memcpy(&value, host, sizeof(value));
        return value;
    }
    if (mem->peripheral_->IsPeripheralAddress(pa)) {
        mem->DeliverDueClockEvents();
        return mem->peripheral_->ReadDword(pa);
    }
    LOG(Caution, "MipsMemoryAccess::LoadDwordHelper: unmapped MMIO read va=0x%08X pa=0x%08X pc=0x%08X "
            "(no peripheral registered)\n", va, pa, mem->cpu_state_->pc);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

void MipsMemoryAccess::StoreByteXlate(MipsMemoryAccess* mem, uint32_t va, uint8_t value,
                            const char* who) {
    uint32_t pa = 0;
    const MipsTlbResult r =
        mem->mmu_->Translate(mem->cpu_state_, va, MipsAccess::kWrite, &pa);
    if (r != MipsTlbResult::kMatch) {
        mem->exceptions_->RaiseTlbException(va, MipsAccess::kWrite, r);  /* TLBS/Mod; SEH unwind */
    }
    uint8_t* host = mem->memory_->TryTranslateWrite(pa);
    if (!host) {
        mem->MmioWrite(va, pa, value, 1, who);
        return;
    }
    mem->cache_->InvalidateOnRamWrite(host, 1u);
    *host = value;
}

void __fastcall MipsMemoryAccess::SdrHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem) {
    /* Little-endian SDR: store the low ((va&7)^7)+1 bytes of gpr[rt], byte n ->
       mem[va+n] = rt>>(n*8). (QEMU tcg/ldst_helper.c helper_sdr + get_lmask.) */
    const uint64_t val   = mem->cpu_state_->gpr[rt];
    const uint32_t count = ((va & 7u) ^ 7u) + 1u;
    for (uint32_t n = 0; n < count; ++n) {
        StoreByteXlate(mem, va + n, static_cast<uint8_t>(val >> (n * 8u)),
                       "MipsMemoryAccess::SdrHelper");
    }
}

void __fastcall MipsMemoryAccess::SdlHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem) {
    /* Little-endian SDL: store the high (va&7)+1 bytes of gpr[rt], byte n ->
       mem[va-n] = rt>>((7-n)*8). (QEMU tcg/ldst_helper.c helper_sdl + get_lmask.) */
    const uint64_t val   = mem->cpu_state_->gpr[rt];
    const uint32_t count = (va & 7u) + 1u;
    for (uint32_t n = 0; n < count; ++n) {
        StoreByteXlate(mem, va - n, static_cast<uint8_t>(val >> ((7u - n) * 8u)),
                       "MipsMemoryAccess::SdlHelper");
    }
}

void __fastcall MipsMemoryAccess::LwlHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem) {
    /* LE: load the aligned word, shift it into the high bytes by ((va&3)^3)*8,
       OR in the kept low bytes of rt, sign-extend the 32-bit result. (QEMU
       translate.c gen_lxl + ext32s, OPC_LWL.) */
    const uint32_t shift  = ((va & 3u) ^ 3u) * 8u;
    const uint32_t w      = LoadWordHelper(va & ~3u, mem);  /* aligned: translate+load+fault */
    const uint32_t old    = static_cast<uint32_t>(mem->cpu_state_->gpr[rt]);
    const uint32_t mask   = 0xFFFFFFFFu << shift;
    const uint32_t merged = (w << shift) | (old & ~mask);
    if (rt != 0) {
        mem->cpu_state_->gpr[rt] =
            static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(merged)));
    }
}

void __fastcall MipsMemoryAccess::LwrHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem) {
    /* LE: load the aligned word, shift it right by s=(va&3)*8 so the right
       bytes land in rt's low end, keep rt's high bytes via (~1)<<(s^31), OR,
       sign-extend the 32-bit result. (QEMU translate.c gen_lxr + ext32s,
       OPC_LWR, MO_UL.) */
    const uint32_t s         = (va & 3u) * 8u;
    const uint32_t w         = LoadWordHelper(va & ~3u, mem);  /* aligned: translate+load+fault */
    const uint32_t loaded    = w >> s;
    const uint32_t keep_mask = 0xFFFFFFFEu << (s ^ 31u);       /* (~1) << (s^31) */
    const uint32_t old       = static_cast<uint32_t>(mem->cpu_state_->gpr[rt]);
    const uint32_t merged    = loaded | (old & keep_mask);
    if (rt != 0) {
        mem->cpu_state_->gpr[rt] =
            static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(merged)));
    }
}

void __fastcall MipsMemoryAccess::LdlHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem) {
    /* LE: load the aligned doubleword, shift it left by shift=((va&7)^7)*8 so the
       left bytes land in rt's high end, keep rt's low bytes via ~((~0)<<shift), OR.
       Full 64-bit (no sext). (QEMU translate.c gen_lxl, OPC_LDL, MO_UQ.) */
    const uint32_t shift  = ((va & 7u) ^ 7u) * 8u;
    const uint64_t w      = LoadDwordHelper(va & ~7u, mem);  /* aligned: translate+load+fault */
    const uint64_t old    = mem->cpu_state_->gpr[rt];
    const uint64_t mask   = (~0ull) << shift;
    const uint64_t merged = (w << shift) | (old & ~mask);
    if (rt != 0) {
        mem->cpu_state_->gpr[rt] = merged;
    }
}

void __fastcall MipsMemoryAccess::LdrHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem) {
    /* LE: load the aligned dword, shift it right by s=(va&7)*8 so the right bytes
       land in rt's low end, keep rt's high bytes via (~1)<<(s^63), OR. Full 64-bit
       (no sext). (QEMU translate.c gen_lxr, OPC_LDR, MO_UQ.) */
    const uint32_t s         = (va & 7u) * 8u;
    const uint64_t w         = LoadDwordHelper(va & ~7u, mem);  /* aligned: translate+load+fault */
    const uint64_t loaded    = w >> s;
    const uint64_t keep_mask = (~1ull) << (s ^ 63u);
    const uint64_t old       = mem->cpu_state_->gpr[rt];
    const uint64_t merged    = loaded | (old & keep_mask);
    if (rt != 0) {
        mem->cpu_state_->gpr[rt] = merged;
    }
}

void __fastcall MipsMemoryAccess::SwrHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem) {
    /* Little-endian SWR: store the low ((va&3)^3)+1 bytes of gpr[rt][31:0],
       byte n -> mem[va+n] = rt>>(n*8). (QEMU tcg/ldst_helper.c helper_swr.) */
    const uint32_t val   = static_cast<uint32_t>(mem->cpu_state_->gpr[rt]);
    const uint32_t count = ((va & 3u) ^ 3u) + 1u;
    for (uint32_t n = 0; n < count; ++n) {
        StoreByteXlate(mem, va + n, static_cast<uint8_t>(val >> (n * 8u)),
                       "MipsMemoryAccess::SwrHelper");
    }
}

void __fastcall MipsMemoryAccess::SwlHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem) {
    /* Little-endian SWL: store the high (va&3)+1 bytes of gpr[rt][31:0], byte n
       -> mem[va-n] = rt>>((3-n)*8). (QEMU tcg/ldst_helper.c helper_swl.) */
    const uint32_t val   = static_cast<uint32_t>(mem->cpu_state_->gpr[rt]);
    const uint32_t count = (va & 3u) + 1u;
    for (uint32_t n = 0; n < count; ++n) {
        StoreByteXlate(mem, va - n, static_cast<uint8_t>(val >> ((3u - n) * 8u)),
                       "MipsMemoryAccess::SwlHelper");
    }
}

void __fastcall MipsMemoryAccess::StoreDwordHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem) {
    if (va & 7u) {                        /* SD requires an 8-byte-aligned EA */
        mem->exceptions_->RaiseAddressError(va, MipsAccess::kWrite);   /* AdES; SEH unwind */
    }
    uint32_t pa = 0;
    const MipsTlbResult r =
        mem->mmu_->Translate(mem->cpu_state_, va, MipsAccess::kWrite, &pa);
    if (r != MipsTlbResult::kMatch) {
        mem->exceptions_->RaiseTlbException(va, MipsAccess::kWrite, r);  /* TLBS/Mod; SEH unwind */
    }
    if (uint8_t* host = mem->memory_->TryTranslateWrite(pa)) {
        mem->cache_->InvalidateOnRamWrite(host, 8u);
        std::memcpy(host, &mem->cpu_state_->gpr[rt], sizeof(uint64_t));
        return;
    }
    if (mem->peripheral_->IsPeripheralAddress(pa)) {
        mem->DeliverDueClockEvents();
        mem->peripheral_->WriteDword(pa, mem->cpu_state_->gpr[rt]);
        mem->LeaveBlockIfCpuStopped();
        return;
    }
    LOG(Caution, "MipsMemoryAccess::StoreDwordHelper: unmapped MMIO write va=0x%08X pa=0x%08X pc=0x%08X "
            "(no peripheral registered)\n", va, pa, mem->cpu_state_->pc);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}
