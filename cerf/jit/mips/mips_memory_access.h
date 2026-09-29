#pragma once

#include <cstdint>

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/service.h"

struct MipsCpuState;

class EmulatedMemory;
class GuestCycleClock;
class MipsExceptionDelivery;
class MipsMmu;
class MipsTranslationCache;
class PeripheralDispatcher;

class MipsMemoryAccess : public Service {
public:
    using Service::Service;

    void OnReady() override;
    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Mips;
    }

    static void __fastcall StoreWordHelper(uint32_t va, uint32_t value,
                                           MipsMemoryAccess* mem);
    static void __fastcall StoreHalfHelper(uint32_t va, uint32_t value,
                                           MipsMemoryAccess* mem);
    static void __fastcall StoreByteHelper(uint32_t va, uint32_t value,
                                           MipsMemoryAccess* mem);
    static void __fastcall StoreDwordHelper(uint32_t va, uint32_t rt,
                                            MipsMemoryAccess* mem);

    static uint32_t __fastcall LoadWordHelper(uint32_t va, MipsMemoryAccess* mem);
    static uint32_t __fastcall LoadByteHelper(uint32_t va, MipsMemoryAccess* mem);
    static uint32_t __fastcall LoadHalfHelper(uint32_t va, MipsMemoryAccess* mem);
    static uint64_t __fastcall LoadDwordHelper(uint32_t va, MipsMemoryAccess* mem);

    static void __fastcall LwlHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem);
    static void __fastcall LwrHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem);
    static void __fastcall LdlHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem);
    static void __fastcall LdrHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem);

    static void __fastcall SwlHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem);
    static void __fastcall SwrHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem);
    static void __fastcall SdlHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem);
    static void __fastcall SdrHelper(uint32_t va, uint32_t rt, MipsMemoryAccess* mem);

    void DeliverDueClockEvents();

private:
    static void StoreByteXlate(MipsMemoryAccess* mem, uint32_t va, uint8_t value,
                               const char* who);

    void     LeaveBlockIfCpuStopped();
    uint32_t MmioRead (uint32_t va, uint32_t pa, uint32_t width, const char* who);
    void     MmioWrite(uint32_t va, uint32_t pa, uint32_t value, uint32_t width,
                       const char* who);

    MipsCpuState*          cpu_state_  = nullptr;
    MipsMmu*               mmu_        = nullptr;
    EmulatedMemory*        memory_     = nullptr;
    PeripheralDispatcher*  peripheral_ = nullptr;
    MipsExceptionDelivery* exceptions_ = nullptr;
    MipsTranslationCache*  cache_      = nullptr;
    GuestCycleClock*       clock_      = nullptr;
};
