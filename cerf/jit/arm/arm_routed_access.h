#pragma once

#include <cstdint>

#include "../../core/service.h"

class ArmMmu;
class ArmPageWalker;
class GuestCycleClock;
class PeripheralDispatcher;
struct ArmCpuState;

class ArmRoutedAccess : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    bool Load(ArmCpuState* cpu_state, uint32_t guest_pc, uint32_t va,
              uint32_t bytes, uint32_t* out, bool unpriv);
    bool Store(ArmCpuState* cpu_state, uint32_t guest_pc, uint32_t va,
               uint32_t bytes, uint32_t value, bool unpriv);

    bool WideAccess(ArmCpuState* cpu_state, uint32_t guest_pc, uint32_t va,
                    uint32_t bytes, uint8_t* buf, bool is_load);

    static uint32_t __cdecl IoLoadHelper(ArmRoutedAccess* self, uint32_t bytes,
                                         uint32_t guest_pc, uint32_t va);
    static void __cdecl IoStoreHelper(ArmRoutedAccess* self, uint32_t bytes,
                                      uint32_t guest_pc, uint32_t va,
                                      uint32_t value);

private:
    uint32_t DispatchRead(uint32_t pa, uint32_t bytes, uint32_t guest_pc,
                          uint32_t va);
    void     DispatchWrite(uint32_t pa, uint32_t bytes, uint32_t value,
                           uint32_t guest_pc, uint32_t va);
    void     DeliverDueClockEvents();

    [[noreturn]] void HaltUnalignedRouted(uint32_t guest_pc, uint32_t va,
                                          uint32_t bytes, uint32_t pa,
                                          const char* kind);
    [[noreturn]] void HaltRoutedWidth(uint32_t guest_pc, uint32_t va,
                                      uint32_t bytes, uint32_t pa,
                                      const char* kind);

    ArmMmu*               mmu_        = nullptr;
    ArmPageWalker*        walker_     = nullptr;
    PeripheralDispatcher* dispatcher_ = nullptr;
    GuestCycleClock*      clock_      = nullptr;
    ArmCpuState*          cpu_state_  = nullptr;
};
