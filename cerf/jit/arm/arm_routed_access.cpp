#include "arm_routed_access.h"

#include <cstring>

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../guest_cycle_clock.h"
#include "arm_cpu.h"
#include "arm_mmu.h"
#include "cpu_state.h"
#include "arm_page_walker.h"

REGISTER_SERVICE(ArmRoutedAccess);

bool ArmRoutedAccess::ShouldRegister() {
    return emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Arm;
}

void ArmRoutedAccess::OnReady() {
    mmu_        = &emu_.Get<ArmMmu>();
    walker_     = &emu_.Get<ArmPageWalker>();
    dispatcher_ = &emu_.Get<PeripheralDispatcher>();
    clock_      = &emu_.Get<GuestCycleClock>();
    cpu_state_  = emu_.Get<ArmCpu>().State();
}

void ArmRoutedAccess::DeliverDueClockEvents() {
    if (ArmCycleDeadlineReached(*cpu_state_)) clock_->OnDispatch();
}

void ArmRoutedAccess::HaltUnalignedRouted(uint32_t guest_pc, uint32_t va,
                                          uint32_t bytes, uint32_t pa,
                                          const char* kind) {
    LOG(Caution, "ArmRoutedAccess: guest PC 0x%08X routes an unaligned %u-byte "
            "%s at VA 0x%08X to peripheral PA 0x%08X\n",
        guest_pc, bytes, kind, va, pa);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

void ArmRoutedAccess::HaltRoutedWidth(uint32_t guest_pc, uint32_t va,
                                      uint32_t bytes, uint32_t pa,
                                      const char* kind) {
    LOG(Caution, "ArmRoutedAccess: guest PC 0x%08X routes a %u-byte %s at "
            "VA 0x%08X to peripheral PA 0x%08X with no modeled width\n",
        guest_pc, bytes, kind, va, pa);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

uint32_t ArmRoutedAccess::DispatchRead(uint32_t pa, uint32_t bytes,
                                       uint32_t guest_pc, uint32_t va) {
    DeliverDueClockEvents();
    switch (bytes) {
    case 1u: return dispatcher_->Read(pa, MmioWidth::kByte);
    case 2u: return dispatcher_->Read(pa, MmioWidth::kHalf);
    case 4u: return dispatcher_->Read(pa, MmioWidth::kWord);
    default: HaltRoutedWidth(guest_pc, va, bytes, pa, "load");
    }
}

void ArmRoutedAccess::DispatchWrite(uint32_t pa, uint32_t bytes, uint32_t value,
                                    uint32_t guest_pc, uint32_t va) {
    DeliverDueClockEvents();
    switch (bytes) {
    case 1u: dispatcher_->Write(pa, value, MmioWidth::kByte); return;
    case 2u: dispatcher_->Write(pa, value, MmioWidth::kHalf); return;
    case 4u: dispatcher_->Write(pa, value, MmioWidth::kWord); return;
    default: HaltRoutedWidth(guest_pc, va, bytes, pa, "store");
    }
}

uint32_t ArmRoutedAccess::IoLoadHelper(ArmRoutedAccess* self, uint32_t bytes,
                                       uint32_t guest_pc, uint32_t va) {
    const uint32_t pa = self->mmu_->io_pending_address();
    self->mmu_->ClearIoPending();
    if ((pa & (bytes - 1u)) != 0u) {
        self->HaltUnalignedRouted(guest_pc, va, bytes, pa, "load");
    }
    return self->DispatchRead(pa, bytes, guest_pc, va);
}

void ArmRoutedAccess::IoStoreHelper(ArmRoutedAccess* self, uint32_t bytes,
                                    uint32_t guest_pc, uint32_t va,
                                    uint32_t value) {
    const uint32_t pa = self->mmu_->io_pending_address();
    self->mmu_->ClearIoPending();
    if ((pa & (bytes - 1u)) != 0u) {
        self->HaltUnalignedRouted(guest_pc, va, bytes, pa, "store");
    }
    self->DispatchWrite(pa, bytes, value, guest_pc, va);
}

bool ArmRoutedAccess::Load(ArmCpuState* cpu_state, uint32_t guest_pc,
                           uint32_t va, uint32_t bytes, uint32_t* out,
                           bool unpriv) {
    if ((va & (bytes - 1u)) != 0u) {
        uint32_t value = 0;
        if (mmu_->AccessPaged(cpu_state, va,
                              reinterpret_cast<uint8_t*>(&value), bytes, true,
                              unpriv)) {
            *out = value;
            return true;
        }
        const uint32_t split_pa = mmu_->io_pending_address();
        if (!mmu_->io_pending()) {
            return false;
        }
        HaltUnalignedRouted(guest_pc, va, bytes, split_pa, "load");
    }

    uint8_t* host = unpriv ? walker_->TranslateUserRead(cpu_state, va)
                           : walker_->TranslateRead(cpu_state, va);
    if (host != nullptr) {
        uint32_t value = 0;
        std::memcpy(&value, host, bytes);
        *out = value;
        return true;
    }
    const uint32_t pa = mmu_->io_pending_address();
    if (!mmu_->io_pending()) {
        return false;
    }
    *out = DispatchRead(pa, bytes, guest_pc, va);
    return true;
}

/* DDI 0406C.c A8.8.332 VLDM Operation, p. A8-923; A8.8.333 VLDR Operation,
   p. A8-925. */
bool ArmRoutedAccess::WideAccess(ArmCpuState* cpu_state, uint32_t guest_pc,
                                 uint32_t va, uint32_t bytes, uint8_t* buf,
                                 bool is_load) {
    uint32_t chunk = 0;
    switch (bytes) {
    case 1u:
    case 2u:
    case 4u: chunk = bytes; break;
    case 8u: chunk = 4u;    break;
    default: HaltRoutedWidth(guest_pc, va, bytes, mmu_->io_pending_address(),
                             is_load ? "load" : "store");
    }

    for (uint32_t done = 0; done < bytes; done += chunk) {
        uint32_t word = 0;
        if (is_load) {
            if (!Load(cpu_state, guest_pc, va + done, chunk, &word, false)) {
                return false;
            }
            std::memcpy(buf + done, &word, chunk);
        } else {
            std::memcpy(&word, buf + done, chunk);
            if (!Store(cpu_state, guest_pc, va + done, chunk, word, false)) {
                return false;
            }
        }
    }
    mmu_->ClearIoPending();
    return true;
}

bool ArmRoutedAccess::Store(ArmCpuState* cpu_state, uint32_t guest_pc,
                            uint32_t va, uint32_t bytes, uint32_t value,
                            bool unpriv) {
    if ((va & (bytes - 1u)) != 0u) {
        uint32_t stored = value;
        if (mmu_->AccessPaged(cpu_state, va,
                              reinterpret_cast<uint8_t*>(&stored), bytes,
                              false, unpriv)) {
            return true;
        }
        const uint32_t split_pa = mmu_->io_pending_address();
        if (!mmu_->io_pending()) {
            return false;
        }
        HaltUnalignedRouted(guest_pc, va, bytes, split_pa, "store");
    }

    uint8_t* host = unpriv ? walker_->TranslateUserWrite(cpu_state, va)
                           : walker_->TranslateWrite(cpu_state, va);
    if (host != nullptr) {
        std::memcpy(host, &value, bytes);
        return true;
    }
    const uint32_t pa = mmu_->io_pending_address();
    if (!mmu_->io_pending()) {
        return false;
    }
    DispatchWrite(pa, bytes, value, guest_pc, va);
    return true;
}
