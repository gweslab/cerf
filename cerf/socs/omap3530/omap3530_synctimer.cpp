#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/arm_processor_config.h"
#include "../../jit/arm_jit.h"
#include "../../jit/cpu_state.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../boards/board_detector.h"

#include <cstdint>
#include <mutex>

namespace {

constexpr uint32_t kSynctimerBasePa = 0x48320000u;
constexpr uint32_t kSynctimerSize   = 0x00001000u;

constexpr uint32_t kOffRev       = 0x00;
constexpr uint32_t kOffSysconfig = 0x04;
constexpr uint32_t kOffCr        = 0x10;

class Omap3530Synctimer : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetSoc() == SocFamily::OMAP3530;
    }
    void OnReady() override {
        divider_ = emu_.Get<ArmProcessorConfig>().CpuToOscrDivider();
        if (divider_ == 0) divider_ = 1;
        emu_.Get<PeripheralDispatcher>().Register(this);
        start_cycles_ = GuestCycles();
    }

    uint32_t MmioBase() const override { return kSynctimerBasePa; }
    uint32_t MmioSize() const override { return kSynctimerSize; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

private:
    uint32_t GuestCycles() const {
        return emu_.Get<ArmJit>().CpuState()->guest_cycle_counter;
    }

    /* SYNC counter from guest_cycle_counter — host wall-clock derivation
       makes two same-input runs see different counter values, breaking
       boot determinism. */
    uint32_t ComputeCounter() const;

    mutable std::mutex state_mutex_;
    uint32_t           start_cycles_ = 0;
    uint32_t           divider_      = 1;
    uint32_t           sysconfig_    = 0;
};

uint32_t Omap3530Synctimer::ComputeCounter() const {
    const uint32_t elapsed_cycles = GuestCycles() - start_cycles_;
    return elapsed_cycles / divider_;
}

uint32_t Omap3530Synctimer::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    std::lock_guard<std::mutex> lk(state_mutex_);
    switch (off) {
    case kOffRev:       return 0u;
    case kOffSysconfig: return sysconfig_;
    case kOffCr:        return ComputeCounter();
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Omap3530Synctimer::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    std::lock_guard<std::mutex> lk(state_mutex_);
    switch (off) {
    case kOffRev:       return;              /* read-only */
    case kOffSysconfig: sysconfig_ = value;  return;
    case kOffCr:        return;              /* counter is read-only */
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

}  /* namespace */

REGISTER_SERVICE(Omap3530Synctimer);
