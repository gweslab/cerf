#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <atomic>
#include <cstdint>

namespace {

/* Linux arch/arm/mach-msm msm_iomap-7x30.h: MSM_CLK_CTL_SH2_PHYS. */
constexpr uint32_t kSh2Base = 0xABA01000u;

constexpr uint32_t kSh2Size = 0x00002000u;

/* Linux arch/arm/mach-msm clock-7x30-vendor.c divides the clock register map
   into the shadow-region 2 offsets reached through MSM_CLK_CTL_SH2_BASE and a
   separate non-shadow region reached through MSM_CLK_CTL_BASE. */
struct Register {
    uint32_t offset;
    uint32_t accepted;
};

constexpr Register kRegisters[] = {
    {0x39Cu, 0x00007000u},
    {0x478u, 0x7FEF7FFFu},
    {0x47Cu, 0xFFFFFFFFu},
};

constexpr uint32_t kRegisterCount =
    sizeof(kRegisters) / sizeof(kRegisters[0]);

constexpr uint32_t kResetValue = 0u;

class Msm8255ClkCtlSh2 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Msm8255;
    }

    void OnReady() override {
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            for (auto& reg : regs_) {
                reg.store(kResetValue, std::memory_order_release);
            }
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kSh2Base; }
    uint32_t MmioSize() const override { return kSh2Size; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t i = IndexOf(addr - MmioBase());
        if (i == kRegisterCount) {
            HaltUnsupportedAccess("ReadWord", addr, 0);
        }
        return regs_[i].load(std::memory_order_acquire);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t i = IndexOf(addr - MmioBase());
        if (i == kRegisterCount ||
            (value & ~kRegisters[i].accepted) != 0u) {
            HaltUnsupportedAccess("WriteWord", addr, value);
        }
        regs_[i].store(value, std::memory_order_release);
    }

    void SaveState(StateWriter& w) override {
        for (auto& reg : regs_) {
            w.Write<uint32_t>("reg", reg.load(std::memory_order_acquire));
        }
    }

    void RestoreState(StateReader& r) override {
        for (uint32_t i = 0; i < kRegisterCount; ++i) {
            uint32_t value = kResetValue;
            r.Read("reg", value);
            if ((value & ~kRegisters[i].accepted) != 0u) {
                r.Reject(
                    "msm8255 clk_ctl_sh2: restored +0x%03X value 0x%08X carries "
                    "bits the guest never writes", kRegisters[i].offset, value);
            }
            regs_[i].store(value, std::memory_order_release);
        }
    }

private:
    static uint32_t IndexOf(uint32_t offset) {
        for (uint32_t i = 0; i < kRegisterCount; ++i) {
            if (kRegisters[i].offset == offset) return i;
        }
        return kRegisterCount;
    }

    std::atomic<uint32_t> regs_[kRegisterCount] = {};
};

}

REGISTER_SERVICE(Msm8255ClkCtlSh2);
