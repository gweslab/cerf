#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <atomic>
#include <cstdint>

namespace {

/* Linux arch/arm/mach-msm msm_iomap-7x30.h: MSM_SAW_PHYS, MSM_SAW_SIZE. */
constexpr uint32_t kSawBase = 0xC0102000u;
constexpr uint32_t kSawSize = 0x00001000u;

/* Linux arch/arm/mach-msm spm.c msm_spm_reg_offsets: MSM_SPM_REG_SAW_CFG 0x10
   through MSM_SPM_REG_SAW_SPM_MPM_CFG 0x38, one word apart. */
constexpr uint32_t kRegFileFirst = 0x10u;
constexpr uint32_t kRegFileLast  = 0x38u;
constexpr uint32_t kRegFileCount = (kRegFileLast - kRegFileFirst) / 4u + 1u;

constexpr uint32_t kReg04 = 0x04u;

constexpr uint32_t kRegReset = 0u;

class Msm8255Saw : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Msm8255;
    }

    void OnReady() override {
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            reg04_.store(kRegReset, std::memory_order_release);
            for (uint32_t i = 0; i < kRegFileCount; ++i) {
                regs_[i].store(kRegReset, std::memory_order_release);
            }
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kSawBase; }
    uint32_t MmioSize() const override { return kSawSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (off == kReg04) return reg04_.load(std::memory_order_acquire);
        if (InRegFile(off)) {
            return regs_[RegIndex(off)].load(std::memory_order_acquire);
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off == kReg04) {
            reg04_.store(value, std::memory_order_release);
            return;
        }
        if (InRegFile(off)) {
            regs_[RegIndex(off)].store(value, std::memory_order_release);
            return;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    void SaveState(StateWriter& w) override {
        w.Write<uint32_t>("reg04", reg04_.load(std::memory_order_acquire));
        for (uint32_t i = 0; i < kRegFileCount; ++i) {
            w.Write<uint32_t>("regs", regs_[i].load(std::memory_order_acquire));
        }
    }

    void RestoreState(StateReader& r) override {
        uint32_t reg04 = kRegReset;
        r.Read("reg04", reg04);
        reg04_.store(reg04, std::memory_order_release);
        for (uint32_t i = 0; i < kRegFileCount; ++i) {
            uint32_t v = kRegReset;
            r.Read("regs", v);
            regs_[i].store(v, std::memory_order_release);
        }
    }

private:
    static bool InRegFile(uint32_t off) {
        return off >= kRegFileFirst && off <= kRegFileLast && (off & 3u) == 0u;
    }
    static uint32_t RegIndex(uint32_t off) {
        return (off - kRegFileFirst) / 4u;
    }

    std::atomic<uint32_t> reg04_{kRegReset};
    std::atomic<uint32_t> regs_[kRegFileCount] = {};
};

}

REGISTER_SERVICE(Msm8255Saw);
