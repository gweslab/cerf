#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <array>
#include <cstdint>

namespace cerf_imx51_ipu_mem_detail {

/* i.MX51 IPUv3EX internal-memory windows (MCIMX51RM Ch 42 Table 42-1): 128 KB
   passive-RAM windows in the IPU internal-memory region (IPU base 0x40000000 +
   0x1F000000 = 0x5F000000) - CPMEM / LUT / CM-Shadow(SRM) / TPM / DC template. */
constexpr uint32_t kSize = 0x00020000u;   /* 128 KB per window, RM Table 42-1 */

template <uint32_t kBase>
class Imx51IpuInternalMem : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint8_t ReadByte(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        return static_cast<uint8_t>(regs_[off >> 2] >> ((off & 3u) * 8u));
    }
    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        return static_cast<uint16_t>(regs_[off >> 2] >> ((off & 2u) * 8u));
    }
    uint32_t ReadWord(uint32_t addr) override { return regs_[(addr - kBase) >> 2]; }
    void WriteByte(uint32_t addr, uint8_t value) override {
        const uint32_t off = addr - kBase, sh = (off & 3u) * 8u;
        uint32_t& w = regs_[off >> 2];
        w = (w & ~(0xFFu << sh)) | (static_cast<uint32_t>(value) << sh);
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t off = addr - kBase, sh = (off & 2u) * 8u;
        uint32_t& w = regs_[off >> 2];
        w = (w & ~(0xFFFFu << sh)) | (static_cast<uint32_t>(value) << sh);
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        regs_[(addr - kBase) >> 2] = value;
    }

    /* JIT-thread-only RAM file (no worker thread). */
    void SaveState(StateWriter& w) override    { w.WriteBytes("regs", regs_.data(), sizeof(regs_)); }
    void RestoreState(StateReader& r) override { r.ReadBytes("regs", regs_.data(), sizeof(regs_)); }

protected:
    std::array<uint32_t, kSize / 4> regs_{};
};

}  /* namespace cerf_imx51_ipu_mem_detail */
