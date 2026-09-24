#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <array>
#include <cstdint>

namespace {

/* i.MX51 HSC (High-Speed Connectivity) @ 0x83FDC000, 16 KB. RM Table 2-1 leaves
   0x83FD_C000 a GAP; the IMX51RMAD errata's corrected Table 2-1 names it HSC -
   ddraw_ipu's display-commit writes one config register here (no read-back). */
constexpr uint32_t kBase = 0x83FDC000u;
constexpr uint32_t kSize = 0x00004000u;  /* 16 KB, errata Table 2-1 */

class Imx51Hsc : public Peripheral {
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
        if (off & 1u) HaltUnsupportedAccess("ReadHalf misaligned", addr, 0);
        return static_cast<uint16_t>(regs_[off >> 2] >> ((off & 2u) * 8u));
    }
    uint32_t ReadWord(uint32_t addr) override { return regs_[(addr - kBase) >> 2]; }
    void WriteByte(uint32_t addr, uint8_t value) override {
        const uint32_t off = addr - kBase, sh = (off & 3u) * 8u;
        uint32_t& w = regs_[off >> 2];
        w = (w & ~(0xFFu << sh)) | (static_cast<uint32_t>(value) << sh);
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t off = addr - kBase;
        if (off & 1u) HaltUnsupportedAccess("WriteHalf misaligned", addr, value);
        const uint32_t sh = (off & 2u) * 8u;
        uint32_t& w = regs_[off >> 2];
        w = (w & ~(0xFFFFu << sh)) | (static_cast<uint32_t>(value) << sh);
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        regs_[(addr - kBase) >> 2] = value;
    }

    void SaveState(StateWriter& w) override    { w.WriteBytes("regs", regs_.data(), sizeof(regs_)); }
    void RestoreState(StateReader& r) override { r.ReadBytes("regs", regs_.data(), sizeof(regs_)); }

private:
    std::array<uint32_t, kSize / 4> regs_{};
};

}  /* namespace */

REGISTER_SERVICE(Imx51Hsc);
