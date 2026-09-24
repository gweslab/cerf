#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <array>
#include <cstdint>

namespace {

/* i.MX51 VPU at 0x83FF4000 - a Chips&Media CODA video codec, NOT the TVE:
   MCIMX51RM Table 2-1 mislabels this base "TVE", but vpu.dll's VPU_Init
   MmMapIoSpace's exactly 0x83FF4000 and runs the CODA BIT protocol on it. */
constexpr uint32_t kBase = 0x83FF4000u;
constexpr uint32_t kSize = 0x00004000u;

/* Chips&Media CODA BIT processor register offsets (mainline Linux coda driver). */
constexpr uint32_t kRegCodeRun = 0x000u;  /* boot/run kick; write 1 to start BIT */
constexpr uint32_t kRegBusy    = 0x160u;  /* BUSY: host sets 1, BIT clears on done */

class Imx51Vpu : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint8_t ReadByte(uint32_t a) override {
        const uint32_t o = a - kBase;
        return static_cast<uint8_t>(regs_[o >> 2] >> ((o & 3u) * 8u));
    }
    uint16_t ReadHalf(uint32_t a) override {
        const uint32_t o = a - kBase;
        return static_cast<uint16_t>(regs_[o >> 2] >> ((o & 2u) * 8u));
    }
    uint32_t ReadWord(uint32_t a) override { return regs_[(a - kBase) >> 2]; }

    void WriteByte(uint32_t a, uint8_t  v) override { Merge(a - kBase, v, (a & 3u) * 8u, 0xFFu); }
    void WriteHalf(uint32_t a, uint16_t v) override { Merge(a - kBase, v, (a & 2u) * 8u, 0xFFFFu); }

    void WriteWord(uint32_t a, uint32_t v) override {
        const uint32_t o = a - kBase;
        regs_[o >> 2] = v;
        /* vpu.dll VPU_Init sets BIT_BUSY=1, writes BIT_CODE_RUN=1, then spins
           `while(*(base+0x160))` until the BIT core clears BUSY. No real CODA
           core exists, so the run-kick clears BUSY here - without it VPU_Init
           never returns and gwes never launches. */
        if (o == kRegCodeRun && v != 0u)
            regs_[kRegBusy >> 2] = 0u;
    }

    void SaveState(StateWriter& w) override    { w.WriteBytes("regs", regs_.data(), sizeof(regs_)); }
    void RestoreState(StateReader& r) override { r.ReadBytes("regs", regs_.data(), sizeof(regs_)); }

private:
    void Merge(uint32_t off, uint32_t v, uint32_t shift, uint32_t vmask) {
        const uint32_t m = vmask << shift;
        uint32_t& r = regs_[off >> 2];
        r = (r & ~m) | ((v << shift) & m);
    }

    std::array<uint32_t, kSize / 4> regs_{};
};

}  /* namespace */

REGISTER_SERVICE(Imx51Vpu);
