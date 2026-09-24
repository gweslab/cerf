#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../../host/host_window.h"
#include "imx51_ipu_cpmem.h"

#include <vector>
#include <cstdint>

namespace {

/* i.MX51 IPUv3EX display controller (MCIMX51RM Ch 42). Register region = IPU base
   0x40000000 + 0x1E000000 = 0x5E000000; the CM/IDMAC/DP/IC/.../DC/DMFC/VDI
   sub-modules span 0x70000 (Table 42-1). */
constexpr uint32_t kBase = 0x5E000000u;          /* 0x40000000 + 0x1E000000 */
constexpr uint32_t kSize = 0x00070000u;          /* CM..VDI sub-module registers */

/* IPU_MEM_RST (IPU_CM + 0xDC, MCIMX51RM Figure 42-52): bit31 RST_MEM_START is a
   self-clearing start bit the IPU clears when the internal-memory reset
   completes. ddraw_ipu.dll DisplayInit (sub_C0A5931C) sets it then Sleep-polls
   until it clears, so it must read back 0 (CERF models no IPU internal mem). */
constexpr uint32_t kOffMemRst   = 0x000000DCu;
constexpr uint32_t kRstMemStart = 1u << 31;

/* IDMAC_CH_EN_1 @ IDMAC+0x14 = 0x5E008014 (guest sub_C0A59A10 writes off+0x14,
   bit = channel). Channel 23 (DP background) is the synchronous-display scanout
   channel; its 0->1 enable edge is the panel-enable that sizes the host window
   from the CPMEM descriptor the driver just programmed. */
constexpr uint32_t kOffIdmacChEn1 = 0x00008014u;
constexpr uint32_t kDisplayChannel = 23u;
constexpr uint32_t kIdmacCh23 = 1u << kDisplayChannel;

class Imx51Ipu : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override {
        regs_.assign(kSize / 4, 0u);
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
        const uint32_t off = addr - kBase;
        if (off == kOffMemRst)
            value &= ~kRstMemStart;   /* reset completes instantly; bit31 reads 0 */
        if (off == kOffIdmacChEn1) {
            const bool was = (regs_[off >> 2] & kIdmacCh23) != 0u;
            regs_[off >> 2] = value;
            if (!was && (value & kIdmacCh23)) SignalDisplayEnabled();
            return;
        }
        regs_[off >> 2] = value;
    }

    void SaveState(StateWriter& w) override {
        w.WriteBytes("regs", regs_.data(), regs_.size() * sizeof(uint32_t));
    }
    void RestoreState(StateReader& r) override {
        r.ReadBytes("regs", regs_.data(), regs_.size() * sizeof(uint32_t));
    }
    void PostRestore() override {
        /* OnLcdEnabled fires only on the IDMAC_CH_EN_1 ch23 0->1 edge in
           WriteWord; a restore where ch23 is already enabled produces no edge,
           so the host panel-enable must be re-asserted here (hibernation.md
           PostRestore: a level-driving source re-drives its level on restore). */
        if (regs_[kOffIdmacChEn1 >> 2] & kIdmacCh23) SignalDisplayEnabled();
    }

private:
    void SignalDisplayEnabled() {
        auto* cp = emu_.TryGet<Imx51IpuCpmem>();
        if (!cp) return;
        const auto d = cp->DecodeChannel(kDisplayChannel);
        if (d.valid) emu_.Get<HostWindow>().OnLcdEnabled();
    }

    std::vector<uint32_t> regs_;
};

}  /* namespace */

REGISTER_SERVICE(Imx51Ipu);
