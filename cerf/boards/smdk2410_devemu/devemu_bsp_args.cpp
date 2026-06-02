#include "../board_detector.h"

#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../core/service.h"
#include "../../cpu/emulated_memory.h"

#include <cstdint>

namespace {

/* args.h BSP_ARGS layout at PA + 0x44: Signature/Width/Height/Bpp. */
constexpr uint32_t kBspArgsPa            = 0x30020000u;
constexpr uint32_t kScreenSignatureOff   = 0x44u;
constexpr uint32_t kBspScreenSignature   = 0xDE12DE34u;
/* S3C2410 LCD handler halts on anything but 16bpp 5:6:5 ENVID=1. */
constexpr uint16_t kPinnedColorDepthBpp  = 16u;

class DevEmuBspArgs : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        if (!bd || bd->GetBoard() != Board::Smdk2410DevEmu) return false;
        return !emu_.Get<DeviceConfig>().guest_additions;
    }

    void OnReady() override {
        auto& cfg = emu_.Get<DeviceConfig>();
        auto& mem = emu_.Get<EmulatedMemory>();

        const uint16_t w = static_cast<uint16_t>(cfg.board_configurable_screen_width);
        const uint16_t h = static_cast<uint16_t>(cfg.board_configurable_screen_height);

        const uint32_t base = kBspArgsPa + kScreenSignatureOff;
        mem.WriteWord(base + 0u, kBspScreenSignature);
        mem.WriteHalf(base + 4u, w);
        mem.WriteHalf(base + 6u, h);
        mem.WriteHalf(base + 8u, kPinnedColorDepthBpp);

        LOG(Board, "DevEmuBspArgs: ScreenSignature=0x%08X "
                   "Width=%u Height=%u BitsPerPixel=%u at PA 0x%08X\n",
            kBspScreenSignature, (unsigned)w, (unsigned)h,
            (unsigned)kPinnedColorDepthBpp, base);
    }
};

}  /* namespace */

REGISTER_SERVICE(DevEmuBspArgs);
