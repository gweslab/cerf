#include "../board_detector.h"
#include "zune_keel_framebuffer.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../core/service.h"
#include "../../cpu/emulated_memory.h"

#include <cstdint>

namespace {

/* Bootloader-synthesized BSP_ARGS block at the start of DRAM. The recovery
   OAL's framebuffer IOCTL (0x1011018) rejects the block unless the signature
   and version below match exactly, then hands software the FB descriptor at
   +72; a wrong magic leaves the recovery screen blank. */
constexpr uint32_t kArgsPa        = 0x80000000u;
constexpr uint32_t kArgsSignature = 0x53475241u;  /* 'ARGS' (LE bytes A,R,G,S) */

/* Framebuffer descriptor (ARGS+72, 36 bytes) the recovery UI reads. It plots
   `*(u16*)(fb + 2*(x + w*y))` → 16bpp RGB565, stride = w*2. */
constexpr uint32_t kFbDescOff = 72u;

class ZuneKeelBspArgs : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::ZuneKeel;
    }

    void OnReady() override {
        auto& mem = emu_.Get<EmulatedMemory>();

        mem.WriteWord(kArgsPa + 0u, kArgsSignature);
        mem.WriteHalf(kArgsPa + 4u, uint16_t{1});  /* OAL version */
        mem.WriteHalf(kArgsPa + 6u, uint16_t{6});  /* BSP version */

        const uint32_t fb = kArgsPa + kFbDescOff;
        mem.WriteWord(fb +  0u, zune_keel::kScreenW); /* +0  screen width  */
        mem.WriteWord(fb +  4u, zune_keel::kScreenH); /* +4  screen height */
        mem.WriteWord(fb +  8u, 0u);
        mem.WriteWord(fb + 12u, 0u);          /* +12 orientation (0 = normal x+w*y) */
        mem.WriteHalf(fb + 16u, uint16_t{1}); /* +16 pixel scale X (>=1) */
        mem.WriteHalf(fb + 18u, uint16_t{1}); /* +18 pixel scale Y (>=1) */
        mem.WriteWord(fb + 20u, 0u);          /* +20 runtime mapped-VA slot */
        mem.WriteWord(fb + 24u, zune_keel::kFbPa);    /* +24 framebuffer phys addr */
        mem.WriteWord(fb + 28u, zune_keel::kFbBytes); /* +28 framebuffer size */
        mem.WriteWord(fb + 32u, 0u);

        LOG(Board, "ZuneKeelBspArgs: 'ARGS' block at PA 0x%08X; recovery FB "
                   "%ux%u RGB565 @ PA 0x%08X (%u bytes)\n",
            kArgsPa, zune_keel::kScreenW, zune_keel::kScreenH,
            zune_keel::kFbPa, zune_keel::kFbBytes);
    }
};

}  /* namespace */

REGISTER_SERVICE(ZuneKeelBspArgs);
