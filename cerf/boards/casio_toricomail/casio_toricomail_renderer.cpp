#define NOMINMAX

#include "casio_toricomail_asic.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../host/panel_frame_renderer.h"
#include "../../lcd/panel_scanout.h"

#include <optional>

namespace {

constexpr size_t kContentProbeStride = 251;

/* ddi.dll DrvEnablePDEV reports bpp=16 w=320 h=240; nk.exe fill sub_9F0B7D20 @0x9F0B8184
   fills 0xF800 = RGB565 pure red - the framebuffer is 16bpp RGB565. */
class CasioToricomailRenderer : public PanelFrameRenderer {
public:
    using PanelFrameRenderer::PanelFrameRenderer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::CasioToricomail;
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        auto& asic = emu_.Get<CasioToricomailAsic>();
        w = asic.GuestW();
        h = asic.GuestH();
    }

    bool HasFrame() override {
        auto& asic = emu_.Get<CasioToricomailAsic>();
        if (!asic.IsDisplayEnabled()) return false;
        if (latch_.Latched())         return true;
        const uint32_t bytes = asic.StrideBytes() * asic.GuestH();
        return latch_.ProbeAndLatch(asic.FbBytes(), bytes, kContentProbeStride);
    }

    void RenderInto(uint32_t* dib, uint32_t host_w, uint32_t host_h) override {
        auto& asic = emu_.Get<CasioToricomailAsic>();
        const PanelSurface src{.fb     = asic.FbBytes(),
                               .stride = asic.StrideBytes(),
                               .width  = asic.GuestW(),
                               .height = asic.GuestH()};
        scanout_.Blit(src, dib, host_w, host_h);
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto& asic = emu_.Get<CasioToricomailAsic>();
        return FbLayout{asic.FbPa(), asic.StrideBytes(), 16u, true};
    }

private:
    PanelScanout scanout_{PanelPixelFormat::kRgb565Le};
};

}  /* namespace */

REGISTER_SERVICE_AS(CasioToricomailRenderer, PanelFrameRenderer);
