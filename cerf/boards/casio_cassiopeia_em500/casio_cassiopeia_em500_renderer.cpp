#define NOMINMAX

#include "casio_cassiopeia_em500_companion.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../host/panel_frame_renderer.h"
#include "../../lcd/panel_scanout.h"

#include <optional>

namespace {

constexpr size_t kContentProbeStride = 251;

/* ddi.dll @0xFC5458-0xFC546C (andi 0xF800/0x7E0/0x1F channel split): the 16bpp
   framebuffer is RGB565. */
class CasioCassiopeiaEm500Renderer : public PanelFrameRenderer {
public:
    using PanelFrameRenderer::PanelFrameRenderer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::CasioCassiopeiaEm500;
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        auto& asic = emu_.Get<CasioCassiopeiaEm500Companion>();
        w = asic.GuestW();
        h = asic.GuestH();
    }

    bool HasFrame() override {
        auto& asic = emu_.Get<CasioCassiopeiaEm500Companion>();
        if (!asic.IsDisplayEnabled()) return false;
        if (latch_.Latched())         return true;
        const uint32_t bytes = asic.StrideBytes() * asic.GuestH();
        return latch_.ProbeAndLatch(asic.FbBytes(), bytes, kContentProbeStride);
    }

    void RenderInto(uint32_t* dib, uint32_t host_w, uint32_t host_h) override {
        auto& asic = emu_.Get<CasioCassiopeiaEm500Companion>();
        const PanelSurface src{.fb     = asic.FbBytes(),
                               .stride = asic.StrideBytes(),
                               .width  = asic.GuestW(),
                               .height = asic.GuestH()};
        scanout_.Blit(src, dib, host_w, host_h);
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto& asic = emu_.Get<CasioCassiopeiaEm500Companion>();
        return FbLayout{asic.FbPa(), asic.StrideBytes(), 16u, true};
    }

private:
    PanelScanout scanout_{PanelPixelFormat::kRgb565Le};
};

}  /* namespace */

REGISTER_SERVICE_AS(CasioCassiopeiaEm500Renderer, PanelFrameRenderer);
