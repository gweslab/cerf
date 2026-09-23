#define NOMINMAX

#include "../../socs/msm8255/msm8255_mddi_client.h"

#include "../../core/cerf_emulator.h"
#include "../../host/panel_frame_renderer.h"
#include "../../lcd/panel_scanout.h"
#include "../board_context.h"
#include "nokia_lumia_800_id.h"

namespace {

class NokiaLumia800PanelRenderer : public PanelFrameRenderer {
public:
    using PanelFrameRenderer::PanelFrameRenderer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NokiaLumia800;
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        const Msm8255MddiSurface s = emu_.Get<Msm8255MddiClient>().Surface();
        w = s.width;
        h = s.height;
    }

    bool HasFrame() override {
        const Msm8255MddiSurface s = emu_.Get<Msm8255MddiClient>().Surface();
        if (!s.visible)       return false;
        if (latch_.Latched()) return true;
        return latch_.ProbeAndLatch(s.pixels, s.stride_bytes * s.height);
    }

    void RenderInto(uint32_t* dib, uint32_t host_w, uint32_t host_h) override {
        const Msm8255MddiSurface s = emu_.Get<Msm8255MddiClient>().Surface();
        const PanelSurface src{.fb     = s.pixels,
                               .stride = s.stride_bytes,
                               .width  = s.width,
                               .height = s.height};
        PanelScanout{s.format}.Blit(src, dib, host_w, host_h);
    }
};

}

REGISTER_SERVICE_AS(NokiaLumia800PanelRenderer, PanelFrameRenderer);
