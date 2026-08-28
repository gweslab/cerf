#define NOMINMAX

#include "ite_it8181.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../host/panel_frame_renderer.h"
#include "../../lcd/panel_scanout.h"

namespace {

constexpr size_t kContentProbeStride = 251;

class IteIt8181Renderer : public PanelFrameRenderer {
public:
    using PanelFrameRenderer::PanelFrameRenderer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::NecMobilePro700;
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        auto& lcd = emu_.Get<IteIt8181>();
        w = lcd.GuestW();
        h = lcd.GuestH();
    }

    bool HasFrame() override {
        auto& lcd = emu_.Get<IteIt8181>();
        if (!lcd.IsEnabled())  return false;
        if (latch_.Latched())  return true;
        const uint32_t bytes = lcd.StrideBytes() * lcd.GuestH();
        return latch_.ProbeAndLatch(lcd.FbBytes(), bytes, kContentProbeStride);
    }

    void RenderInto(uint32_t* dib, uint32_t host_w, uint32_t host_h) override {
        auto& lcd = emu_.Get<IteIt8181>();
        const PanelSurface src{.fb     = lcd.FbBytes(),
                               .stride = lcd.StrideBytes(),
                               .width  = lcd.GuestW(),
                               .height = lcd.GuestH()};
        scanout_.Blit(src, dib, host_w, host_h);
    }

private:
    PanelScanout scanout_{PanelPixelFormat::kGray2Msb};
};

}  /* namespace */

REGISTER_SERVICE_AS(IteIt8181Renderer, PanelFrameRenderer);
