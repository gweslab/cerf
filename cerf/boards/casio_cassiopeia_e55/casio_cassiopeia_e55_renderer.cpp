#define NOMINMAX

#include "casio_cassiopeia_e55_lcd.h"

#include "../../core/cerf_emulator.h"
#include "../../host/panel_frame_renderer.h"
#include "../../lcd/panel_scanout.h"
#include "../board_context.h"

#include <optional>

namespace {

constexpr size_t kContentProbeStride = 251;

class CasioCassiopeiaE55Renderer : public PanelFrameRenderer {
public:
    using PanelFrameRenderer::PanelFrameRenderer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::CasioCassiopeiaE55;
    }

    void PresentedSize(uint32_t& w, uint32_t& h) override {
        auto& lcd = emu_.Get<CasioCassiopeiaE55Lcd>();
        w = lcd.GuestW();
        h = lcd.GuestH();
    }

    bool HasFrame() override {
        auto& lcd = emu_.Get<CasioCassiopeiaE55Lcd>();
        lcd.MaybePublishDisplaySize();
        if (!lcd.IsDisplayEnabled()) return false;
        if (latch_.Latched())         return true;
        return latch_.ProbeAndLatch(lcd.FbBytes(), lcd.FbSize(), kContentProbeStride);
    }

    void RenderInto(uint32_t* dib, uint32_t host_w, uint32_t host_h) override {
        auto& lcd = emu_.Get<CasioCassiopeiaE55Lcd>();
        const PanelSurface src{.fb     = lcd.FbBytes(),
                               .stride = lcd.StrideBytes(),
                               .width  = lcd.GuestW(),
                               .height = lcd.GuestH()};
        scanout_.Blit(src, dib, host_w, host_h);
    }

    std::optional<FbLayout> GetFbLayout() override {
        auto& lcd = emu_.Get<CasioCassiopeiaE55Lcd>();
        return FbLayout{lcd.FbPa(), lcd.StrideBytes(), CasioCassiopeiaE55Lcd::kBpp, false};
    }

private:
    /* casio_cassiopeia_e55 ddi.dll sub_14F1A94 stores sub_14F4DBC into a2[0]; sub_14F4DBC walks
       *(a2+12) pels along the octant at *(a2+28). Its 2bpp mask (2 << (bpp+31))-1 is 3 and its
       shift (idx*bpp) ^ (8-bpp) puts pixel 0 at bits 7:6; its op table runs in ROP2 order, so
       case 1's 0 is black and case 16's ~0 is white. */
    PanelScanout scanout_{PanelPixelFormat::kGray2Msb};
};

}  /* namespace */

REGISTER_SERVICE_AS(CasioCassiopeiaE55Renderer, PanelFrameRenderer);
