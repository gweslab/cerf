#define NOMINMAX

#include "mediaq_mq1188.h"

#include "../mediaq_ge/mediaq_panel_renderer.h"
#include "../../boards/board_context.h"
#include "../../boards/falcon_pc3xx/falcon_4220_id.h"

namespace {

class MediaQMq1188Renderer : public MediaQPanelRenderer<MediaQMq1188> {
public:
    using MediaQPanelRenderer<MediaQMq1188>::MediaQPanelRenderer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Falcon4220;
    }
};

}

REGISTER_SERVICE_AS(MediaQMq1188Renderer, PanelFrameRenderer);
