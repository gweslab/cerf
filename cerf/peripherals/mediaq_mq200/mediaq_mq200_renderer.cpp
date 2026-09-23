#define NOMINMAX

#include "mediaq_mq200.h"

#include "../mediaq_ge/mediaq_panel_renderer.h"
#include "../../boards/board_context.h"
#include "../../boards/simpad_sl4/simpad_sl4_id.h"
#include "../../boards/smartbook_g138/smartbook_g138_id.h"

namespace {

class MediaQMq200Renderer : public MediaQPanelRenderer<MediaQMq200> {
public:
    using MediaQPanelRenderer<MediaQMq200>::MediaQPanelRenderer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd) return false;
        const std::string_view b = bd->GetBoardId();
        return b == BoardId::SimpadSl4 || b == BoardId::SmartbookG138;
    }
};

}

REGISTER_SERVICE_AS(MediaQMq200Renderer, PanelFrameRenderer);
