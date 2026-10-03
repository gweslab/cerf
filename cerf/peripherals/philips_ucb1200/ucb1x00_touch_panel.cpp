#include "ucb1x00_touch_panel.h"

#include "ucb1x00_codec.h"

#include "../../boards/board_context.h"
#include "../../boards/philips_nino_300/philips_nino_300_id.h"
#include "../../boards/philips_velo_1/philips_velo_1_id.h"
#include "../../boards/sharp_mobilon_hc4100/sharp_mobilon_hc4100_id.h"
#include "../../boards/simpad_sl4/simpad_sl4_id.h"
#include "../../core/cerf_emulator.h"

bool Ucb1x00TouchPanel::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd) return false;
    const std::string_view b = bd->GetBoardId();
    return b == BoardId::PhilipsNino300 || b == BoardId::PhilipsVelo1 ||
           b == BoardId::SharpMobilonHc4100 || b == BoardId::SimpadSl4;
}

void Ucb1x00TouchPanel::OnPenDown(int x, int y) { SetPen(true, x, y); }

void Ucb1x00TouchPanel::OnPenMove(int x, int y) {
    if (Down()) SetPen(true, x, y);
}

void Ucb1x00TouchPanel::OnPenUp(int x, int y) { SetPen(false, x, y); }

void Ucb1x00TouchPanel::OnCaptureLost() { SetPen(false, 0, 0); }

bool Ucb1x00TouchPanel::Down() { return emu_.Get<Ucb1x00Codec>().PenDown(); }

void Ucb1x00TouchPanel::SetPen(bool down, int x, int y) {
    x_.store(x, std::memory_order_relaxed);
    y_.store(y, std::memory_order_relaxed);
    emu_.Get<Ucb1x00Codec>().SetTouchPressed(down);
}

REGISTER_SERVICE_AS(Ucb1x00TouchPanel, TouchInput);
