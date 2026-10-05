#include "../../host/touch_input.h"

#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../peripherals/wolfson_wm9705/wm9705_codec.h"
#include "../board_context.h"
#include "falcon_4220_id.h"

#include <algorithm>
#include <cstdint>

namespace {

/* falcon_4220__4_10 nk.exe sub_800F33D4 (OSMR1 branch) reads the word at 0xA3CC3000: 1 raises SYSINTR
   18, anything else marks pen up and raises SYSINTR 24. */
constexpr uint32_t kCpldPenState = 0xA3CC3000u;

class FalconTouchInput : public TouchInput {
public:
    using TouchInput::TouchInput;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Falcon4220;
    }

    void OnReady() override {
        codec_ = &emu_.Get<Wm9705Codec>();
        codec_->SetPenLineObserver([this](bool down) {
            emu_.Get<PeripheralDispatcher>().WriteWord(kCpldPenState, down ? 1u : 0u);
        });
    }

    void OnPenDown(int x, int y) override {
        SetPosition(x, y);
        codec_->QueuePenEdge(true);
    }
    void OnPenMove(int x, int y) override { SetPosition(x, y); }
    void OnPenUp(int x, int y) override {
        SetPosition(x, y);
        codec_->QueuePenEdge(false);
    }
    void OnCaptureLost() override { codec_->QueuePenEdge(false); }

private:
    void SetPosition(int x, int y) {
        uint16_t rx = 0, ry = 0;
        RawFromScreen(x, y, rx, ry);
        codec_->SetPenPosition(rx, ry);
    }

    /* Inverse of the PC3xx factory cal (touch.dll TouchPanelCalibrateAPoint:
       out = 4*(M.raw+off)/DIV, in QUARTER-pixels; gwes.exe sub_20FA0 then /4's
       it to the screen pixel). */
    static void RawFromScreen(int sx, int sy, uint16_t& raw_x, uint16_t& raw_y) {
        constexpr int64_t kM0 = 556, kM1 = -23408, kM2 = 85992351;
        constexpr int64_t kM3 = -30734, kM4 = 109, kM5 = 113344548;
        constexpr int64_t kDiv = 331292;
        constexpr int64_t kDet = kM0 * kM4 - kM1 * kM3;
        const int64_t bx = static_cast<int64_t>(sx) * kDiv - kM2;
        const int64_t by = static_cast<int64_t>(sy) * kDiv - kM5;
        raw_x = static_cast<uint16_t>(std::clamp<int64_t>((kM4 * bx - kM1 * by) / kDet, 0, 0x0FFF));
        raw_y = static_cast<uint16_t>(std::clamp<int64_t>((kM0 * by - kM3 * bx) / kDet, 0, 0x0FFF));
    }

    Wm9705Codec* codec_ = nullptr;
};

}  // namespace

REGISTER_SERVICE_AS(FalconTouchInput, TouchInput);
