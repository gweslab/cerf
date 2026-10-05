#include "../../host/touch_input.h"

#include "../../core/cerf_emulator.h"
#include "../../host/host_canvas.h"
#include "../../peripherals/wolfson_wm9713/wm9713_codec.h"
#include "../../socs/pxa27x/pxa27x_gpio.h"
#include "../board_context.h"
#include "symbol_mk500_id.h"

#include <algorithm>
#include <cmath>
#include <cstdint>

namespace {

/* WM9713L datasheet (Cirrus Logic, Rev 4.0) page 122, register 7Ah bits 11:0
   ADCD "Touchpanel ADC Data (Read-only) Bit 0 = LSB, Bit 11 = MSB"; symbol_mk500
   touch.dll FUN_022379ac @0x022379ac keeps those bits as the channel value. */
constexpr long kAdcMax = 0x0FFF;

constexpr uint32_t kGpioPenDown = 101u;

class SymbolMk500TouchInput : public TouchInput {
public:
    using TouchInput::TouchInput;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SymbolMk500;
    }

    void OnReady() override {
        codec_ = &emu_.Get<Wm9713Codec>();
        gpio_  = &emu_.Get<Pxa27xGpio>();
        gpio_->SetInputLevel(kGpioPenDown, true);
        codec_->SetPenLineObserver([this](bool down) { gpio_->SetInputLevel(kGpioPenDown, !down); });
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
        auto&      hc = emu_.Get<HostCanvas>();
        const long w  = static_cast<long>(hc.GuestSurfaceWidth());
        const long h  = static_cast<long>(hc.GuestSurfaceHeight());
        codec_->SetPenPosition(Scale(x, w), Scale(y, h));
    }

    static uint16_t Scale(int pos, long span) {
        if (span <= 1) return 0u;
        const long v = std::lround(static_cast<double>(pos) * kAdcMax / (span - 1));
        return static_cast<uint16_t>(std::clamp<long>(v, 0, kAdcMax));
    }

    Wm9713Codec* codec_ = nullptr;
    Pxa27xGpio*  gpio_  = nullptr;
};

}  // namespace

REGISTER_SERVICE_AS(SymbolMk500TouchInput, TouchInput);
