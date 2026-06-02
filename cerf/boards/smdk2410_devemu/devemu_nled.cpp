#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/host_widget.h"
#include "../../host/host_widget_registry.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../board_detector.h"

#include <array>
#include <cstdint>
#include <mutex>
#include <string>

namespace {

constexpr uint32_t kBase = 0x500FFFD0u;
constexpr uint32_t kSize = 0x00000006u;
constexpr uint32_t kNumLeds      = 2u;
constexpr uint32_t kBytesPerLed  = 3u;

constexpr uint32_t kFieldOnOffBlink = 0u;
constexpr uint32_t kFieldOnTime     = 1u;
constexpr uint32_t kFieldOffTime    = 2u;

/* OnOffBlink encoding, NLEDDRVR/snled.cpp:33. LED 0 is the notification light,
   LED 1 is the vibrate motor (snled.cpp:46-67). OnTime/OffTime are in units of
   100 ms (snled.cpp:34-35), which is exactly the status-bar tick, so blink can
   animate at the real cadence. */
constexpr uint8_t kOff   = 0u;
constexpr uint8_t kOn     = 1u;
constexpr uint8_t kBlink  = 2u;

/* Fallback blink cadence (ticks on / off) when the driver set blink but left
   the timing fields at zero. */
constexpr uint32_t kDefaultBlinkTicks = 5u;  /* 500 ms */

const COLORREF kClrLit  = RGB(78, 201, 90);
const COLORREF kClrDark = RGB(50, 55, 50);

class DevEmuNotificationLed : public Peripheral, public HostWidget {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::Smdk2410DevEmu;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<HostWidgetRegistry>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint8_t ReadByte (uint32_t addr) override;
    void    WriteByte(uint32_t addr, uint8_t value) override;

    /* HostWidget. The icon IS the LED state; no data path -> no RX/TX. */
    std::wstring WidgetName() const override { return L"Notification LED"; }
    WidgetGroup  Group() const override { return WidgetGroup::Indicator; }
    std::wstring Tooltip() const override;
    void DrawIcon(HDC dc, const RECT& box) const override;
    bool PollDirty() override;

private:
    static const char* FieldName(uint32_t led_off);

    mutable std::mutex                            state_mutex_;
    std::array<uint8_t, kNumLeds * kBytesPerLed>  regs_{};

    /* UI-thread only: free-running tick + last-drawn appearance. */
    uint32_t tick_           = 0;
    bool     draw_led0_lit_  = false;
    bool     draw_led0_blink_ = false;
    bool     draw_vibrate_   = false;
};

const char* DevEmuNotificationLed::FieldName(uint32_t led_off) {
    switch (led_off) {
        case kFieldOnOffBlink: return "OnOffBlink";
        case kFieldOnTime:     return "OnTime";
        case kFieldOffTime:    return "OffTime";
        default:               return "?";
    }
}

uint8_t DevEmuNotificationLed::ReadByte(uint32_t addr) {
    const uint32_t off = addr - kBase;
    uint8_t value = 0;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (off >= regs_.size()) {
            HaltUnsupportedAccess("ReadByte", addr, 0);  /* noreturn */
        }
        value = regs_[off];
    }
    const uint32_t led     = off / kBytesPerLed;
    const uint32_t led_off = off % kBytesPerLed;
    LOG(Periph, "[NLED] read8 led=%u %s -> 0x%02X\n",
        led, FieldName(led_off), value);
    return value;
}

void DevEmuNotificationLed::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off     = addr - kBase;
    const uint32_t led     = off / kBytesPerLed;
    const uint32_t led_off = off % kBytesPerLed;
    LOG(Periph, "[NLED] write8 led=%u %s = 0x%02X\n",
        led, FieldName(led_off), value);
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (off >= regs_.size()) {
        HaltUnsupportedAccess("WriteByte", addr, value);  /* noreturn */
    }
    regs_[off] = value;
}

std::wstring DevEmuNotificationLed::Tooltip() const {
    uint8_t mode0, on0, off0, mode1;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        mode0 = regs_[kFieldOnOffBlink];
        on0   = regs_[kFieldOnTime];
        off0  = regs_[kFieldOffTime];
        mode1 = regs_[kBytesPerLed + kFieldOnOffBlink];
    }
    wchar_t buf[128];
    if (mode0 == kBlink) {
        swprintf_s(buf, L"Notification LED: blink (on %ums / off %ums) · Vibrate: %s",
                   (unsigned)on0 * 100u, (unsigned)off0 * 100u,
                   mode1 != kOff ? L"on" : L"off");
    } else {
        swprintf_s(buf, L"Notification LED: %s · Vibrate: %s",
                   mode0 == kOn ? L"on" : L"off",
                   mode1 != kOff ? L"on" : L"off");
    }
    return buf;
}

void DevEmuNotificationLed::DrawIcon(HDC dc, const RECT& box) const {
    const int cx = (box.left + box.right) / 2;
    const int cy = (box.top + box.bottom) / 2;
    constexpr int r = 5;

    /* Vibrate motion chevrons flanking the dot. */
    if (draw_vibrate_) {
        HPEN vp = CreatePen(PS_SOLID, 1, RGB(200, 160, 80));
        HGDIOBJ ov = SelectObject(dc, vp);
        for (int s = 1; s <= 2; ++s) {
            const int xr = cx + r + 1 + s * 2;
            MoveToEx(dc, xr, cy - 3, nullptr); LineTo(dc, xr + 2, cy);
            LineTo(dc, xr, cy + 3);
            const int xl = cx - r - 1 - s * 2;
            MoveToEx(dc, xl, cy - 3, nullptr); LineTo(dc, xl - 2, cy);
            LineTo(dc, xl, cy + 3);
        }
        SelectObject(dc, ov);
        DeleteObject(vp);
    }

    /* Notification LED dot (LED 0). A brighter ring marks blink mode. */
    HBRUSH  fill = CreateSolidBrush(draw_led0_lit_ ? kClrLit : kClrDark);
    HPEN    pen  = CreatePen(PS_SOLID, 1,
                             draw_led0_blink_ ? RGB(120, 230, 130) : RGB(90, 95, 90));
    HGDIOBJ ob = SelectObject(dc, fill);
    HGDIOBJ op = SelectObject(dc, pen);
    Ellipse(dc, cx - r, cy - r, cx + r, cy + r);
    SelectObject(dc, ob);
    SelectObject(dc, op);
    DeleteObject(fill);
    DeleteObject(pen);
}

bool DevEmuNotificationLed::PollDirty() {
    uint8_t mode0, on0, off0, mode1;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        mode0 = regs_[kFieldOnOffBlink];
        on0   = regs_[kFieldOnTime];
        off0  = regs_[kFieldOffTime];
        mode1 = regs_[kBytesPerLed + kFieldOnOffBlink];
    }
    ++tick_;

    bool led0_lit;
    if (mode0 == kBlink) {
        uint32_t on_ticks  = on0;
        uint32_t off_ticks = off0;
        if (on_ticks == 0 && off_ticks == 0) {
            on_ticks = off_ticks = kDefaultBlinkTicks;
        }
        const uint32_t cycle = on_ticks + off_ticks;
        led0_lit = cycle == 0 ? true : (tick_ % cycle) < on_ticks;
    } else {
        led0_lit = mode0 == kOn;
    }
    const bool blink0   = mode0 == kBlink;
    const bool vibrate  = mode1 != kOff;

    if (led0_lit == draw_led0_lit_ && blink0 == draw_led0_blink_ &&
        vibrate == draw_vibrate_) {
        return false;
    }
    draw_led0_lit_   = led0_lit;
    draw_led0_blink_ = blink0;
    draw_vibrate_    = vibrate;
    return true;
}

}  /* namespace */

REGISTER_SERVICE(DevEmuNotificationLed);
