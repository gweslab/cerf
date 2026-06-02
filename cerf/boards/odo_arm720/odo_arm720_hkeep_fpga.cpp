#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../host/host_widget.h"
#include "../../host/host_widget_registry.h"
#include "../../peripherals/peripheral_dispatcher.h"

#include <cstdint>
#include <cstdio>
#include <mutex>
#include <string>

namespace {

/* INT720.C:55 RMWs LED_DISCRETE every 1ms — reads MUST return
   last-written value. LED_ALPHA mirrors 64KB per P2DEBUG.H:135;
   DEBUG.C:184 trips it via wIndex*4 & 0xFFFF. */

constexpr uint32_t kHkeepFpgaPaBase   = 0x04040000u;
constexpr uint32_t kHkeepFpgaSize     = 0x00030000u;

constexpr uint32_t kLedDiscretePa     = 0x04040000u;  /* P2DEBUG.H line 133 */
constexpr uint32_t kLedAlphaPa        = 0x04060000u;  /* P2DEBUG.H line 134 */
constexpr uint32_t kLedAlphaMirror    = 0x0000FFFFu;  /* P2DEBUG.H line 135 */

class OdoArm720HkeepFpga : public Peripheral, public HostWidget {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OdoArm720;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<HostWidgetRegistry>().Register(this);
    }

    uint32_t MmioBase() const override { return kHkeepFpgaPaBase; }
    uint32_t MmioSize() const override { return kHkeepFpgaSize; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    /* HostWidget. The icon IS the LED — the discrete LED register lights it,
       the 4-char alpha display shows in the tooltip. No RX/TX. */
    std::wstring WidgetName() const override { return L"Debug LED"; }
    WidgetGroup  Group() const override { return WidgetGroup::Indicator; }
    std::wstring Tooltip() const override;
    void DrawIcon(HDC dc, const RECT& box) const override;
    bool PollDirty() override;

private:
    /* Returns true and *out_is_alpha if addr resolves to a known
       LED register. False otherwise. */
    bool ClassifyAddr(uint32_t addr, bool* out_is_alpha) const;

    /* Decode + log alpha-LED write as 4-char ASCII (the kernel
       writes 7-segment-style ASCII codes; CFWP2.C OEMInit's
       0xECEEECEE prints as ".ECEE" backwards = "EECE." or similar
       7-segment pattern depending on hardware decoding). */
    void LogAlphaWrite(uint32_t addr, uint32_t value);

    mutable std::mutex state_mutex_;
    uint32_t           led_discrete_value_ = 0;
    uint32_t           led_alpha_value_    = 0;

    /* UI-thread only: last values the widget drew, so PollDirty repaints only
       on change. Init to impossible so the first poll always repaints. */
    uint32_t last_drawn_discrete_ = ~0u;
    uint32_t last_drawn_alpha_    = ~0u;
};

bool OdoArm720HkeepFpga::ClassifyAddr(uint32_t addr, bool* out_is_alpha) const {
    if (addr == kLedDiscretePa) {
        *out_is_alpha = false;
        return true;
    }
    /* Alpha mirror: LED_ALPHA + (offset & LED_ALPHA_MIRROR).
       Any DWORD-aligned address in [LED_ALPHA, LED_ALPHA + 0xFFFF]
       hits the single alpha register. */
    if (addr >= kLedAlphaPa && addr <= kLedAlphaPa + kLedAlphaMirror) {
        *out_is_alpha = true;
        return true;
    }
    return false;
}

uint32_t OdoArm720HkeepFpga::ReadWord(uint32_t addr) {
    bool is_alpha = false;
    if (!ClassifyAddr(addr, &is_alpha)) {
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    uint32_t value;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        value = is_alpha ? led_alpha_value_ : led_discrete_value_;
    }

#if CERF_DEV_MODE
    /* LED_DISCRETE reads can fire at ~1 kHz when the timer ISR
       is running (INT720.C line 55 read-modify-write). Per
       agent_docs/rules.md § "Simple LOG verbose lines",
       high-frequency LOG sites must not ship in production. */
    LOG(Board, "Odo HKEEP %s read  [0x%08X] -> 0x%08X\n",
        is_alpha ? "LED_ALPHA" : "LED_DISCRETE", addr, value);
#endif
    return value;
}

void OdoArm720HkeepFpga::WriteWord(uint32_t addr, uint32_t value) {
    bool is_alpha = false;
    if (!ClassifyAddr(addr, &is_alpha)) {
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (is_alpha) led_alpha_value_    = value;
        else          led_discrete_value_ = value;
    }

    if (is_alpha) {
        LogAlphaWrite(addr, value);
    } else {
#if CERF_DEV_MODE
        /* Same 1 kHz consideration as the read path. */
        LOG(Board, "Odo HKEEP LED_DISCRETE = 0x%08X\n", value);
#endif
    }
}

void OdoArm720HkeepFpga::LogAlphaWrite(uint32_t addr, uint32_t value) {
    /* LED_ALPHA writes are LOW-frequency on this build path
       (boot stub WhereAmI, OEMInit's 0xECEEECEE, and the very
       rare OEMWriteDebugLED-triggered prints). Permanent LOG is
       acceptable — these are major boot landmarks. */
    char as_ascii[5] = {
        static_cast<char>((value      ) & 0xFFu),
        static_cast<char>((value >>  8) & 0xFFu),
        static_cast<char>((value >> 16) & 0xFFu),
        static_cast<char>((value >> 24) & 0xFFu),
        0,
    };
    auto sanitize = [](char c) -> char {
        return (c >= 0x20 && c < 0x7F) ? c : '.';
    };
    /* DEBUG.C line 184 derives the index from
       `(wIndex * sizeof(ULONG)) & LED_ALPHA_MIRROR`. Showing the
       byte offset so a future reader can recover wIndex (= byte
       offset / 4) for diagnostic correlation. */
    const uint32_t offset = addr - kLedAlphaPa;
    LOG(Board, "Odo HKEEP LED_ALPHA +0x%04X = 0x%08X (\"%c%c%c%c\")\n",
        offset, value,
        sanitize(as_ascii[0]),
        sanitize(as_ascii[1]),
        sanitize(as_ascii[2]),
        sanitize(as_ascii[3]));
}

std::wstring OdoArm720HkeepFpga::Tooltip() const {
    uint32_t discrete, alpha;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        discrete = led_discrete_value_;
        alpha    = led_alpha_value_;
    }
    auto sane = [](uint32_t v, int shift) -> wchar_t {
        const wchar_t c = (wchar_t)((v >> shift) & 0xFFu);
        return (c >= 0x20 && c < 0x7F) ? c : L'.';
    };
    wchar_t buf[64];
    swprintf_s(buf, L"Debug LED  '%c%c%c%c'  discrete=0x%08X",
               sane(alpha, 0), sane(alpha, 8), sane(alpha, 16), sane(alpha, 24),
               discrete);
    return buf;
}

void OdoArm720HkeepFpga::DrawIcon(HDC dc, const RECT& box) const {
    uint32_t discrete;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        discrete = led_discrete_value_;
    }
    /* LED_DISCRETE is an 8-bit counter the kernel timer ISR increments each
       tick (INT720.C:55: `LED_DISCRETE = (LED_DISCRETE + 1) & 0xFF`); the real
       board wires its 8 bits to 8 discrete LEDs, so render them as a binary
       counter (MSB top-left .. LSB bottom-right). */
    const uint8_t bits = (uint8_t)(discrete & 0xFFu);
    constexpr int kCell = 4, kGap = 1;
    const int grid_w = 4 * kCell + 3 * kGap;
    const int grid_h = 2 * kCell + 1 * kGap;
    const int x0 = (box.left + box.right) / 2 - grid_w / 2;
    const int y0 = (box.top + box.bottom) / 2 - grid_h / 2;

    HPEN    pen = CreatePen(PS_SOLID, 1, RGB(90, 75, 40));
    HGDIOBJ op  = SelectObject(dc, pen);
    for (int i = 0; i < 8; ++i) {
        const bool on  = ((bits >> (7 - i)) & 1u) != 0u;
        const int  col = i % 4;
        const int  row = i / 4;
        const int  x   = x0 + col * (kCell + kGap);
        const int  y   = y0 + row * (kCell + kGap);
        HBRUSH  fill = CreateSolidBrush(on ? RGB(255, 180, 40) : RGB(60, 50, 30));
        HGDIOBJ ob   = SelectObject(dc, fill);
        Rectangle(dc, x, y, x + kCell, y + kCell);
        SelectObject(dc, ob);
        DeleteObject(fill);
    }
    SelectObject(dc, op);
    DeleteObject(pen);
}

bool OdoArm720HkeepFpga::PollDirty() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (led_discrete_value_ == last_drawn_discrete_ &&
        led_alpha_value_    == last_drawn_alpha_) {
        return false;
    }
    last_drawn_discrete_ = led_discrete_value_;
    last_drawn_alpha_    = led_alpha_value_;
    return true;
}

}  /* namespace */

REGISTER_SERVICE(OdoArm720HkeepFpga);
