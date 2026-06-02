#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/host_widget.h"
#include "../../host/host_widget_registry.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../board_detector.h"

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace {

constexpr uint32_t kBase = 0x500FFFF0u;
constexpr uint32_t kSize = 0x00000004u;

constexpr uint32_t kRegIsOnBattery   = 0x00u;
constexpr uint32_t kRegChargePercent = 0x01u;
constexpr uint32_t kRegTemperature   = 0x02u;

/* Charge thresholds on the user-facing percent (= 100 - register), matching the
   level banding in BATTDRVR/battif.c:175-180. */
constexpr int kLevelHigh = 65;   /* >= -> HIGH  */
constexpr int kLevelLow  = 20;   /* >= -> LOW, else CRITICAL */

const COLORREF kClrHigh = RGB(78, 201, 90);
const COLORREF kClrLow  = RGB(220, 200, 60);
const COLORREF kClrCrit = RGB(229, 80, 80);

class DevEmuBattery : public Peripheral, public HostWidget {
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

    uint8_t  ReadByte(uint32_t addr) override;
    uint16_t ReadHalf(uint32_t addr) override;

    /* HostWidget. No data path -> no RX/TX; the icon IS the state, and the menu
       is the user's control over the emulated battery (the Device Emulator
       exposes the same controls in its UI). */
    std::wstring WidgetName() const override { return L"Battery"; }
    WidgetGroup  Group() const override { return WidgetGroup::Power; }
    std::wstring Tooltip() const override;
    void DrawIcon(HDC dc, const RECT& box) const override;
    std::vector<WidgetMenuItem> BuildMenu() override;
    bool PollDirty() override;

private:
    /* User-facing fill percent (0..100) the panel shows; the register stores
       its inverse per battif.c:34. */
    int  FillPercent() const;             /* caller need not hold the lock */
    void SetOnBattery(bool on_battery);
    void SetFillPercent(int fill);

    mutable std::mutex state_mutex_;
    uint8_t            is_on_battery_  = 0;   /* battif.c:33 — 0 = AC */
    uint8_t            charge_percent_ = 0;   /* battif.c:34 — 0 = full */
    uint16_t           temperature_    = 0;   /* raw, not interpreted */

    /* UI-thread only: last-drawn state so PollDirty repaints only on change. */
    uint8_t last_drawn_on_battery_ = 0xFF;
    uint8_t last_drawn_charge_     = 0xFF;
};

uint8_t DevEmuBattery::ReadByte(uint32_t addr) {
    const uint32_t off = addr - kBase;
    uint8_t value = 0;
    const char* name = "?";
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        switch (off) {
            case kRegIsOnBattery:
                value = is_on_battery_;
                name  = "IsOnBattery";
                break;
            case kRegChargePercent:
                value = charge_percent_;
                name  = "ChargePercent";
                break;
            default:
                HaltUnsupportedAccess("ReadByte", addr, 0);  /* noreturn */
        }
    }
    LOG(Periph, "[Battery] read8 %s -> 0x%02X\n", name, value);
    return value;
}

uint16_t DevEmuBattery::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - kBase;
    uint16_t value = 0;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        switch (off) {
            case kRegTemperature:
                value = temperature_;
                break;
            default:
                HaltUnsupportedAccess("ReadHalf", addr, 0);  /* noreturn */
        }
    }
    LOG(Periph, "[Battery] read16 Temperature -> 0x%04X\n", value);
    return value;
}

int DevEmuBattery::FillPercent() const {
    std::lock_guard<std::mutex> lk(state_mutex_);
    const int reg = charge_percent_ > 100 ? 100 : charge_percent_;
    return 100 - reg;  /* battif.c:152-155 inversion */
}

void DevEmuBattery::SetOnBattery(bool on_battery) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    is_on_battery_ = on_battery ? 1u : 0u;
}

void DevEmuBattery::SetFillPercent(int fill) {
    if (fill < 0)   fill = 0;
    if (fill > 100) fill = 100;
    std::lock_guard<std::mutex> lk(state_mutex_);
    charge_percent_ = static_cast<uint8_t>(100 - fill);
}

std::wstring DevEmuBattery::Tooltip() const {
    bool on_batt;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        on_batt = is_on_battery_ != 0;
    }
    const int fill = FillPercent();
    const wchar_t* level = fill >= kLevelHigh ? L"High"
                         : fill >= kLevelLow  ? L"Low"
                                              : L"Critical";
    wchar_t buf[96];
    swprintf_s(buf, L"Battery — %s, %d%% (%s)",
               on_batt ? L"on battery" : L"on AC", fill, level);
    return buf;
}

void DevEmuBattery::DrawIcon(HDC dc, const RECT& box) const {
    bool on_batt;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        on_batt = is_on_battery_ != 0;
    }
    const int fill = FillPercent();
    const COLORREF lvl = fill >= kLevelHigh ? kClrHigh
                       : fill >= kLevelLow  ? kClrLow
                                            : kClrCrit;

    const int cx = (box.left + box.right) / 2;
    const int cy = (box.top + box.bottom) / 2;
    constexpr int kBodyW = 18, kBodyH = 11;
    RECT body = { cx - kBodyW / 2, cy - kBodyH / 2,
                  cx + kBodyW / 2, cy + kBodyH / 2 };

    HPEN    pen   = CreatePen(PS_SOLID, 1, RGB(170, 170, 180));
    HBRUSH  dark  = CreateSolidBrush(RGB(30, 32, 38));
    HGDIOBJ op    = SelectObject(dc, pen);
    HGDIOBJ ob    = SelectObject(dc, dark);
    Rectangle(dc, body.left, body.top, body.right, body.bottom);

    /* terminal nub on the right */
    RECT nub = { body.right, cy - 2, body.right + 2, cy + 2 };
    HBRUSH nubfill = CreateSolidBrush(RGB(170, 170, 180));
    FillRect(dc, &nub, nubfill);
    DeleteObject(nubfill);

    /* charge fill, proportional, level-coloured */
    const int inner_w = kBodyW - 2;
    const int fw      = inner_w * fill / 100;
    if (fw > 0) {
        RECT fr = { body.left + 1, body.top + 1, body.left + 1 + fw, body.bottom - 1 };
        HBRUSH fb = CreateSolidBrush(lvl);
        FillRect(dc, &fr, fb);
        DeleteObject(fb);
    }

    /* AC: a small charging bolt overlay */
    if (!on_batt) {
        const POINT bolt[] = {
            { cx,     cy - 5 }, { cx - 3, cy + 1 }, { cx,     cy + 1 },
            { cx - 1, cy + 5 }, { cx + 3, cy - 1 }, { cx,     cy - 1 },
        };
        HBRUSH boltfill = CreateSolidBrush(RGB(120, 220, 255));
        HPEN   boltpen  = CreatePen(PS_SOLID, 1, RGB(40, 60, 80));
        HGDIOBJ pob = SelectObject(dc, boltfill);
        HGDIOBJ pop = SelectObject(dc, boltpen);
        Polygon(dc, bolt, (int)(sizeof(bolt) / sizeof(bolt[0])));
        SelectObject(dc, pob);
        SelectObject(dc, pop);
        DeleteObject(boltfill);
        DeleteObject(boltpen);
    }

    SelectObject(dc, ob);
    SelectObject(dc, op);
    DeleteObject(dark);
    DeleteObject(pen);
}

std::vector<WidgetMenuItem> DevEmuBattery::BuildMenu() {
    bool on_batt;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        on_batt = is_on_battery_ != 0;
    }
    const int fill = FillPercent();

    std::vector<WidgetMenuItem> items;

    WidgetMenuItem ac;
    ac.label    = L"On battery power";
    ac.checked  = on_batt;
    ac.on_click = [this, on_batt] { SetOnBattery(!on_batt); };
    items.push_back(std::move(ac));

    items.push_back(WidgetMenuItem{});  /* separator */

    WidgetMenuItem level;
    level.label = L"Charge level";
    for (int preset : { 100, 80, 60, 40, 20, 5 }) {
        WidgetMenuItem p;
        wchar_t lbl[16];
        swprintf_s(lbl, L"%d%%", preset);
        p.label    = lbl;
        p.checked  = fill == preset;
        p.on_click = [this, preset] { SetFillPercent(preset); };
        level.submenu.push_back(std::move(p));
    }
    items.push_back(std::move(level));

    return items;
}

bool DevEmuBattery::PollDirty() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (is_on_battery_ == last_drawn_on_battery_ &&
        charge_percent_ == last_drawn_charge_) {
        return false;
    }
    last_drawn_on_battery_ = is_on_battery_;
    last_drawn_charge_     = charge_percent_;
    return true;
}

}  /* namespace */

REGISTER_SERVICE(DevEmuBattery);
