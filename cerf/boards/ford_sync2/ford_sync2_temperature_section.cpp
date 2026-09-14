#include "ford_sync2_temperature_section.h"

#include "ford_sync2_ambient_temperature.h"
#include "ford_sync2_ilp_channel.h"
#include "../../core/cerf_emulator.h"
#include "../../state/state_stream.h"
#include <cwchar>

std::wstring TemperatureSection::Label() const {
    const auto snapshot = emu_.Get<FordSync2AmbientTemperature>().Read();
    if (!snapshot.available) return L"Outside temperature: Not reported";
    if (!snapshot.half_celsius) return L"Outside temperature: No reading";
    wchar_t text[64];
    if (imperial_) {
        const double fahrenheit = *snapshot.half_celsius * 0.9 + 32.0;
        std::swprintf(text, std::size(text), L"Outside temperature: %.1f \u00b0F", fahrenheit);
    } else {
        std::swprintf(text, std::size(text), L"Outside temperature: %.1f \u00b0C", *snapshot.half_celsius * 0.5);
    }
    return text;
}

std::vector<WidgetMenuItem> TemperatureSection::BuildItems() {
    /* EA5T-14D544-BA.sec, VNIGeneralSvc.dll sub_C1595D40, Fahrenheit table C15AA340. */
    constexpr int16_t celsius[] = {-40, -30, -20, -10, -5, 0, 5, 10, 15, 20, 25, 30, 35, 40, 50};
    constexpr int16_t fahrenheit[] = {-40, -22, -4, 14, 23, 32, 41, 50, 59, 68, 77, 86, 95, 104, 122};
    const auto snapshot = emu_.Get<FordSync2AmbientTemperature>().Read();
    std::vector<WidgetMenuItem> items;
    for (std::size_t i = 0; i < std::size(celsius); ++i) {
        const int16_t half = celsius[i] * 2;
        WidgetMenuItem item;
        item.label = std::to_wstring(imperial_ ? fahrenheit[i] : celsius[i]) + (imperial_ ? L" °F" : L" °C");
        item.checked = snapshot.available && snapshot.half_celsius == half;
        item.on_click = [this, half] {
            emu_.Get<FordSync2IlpChannel>().ApplyHostChange([&] { emu_.Get<FordSync2AmbientTemperature>().Set(half); });
        };
        items.push_back(std::move(item));
    }
    WidgetMenuItem invalid;
    invalid.label = L"No reading";
    invalid.checked = snapshot.available && !snapshot.half_celsius;
    invalid.on_click = [this] {
        emu_.Get<FordSync2IlpChannel>().ApplyHostChange([&] { emu_.Get<FordSync2AmbientTemperature>().Set(std::nullopt); });
    };
    items.push_back(std::move(invalid));
    WidgetMenuItem clear;
    clear.label = L"Stop reporting outside temperature";
    clear.checked = !snapshot.available;
    clear.on_click = [this] {
        emu_.Get<FordSync2IlpChannel>().ApplyHostChange([&] { emu_.Get<FordSync2AmbientTemperature>().Clear(); });
    };
    items.push_back(std::move(clear));
    WidgetMenuItem units;
    units.label = L"Show presets in °F";
    units.checked = imperial_;
    units.on_click = [this] { imperial_ = !imperial_; };
    items.push_back(std::move(units));
    return items;
}

bool TemperatureSection::PollDirty() {
    const auto revision = emu_.Get<FordSync2AmbientTemperature>().Read().revision;
    if (revision == last_revision_) return false;
    last_revision_ = revision;
    return true;
}

void TemperatureSection::SaveState(StateWriter& w) const { w.Write<uint8_t>(imperial_); }
void TemperatureSection::RestoreState(StateReader& r) {
    uint8_t imperial = 0; r.Read(imperial); imperial_ = imperial != 0;
}
