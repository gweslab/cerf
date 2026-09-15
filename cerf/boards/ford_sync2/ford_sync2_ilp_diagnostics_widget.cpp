#include "ford_sync2_ilp_channel.h"
#include "ford_sync2_ilp_signals.h"
#include "../board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../host/host_widget.h"
#include "../../host/host_widget_registry.h"
#include "../../host/host_icon_cache.h"
#include <cwchar>

namespace {
class FordSync2IlpDiagnosticsWidget : public Service, public HostWidget {
public:
    using Service::Service;
    bool ShouldRegister() override {
        auto* board = emu_.TryGet<BoardContext>();
        return board && board->GetBoard() == Board::FordSyncGen2;
    }
    void OnReady() override { emu_.Get<HostWidgetRegistry>().Register(this); }
    std::wstring WidgetName() const override { return L"ILP diagnostics"; }
    WidgetGroup Group() const override { return WidgetGroup::Debug; }
    bool PrimaryActionOpensMenu() const override { return true; }
    /* Latch the rejection badge after unsupported, invalid, unavailable or malformed
       requests. Dismissal acknowledges the menu's captured failure count without
       clearing counters; any later failure lights the badge again. */
    void DrawIcon(HDC dc, const RECT& box) const override {
        const bool rejected = Failures(emu_.Get<FordSync2IlpChannel>().ReadCounters()) > dismissed_failures_;
        emu_.Get<HostIconCache>().DrawCentered(dc, box,
            rejected ? L"ICON_ILP_DIAGNOSTICS_REJECTED" : L"ICON_ILP_DIAGNOSTICS");
    }
    std::wstring Tooltip() const override {
        const auto c = emu_.Get<FordSync2IlpChannel>().ReadCounters();
        return L"ILP messages: received " + std::to_wstring(c.received) + L", sent " + std::to_wstring(c.sent) +
            L"; Outcomes: accepted " + std::to_wstring(c.accepted) + L", unsupported " +
            std::to_wstring(c.unsupported) + L", invalid " + std::to_wstring(c.invalid) +
            L", unavailable " + std::to_wstring(c.unavailable) + L", malformed " + std::to_wstring(c.malformed);
    }
    bool PollDirty() override {
        const auto counters = emu_.Get<FordSync2IlpChannel>().ReadCounters();
        if (counters.received != last_received_) MarkRx();
        if (counters.sent != last_sent_) MarkTx();
        last_received_ = counters.received;
        last_sent_ = counters.sent;
        auto current = Tooltip();
        if (current == last_tooltip_) return false;
        last_tooltip_ = std::move(current);
        return true;
    }
    std::vector<WidgetMenuItem> BuildMenu() override {
        WidgetMenuItem counters;
        counters.label = Tooltip(); counters.enabled = false;
        std::vector<WidgetMenuItem> items{std::move(counters)};
        const auto failures = Failures(emu_.Get<FordSync2IlpChannel>().ReadCounters());
        WidgetMenuItem dismiss;
        dismiss.label = L"Dismiss rejection indicator";
        dismiss.enabled = failures > dismissed_failures_;
        dismiss.on_click = [this, failures] {
            dismissed_failures_ = failures;
            last_tooltip_.clear();
        };
        items.push_back(std::move(dismiss));
        auto& signals = emu_.Get<FordSync2IlpSignals>();
        for (std::size_t start = 0; start < signals.GroundedSignalCount(); start += 32) {
            WidgetMenuItem group;
            group.label = L"Status signals " + std::to_wstring(start + 1);
            for (std::size_t i = start; i < start + 32 && i < signals.GroundedSignalCount(); ++i) {
                const auto id = signals.GroundedSignalIdAt(i);
                wchar_t text[96];
                if (signals.IsReported(id)) std::swprintf(text, std::size(text), L"0x%08X = %llu", id,
                    static_cast<unsigned long long>(signals.ReportedValue(id)));
                else std::swprintf(text, std::size(text), L"0x%08X: Not reported", id);
                WidgetMenuItem item; item.label = text; item.enabled = false;
                group.submenu.push_back(std::move(item));
            }
            items.push_back(std::move(group));
        }
        return items;
    }
private:
    static uint64_t Failures(const FordSync2IlpChannel::Counters& counters) {
        return counters.unsupported + counters.invalid + counters.unavailable + counters.malformed;
    }
    std::wstring last_tooltip_;
    uint64_t last_received_ = 0, last_sent_ = 0, dismissed_failures_ = 0;
};
REGISTER_SERVICE(FordSync2IlpDiagnosticsWidget);
}
