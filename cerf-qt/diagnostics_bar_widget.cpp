#include "bar_widget_source.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/machine_diagnostics_channel.h>

#include <cstdio>
#include <iterator>
#include <memory>
#include <string>

namespace cerffrontend {

namespace {

constexpr std::size_t kSignalsPerGroup = 32;

uint64_t Failures(const cerfcore::ChannelCounters& c) {
    return c.unsupported + c.invalid + c.unavailable + c.malformed;
}

class DiagnosticsBarWidget final : public BarWidget {
public:
    explicit DiagnosticsBarWidget(cerfcore::MachineDiagnosticsChannel& channel) : channel_(channel) {}

    std::string Name() const override { return channel_.ObjectName(); }
    BarGroup    Group() const override { return BarGroup::Debug; }

    BarIcon Icon() const override {
        const bool rejected = Failures(channel_.Counters()) > dismissed_;
        return ResourceIcon{rejected ? "ilp_diagnostics_rejected" : "ilp_diagnostics"};
    }

    std::string Tooltip() const override {
        const cerfcore::ChannelCounters c = channel_.Counters();
        return "ILP messages: received " + std::to_string(c.received) + ", sent " + std::to_string(c.sent) +
               "; Outcomes: accepted " + std::to_string(c.accepted) + ", unsupported " +
               std::to_string(c.unsupported) + ", invalid " + std::to_string(c.invalid) + ", unavailable " +
               std::to_string(c.unavailable) + ", malformed " + std::to_string(c.malformed);
    }

    std::vector<MenuItem> Menu() override {
        std::vector<MenuItem> items{MenuItem::Info(Tooltip())};
        const uint64_t        failures = Failures(channel_.Counters());
        MenuItem dismiss = MenuItem::Action("Dismiss rejection indicator", [this, failures] { dismissed_ = failures; });
        dismiss.enabled  = failures > dismissed_;
        items.push_back(std::move(dismiss));
        const std::vector<cerfcore::ChannelSignal> signals = channel_.Signals();
        for (std::size_t start = 0; start < signals.size(); start += kSignalsPerGroup) {
            std::vector<MenuItem> group;
            for (std::size_t i = start; i < start + kSignalsPerGroup && i < signals.size(); ++i) {
                char text[96];
                if (signals[i].reported)
                    std::snprintf(text, sizeof(text), "0x%08X = %llu", signals[i].id,
                                  static_cast<unsigned long long>(signals[i].value));
                else
                    std::snprintf(text, sizeof(text), "0x%08X: Not reported", signals[i].id);
                group.push_back(MenuItem::Info(text));
            }
            items.push_back(MenuItem::Submenu("Status signals " + std::to_string(start + 1), std::move(group)));
        }
        return items;
    }

    uint64_t RxCount() const override { return channel_.RxCount(); }
    uint64_t TxCount() const override { return channel_.TxCount(); }

private:
    cerfcore::MachineDiagnosticsChannel& channel_;
    uint64_t                             dismissed_ = 0;
};

class DiagnosticsBarWidgetSource final : public BarWidgetSource {
public:
    using BarWidgetSource::BarWidgetSource;

protected:
    std::unique_ptr<BarWidget> Create(cerfcore::MachineObject& object) override {
        auto* channel = dynamic_cast<cerfcore::MachineDiagnosticsChannel*>(&object);
        if (!channel) return nullptr;
        return std::make_unique<DiagnosticsBarWidget>(*channel);
    }
};

}

REGISTER_SERVICE(DiagnosticsBarWidgetSource);

}
