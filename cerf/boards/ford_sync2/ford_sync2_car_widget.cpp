#include "../board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/service.h"
#include "../../host/host_icon_cache.h"
#include "../../host/host_widget.h"
#include "../../host/host_widget_registry.h"

namespace {

class FordSync2CarWidget : public Service, public HostWidget {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* board = emu_.TryGet<BoardContext>();
        return board && board->GetBoard() == Board::FordSyncGen2;
    }

    void OnReady() override { emu_.Get<HostWidgetRegistry>().Register(this); }

    std::wstring WidgetName() const override { return L"Car"; }
    WidgetGroup Group() const override { return WidgetGroup::Indicator; }
    std::wstring Tooltip() const override { return L"SYNC 2 car controls"; }
    bool PrimaryActionOpensMenu() const override { return true; }

    void DrawIcon(HDC dc, const RECT& box) const override {
        emu_.Get<HostIconCache>().DrawCentered(dc, box, L"ICON_CAR");
    }

    std::vector<WidgetMenuItem> BuildMenu() override {
        return {
            Section(L"Climate"),
            Section(L"Outside temperature"),
            Section(L"Location"),
            Section(L"Entertainment"),
        };
    }

private:
    static WidgetMenuItem Section(const wchar_t* label) {
        WidgetMenuItem item;
        item.label = label;
        item.enabled = false;
        return item;
    }
};

REGISTER_SERVICE(FordSync2CarWidget);

}
