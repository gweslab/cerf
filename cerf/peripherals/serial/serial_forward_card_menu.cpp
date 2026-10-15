#include "serial_forward_card_menu.h"

#include "host_serial_ports.h"

#include "../../core/cerf_emulator.h"
#include "../../host/host_link_opener.h"
#include "../../host/ui_language.h"

#include <utility>

namespace {

constexpr const wchar_t* kActiveSyncUrl = L"https://cerf.cx/activesync";

}

REGISTER_SERVICE(SerialForwardCardMenu);

std::vector<WidgetMenuItem> SerialForwardCardMenu::BuildInsertMenu(
    std::function<void(std::wstring host_port)> on_insert) {
    std::vector<WidgetMenuItem> items;

    const std::vector<std::wstring> ports = emu_.Get<HostSerialPorts>().Enumerate();
    if (ports.empty()) {
        WidgetMenuItem none;
        none.label   = emu_.Get<UiLanguage>().Text("pcmcia.no_serial_ports");
        none.enabled = false;
        items.push_back(std::move(none));
    } else {
        for (const std::wstring& p : ports) {
            WidgetMenuItem it;
            it.label    = p;
            it.on_click = [on_insert, p] { on_insert(p); };
            items.push_back(std::move(it));
        }
    }

    items.push_back({});

    WidgetMenuItem tutorial;
    tutorial.label    = emu_.Get<UiLanguage>().Text("pcmcia.activesync_help");
    tutorial.on_click = [this] {
        emu_.Get<HostLinkOpener>().Open(nullptr, kActiveSyncUrl);
    };
    items.push_back(std::move(tutorial));

    return items;
}
