#include "serial_modem_card_menu.h"

#include "../../core/cerf_emulator.h"
#include "../../host/host_link_opener.h"
#include "../../host/ui_language.h"

#include <utility>

namespace {

constexpr const wchar_t* kGettingOnlineUrl = L"https://cerf.cx/getting-online";

}

REGISTER_SERVICE(SerialModemCardMenu);

std::vector<WidgetMenuItem> SerialModemCardMenu::BuildInsertMenu(
    std::function<void()> on_insert) {
    std::vector<WidgetMenuItem> items;

    WidgetMenuItem insert;
    insert.label    = emu_.Get<UiLanguage>().Text("pcmcia.insert");
    insert.on_click = std::move(on_insert);
    items.push_back(std::move(insert));

    items.push_back({});

    WidgetMenuItem tutorial;
    tutorial.label    = emu_.Get<UiLanguage>().Text("pcmcia.getting_online_help");
    tutorial.on_click = [this] {
        emu_.Get<HostLinkOpener>().Open(nullptr, kGettingOnlineUrl);
    };
    items.push_back(std::move(tutorial));

    return items;
}
