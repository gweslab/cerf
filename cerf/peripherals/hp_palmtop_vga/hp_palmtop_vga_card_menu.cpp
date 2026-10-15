#include "hp_palmtop_vga_card_menu.h"

#include "hp_palmtop_vga_card.h"
#include "../../core/cerf_emulator.h"
#include "../../host/ui_language.h"

#include <memory>

REGISTER_SERVICE(HpPalmtopVgaCardMenu);

std::vector<WidgetMenuItem> HpPalmtopVgaCardMenu::BuildInsertMenu(
    PcmciaCardCatalog::CardInserter inserter) {
    std::vector<WidgetMenuItem> items;

    auto note = [&items](const wchar_t* text) {
        WidgetMenuItem it;
        it.label   = text;
        it.enabled = false;   /* shown grayed: inline guidance, not clickable */
        items.push_back(std::move(it));
    };
    WidgetMenuItem insert;
    insert.label    = emu_.Get<UiLanguage>().Text("pcmcia.insert");
    insert.on_click = [this, inserter] {
        inserter(std::make_unique<HpPalmtopVgaCard>(emu_));
    };
    items.push_back(std::move(insert));

    items.push_back({});   /* separator */

    note(emu_.Get<UiLanguage>().Text("pcmcia.hp_vga.external_output"));
    note(emu_.Get<UiLanguage>().Text("pcmcia.hp_vga.jornada_support"));
    note(emu_.Get<UiLanguage>().Text("pcmcia.hp_vga.verified_720"));

    return items;
}
