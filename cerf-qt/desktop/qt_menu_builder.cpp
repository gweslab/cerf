#include "qt_menu_builder.h"
#include "qt_menu_item_text.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QAction>
#include <QActionGroup>
#include <QMenu>
#include <QPoint>
#include <QTimer>

REGISTER_SERVICE(QtMenuBuilder);

void QtMenuBuilder::Append(QMenu* menu, const std::vector<cerffrontend::MenuItem>& items,
                           Callbacks& out) {
    QActionGroup* radio_group = nullptr;
    for (const cerffrontend::MenuItem& it : items) {
        if (it.label.empty()) {
            menu->addSeparator();
            continue;
        }
        const QString label = MenuItemText(it.label);
        if (!it.submenu.empty()) {
            QMenu* sub = menu->addMenu(label);
            sub->setEnabled(it.enabled);
            Append(sub, it.submenu, out);
            continue;
        }
        QAction* action = menu->addAction(label);
        action->setEnabled(it.enabled && it.on_click);
        if (it.checked) {
            action->setCheckable(true);
            action->setChecked(true);
            if (it.radio) {
                if (!radio_group) radio_group = new QActionGroup(menu);
                radio_group->addAction(action);
            }
        }
        if (it.on_click && it.enabled) out.emplace_back(action, it.on_click);
    }
}

void QtMenuBuilder::Populate(QMenu* menu, const std::vector<cerffrontend::MenuItem>& items) {
    menu->clear();
    Callbacks callbacks;
    Append(menu, items, callbacks);
    for (auto& [action, callback] : callbacks)
        QObject::connect(action, &QAction::triggered, menu, gate_.Bind([cb = callback] { cb(); }));
}

void QtMenuBuilder::Bind(QMenu* menu, MenuSource source) {
    const auto refill = [this, menu, source = std::move(source)] { Populate(menu, source(emu_)); };
    QObject::connect(menu, &QMenu::aboutToShow, menu, gate_.Bind(refill));
    QTimer::singleShot(0, menu, gate_.Bind(refill));
}

void QtMenuBuilder::RunContextMenu(const std::vector<cerffrontend::MenuItem>& items,
                                   const QPoint& global) {
    QMenu     menu;
    Callbacks callbacks;
    Append(&menu, items, callbacks);
    QAction* chosen = menu.exec(global);
    if (!chosen) return;
    for (auto& [action, callback] : callbacks) {
        if (action != chosen) continue;
        gate_.Run([&callback](cerfcore::CerfEmulator&) { callback(); });
        return;
    }
}
