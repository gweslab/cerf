#include "qt_menu_builder.h"
#include "qt_menu_item_text.h"

#include "../tinted_symbol_icon.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QAction>
#include <QActionGroup>
#include <QHBoxLayout>
#include <QIcon>
#include <QMenu>
#include <QPixmap>
#include <QPoint>
#include <QTimer>
#include <QToolButton>
#include <QWidgetAction>

#include <cmath>

REGISTER_SERVICE(QtMenuBuilder);

namespace {

constexpr int kRowIconPx = 20;

}

void QtMenuBuilder::Append(QMenu* menu, const std::vector<cerffrontend::MenuItem>& items,
                           Callbacks& out) {
    QActionGroup* radio_group = nullptr;
    for (const cerffrontend::MenuItem& it : items) {
        if (it.label.empty()) {
            menu->addSeparator();
            continue;
        }
        if (!it.row.empty()) {
            menu->addAction(RowAction(menu, it.row));
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

QWidgetAction* QtMenuBuilder::RowAction(QMenu* menu, const std::vector<cerffrontend::MenuItem>& buttons) {
    auto*        row    = new QWidget;
    auto*        layout = new QHBoxLayout(row);
    const QColor ink    = menu->palette().color(QPalette::Text);
    const qreal  dpr    = menu->devicePixelRatioF();
    const int    side   = static_cast<int>(std::lround(kRowIconPx * dpr));
    row->setAttribute(Qt::WA_ShowWithoutActivating);
    row->setWindowFlag(Qt::WindowDoesNotAcceptFocus);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    for (const cerffrontend::MenuItem& b : buttons) {
        QPixmap icon = QPixmap::fromImage(TintedSymbolIcon(QString::fromStdString(b.icon), QSize(side, side), ink));
        icon.setDevicePixelRatio(dpr);
        auto* button = new QToolButton(row);
        button->setAutoRaise(true);
        button->setIcon(QIcon(icon));
        button->setIconSize(QSize(kRowIconPx, kRowIconPx));
        button->setToolTip(QString::fromStdString(b.label));
        button->setAccessibleName(QString::fromStdString(b.label));
        button->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        button->setEnabled(b.enabled && b.on_click);
        if (b.enabled && b.on_click)
            QObject::connect(button, &QToolButton::clicked, button, gate_.Bind([cb = b.on_click] { cb(); }));
        layout->addWidget(button);
    }
    auto* action = new QWidgetAction(menu);
    action->setDefaultWidget(row);
    return action;
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
