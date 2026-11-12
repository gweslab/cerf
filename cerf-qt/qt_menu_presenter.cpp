#include "qt_menu_presenter.h"

#include "qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QMetaObject>
#include <QObject>
#include <QQuickWindow>
#include <QString>
#include <QVariantMap>

REGISTER_SERVICE(QtMenuPresenter);

QVariantList QtMenuPresenter::Model(Actions& actions, const std::vector<cerffrontend::MenuItem>& items) {
    QVariantList model;
    for (const cerffrontend::MenuItem& item : items) {
        QVariantMap entry;
        entry.insert(QStringLiteral("separator"), item.label.empty());
        entry.insert(QStringLiteral("text"), QString::fromStdString(item.label));
        entry.insert(QStringLiteral("icon"), QString::fromStdString(item.icon));
        entry.insert(QStringLiteral("role"), static_cast<int>(item.role));
        entry.insert(QStringLiteral("row"), Model(actions, item.row));
        entry.insert(QStringLiteral("enabled"), item.enabled);
        entry.insert(QStringLiteral("checked"), item.checked);
        entry.insert(QStringLiteral("checkable"), item.checkable);
        entry.insert(QStringLiteral("radio"), item.radio);
        entry.insert(QStringLiteral("submenu"), Model(actions, item.submenu));
        int id = -1;
        if (item.on_click && item.enabled && item.submenu.empty()) {
            id = static_cast<int>(actions.size());
            actions.push_back(item.on_click);
        }
        entry.insert(QStringLiteral("id"), id);
        model.append(entry);
    }
    return model;
}

QVariantList QtMenuPresenter::Build(const QObject* menu, const std::vector<cerffrontend::MenuItem>& items) {
    if (menu != nullptr && actions_.find(menu) == actions_.end())
        QObject::connect(menu, &QObject::destroyed, gate_.Bind([this, menu] { actions_.erase(menu); }));
    Actions& actions = actions_[menu];
    actions.clear();
    return Model(actions, items);
}

void QtMenuPresenter::Show(const std::vector<cerffrontend::MenuItem>& items, QPointF at) {
    if (items.empty()) return;
    const QVariantList model  = Build(nullptr, items);
    QQuickWindow*      window = emu_.Get<QtEmulatorWindow>().Window();
    QMetaObject::invokeMethod(window, "showMenu", Q_ARG(QVariant, model), Q_ARG(QVariant, at.x()),
                              Q_ARG(QVariant, at.y()));
}

std::function<void()> QtMenuPresenter::Action(const QObject* menu, int id) const {
    return actions_.at(menu)[static_cast<size_t>(id)];
}
