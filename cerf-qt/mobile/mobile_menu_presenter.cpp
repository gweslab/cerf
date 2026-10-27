#include "mobile_menu_presenter.h"

#include "mobile_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QMetaObject>
#include <QQuickWindow>
#include <QString>
#include <QVariantMap>

REGISTER_SERVICE(MobileMenuPresenter);

QVariantList MobileMenuPresenter::Model(const std::vector<cerffrontend::MenuItem>& items) {
    QVariantList model;
    for (const cerffrontend::MenuItem& item : items) {
        QVariantMap entry;
        entry.insert(QStringLiteral("separator"), item.label.empty());
        entry.insert(QStringLiteral("text"), QString::fromStdString(item.label));
        entry.insert(QStringLiteral("enabled"), item.enabled);
        entry.insert(QStringLiteral("checked"), item.checked);
        entry.insert(QStringLiteral("checkable"), item.checkable);
        entry.insert(QStringLiteral("radio"), item.radio);
        entry.insert(QStringLiteral("submenu"), Model(item.submenu));
        int id = -1;
        if (item.on_click && item.enabled && item.submenu.empty()) {
            id = static_cast<int>(actions_.size());
            actions_.push_back(item.on_click);
        }
        entry.insert(QStringLiteral("id"), id);
        model.append(entry);
    }
    return model;
}

void MobileMenuPresenter::Show(const std::vector<cerffrontend::MenuItem>& items, QPointF at) {
    actions_.clear();
    const QVariantList model  = Model(items);
    QQuickWindow*      window = emu_.Get<MobileEmulatorWindow>().Window();
    QMetaObject::invokeMethod(window, "showMenu", Q_ARG(QVariant, model), Q_ARG(QVariant, at.x()),
                              Q_ARG(QVariant, at.y()));
}

void MobileMenuPresenter::Pick(int id) {
    const std::function<void()> action = actions_[static_cast<size_t>(id)];
    action();
}
