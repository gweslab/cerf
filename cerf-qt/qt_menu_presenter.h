#pragma once

#include "widget_menu_model.h"

#include <cerfcore/core/instance_gate.h>
#include <cerfcore/core/service.h>

#include <QPointF>
#include <QVariantList>

#include <functional>
#include <map>
#include <vector>

class QObject;

class QtMenuPresenter : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void                  Show(const std::vector<cerffrontend::MenuItem>& items, QPointF at);
    QVariantList          Build(const QObject* menu, const std::vector<cerffrontend::MenuItem>& items);
    std::function<void()> Action(const QObject* menu, int id) const;

private:
    using Actions = std::vector<std::function<void()>>;

    QVariantList Model(Actions& actions, const std::vector<cerffrontend::MenuItem>& items);

    const cerfcore::InstanceGate      gate_{emu_};
    std::map<const QObject*, Actions> actions_;
};
