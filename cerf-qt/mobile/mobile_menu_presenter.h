#pragma once

#include "../widget_menu_model.h"

#include <cerfcore/core/service.h>

#include <QPointF>
#include <QVariantList>

#include <functional>
#include <vector>

class MobileMenuPresenter : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void Show(const std::vector<cerffrontend::MenuItem>& items, QPointF at);
    void Pick(int id);

private:
    QVariantList Model(const std::vector<cerffrontend::MenuItem>& items);

    std::vector<std::function<void()>> actions_;
};
