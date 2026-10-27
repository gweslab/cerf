#pragma once

#include <cerfcore/core/service.h>

#include <QObject>
#include <QPointer>
#include <QString>
#include <QVariantMap>

#include <memory>
#include <vector>

class ManagerQmlEngine;

class ManagerEngine : public cerfcore::Service {
public:
    using cerfcore::Service::Service;
    ~ManagerEngine() override;

    void OnShutdown() override;

    QObject* Open(const QString& type_name, const QVariantMap& properties);

private:
    ManagerQmlEngine& Engine();

    std::unique_ptr<ManagerQmlEngine> engine_;
    std::vector<QPointer<QObject>>    opened_;
};
