#pragma once

#include <cerfcore/core/service.h>

#include <QString>
#include <QStringList>
#include <QVariantMap>

class EmulatorLauncher : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    virtual QVariantMap Launch(const QString& name, const QStringList& args, bool confirmed) = 0;

protected:
    QVariantMap Started(const QString& name);
};
