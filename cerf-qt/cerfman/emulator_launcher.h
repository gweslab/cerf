#pragma once

#include <cerfcore/core/service.h>

#include <QString>
#include <QStringList>
#include <QVariantMap>

class EmulatorLauncher : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static QVariantMap StartedReply(const QString& name);

    virtual QVariantMap Launch(const QString& name, const QStringList& args, bool confirmed) = 0;
};
