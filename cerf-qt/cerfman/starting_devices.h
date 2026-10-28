#pragma once

#include <cerfcore/core/service.h>

#include <QElapsedTimer>
#include <QHash>
#include <QObject>
#include <QString>

class StartingDevices : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void Mark(const QString& name);
    bool Pending(const QString& name) const;

private:
    QHash<QString, QElapsedTimer> started_;
    QObject                       context_;
};
