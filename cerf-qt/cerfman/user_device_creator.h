#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

class UserDeviceCreator : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit UserDeviceCreator(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static UserDeviceCreator* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<UserDeviceCreator>(qml);
    }

    Q_INVOKABLE QString NameProblem(const QString& name) const;
    Q_INVOKABLE QString SuggestedName(const QString& board_name) const;
    Q_INVOKABLE void    Start(const QString& name, const QString& board_id, const QVariantMap& files, bool copy);

signals:
    void created(const QString& name);
};
