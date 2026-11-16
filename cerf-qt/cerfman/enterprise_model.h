#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QVariantList>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

class EnterpriseModel : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit EnterpriseModel(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static EnterpriseModel* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<EnterpriseModel>(qml);
    }

    Q_INVOKABLE bool         Allowed() const;
    Q_INVOKABLE bool         Enabled() const;
    Q_INVOKABLE bool         Kiosk() const;
    Q_INVOKABLE QString      Password() const;
    Q_INVOKABLE int          MinPasswordLength() const;
    Q_INVOKABLE QString      Device() const;
    Q_INVOKABLE QString      Splash() const;
    Q_INVOKABLE QVariantList SplashValues() const;
    Q_INVOKABLE QString      SplashLabel(const QString& value) const;
    Q_INVOKABLE QString      LogoPath() const;
    Q_INVOKABLE QString      LogoFolder() const;
    Q_INVOKABLE QVariantList ShutdownActions() const;
    Q_INVOKABLE QString      Problem(const QVariantMap& values) const;
    Q_INVOKABLE QString      Save(const QVariantMap& values);
};
