#pragma once

#include "cerf_release.h"
#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

#include <memory>
#include <optional>

class CerfUpgradeSession;

class CerfUpdates : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(QString status READ Status NOTIFY changed)
    Q_PROPERTY(bool available READ Available NOTIFY changed)

public:
    explicit CerfUpdates(cerfcore::CerfEmulator& emu);
    ~CerfUpdates() override;
    static CerfUpdates* create(QQmlEngine* qml, QJSEngine*) { return ManagerQmlEngine::Singleton<CerfUpdates>(qml); }

    void OnShutdown() override;

    QString Status() const { return status_; }
    bool    Available() const { return release_.has_value(); }

    Q_INVOKABLE void        Check();
    Q_INVOKABLE QVariantMap Offer() const;
    Q_INVOKABLE QVariantMap RunningCheck() const;
    Q_INVOKABLE QVariantMap Upgrade();

signals:
    void changed();
    void offerReady();

private:
    void SetStatus(const QString& status);
    void Apply(const std::optional<CerfRelease>& release);

    QString                             status_;
    std::optional<CerfRelease>          release_;
    int                                 generation_ = 0;
    std::unique_ptr<CerfUpgradeSession> session_;
};
