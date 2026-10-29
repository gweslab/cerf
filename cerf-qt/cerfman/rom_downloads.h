#pragma once

#include "device_bundle.h"
#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

#include <optional>
#include <vector>

class RomDownloads : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(QString repositoriesUrl READ RepositoriesUrl CONSTANT)
    Q_PROPERTY(QString contactsTitle READ ContactsTitle CONSTANT)

public:
    explicit RomDownloads(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static RomDownloads* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<RomDownloads>(qml);
    }

    QString RepositoriesUrl() const;
    QString ContactsTitle() const;

    Q_INVOKABLE QVariantMap  Catalog(bool show_unsupported, const QString& query, bool by_downloads) const;
    Q_INVOKABLE QString      Summary(const QStringList& keys) const;
    Q_INVOKABLE QString      ContactsText() const;
    Q_INVOKABLE QVariantMap  Plan(const QStringList& keys) const;
    Q_INVOKABLE void         Start(const QStringList& keys);

    Q_INVOKABLE QVariantMap  DevicePlan(const QString& name) const;
    Q_INVOKABLE void         UpdateDevice(const QString& name, bool download);
    Q_INVOKABLE QVariantMap  PackagePlan(const QString& name, const QString& category, const QString& key) const;
    Q_INVOKABLE void         InstallPackage(const QString& name, const QString& category, const QString& key);
    Q_INVOKABLE void         DeletePackage(const QString& name, const QString& category, const QString& key);
    Q_INVOKABLE QVariantMap  UpdateAllPlan() const;
    Q_INVOKABLE void         UpdateAll();

private:
    struct UpdateItem {
        enum class Kind { kRom, kPackage, kConfig };
        Kind   kind;
        size_t device;
        size_t package;
    };
    struct UpdateSelection {
        std::vector<DeviceBundle> devices;
        std::vector<UpdateItem>   items;
        QStringList               running;
    };

    std::vector<DeviceBundle> Candidates() const;
    QVariantList              Thanks(const std::vector<const DeviceBundle*>& devices) const;
    QVariantMap               ThanksPlan(const std::vector<const DeviceBundle*>& devices) const;
    UpdateSelection           SelectUpdates() const;
};
