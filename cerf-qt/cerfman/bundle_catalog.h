#pragma once

#include "manager_qml_engine.h"
#include "remote_manifest.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QPair>
#include <QString>
#include <QtQml/qqmlregistration.h>

#include <optional>
#include <vector>

class BundleCatalog : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(bool loading READ Loading NOTIFY loadingChanged)
    Q_PROPERTY(QString loadingLabel READ LoadingLabel CONSTANT)

public:
    struct RepoError {
        QString url;
        QString error;
    };
    using AbuseContact = QPair<QString, std::optional<QString>>;

    explicit BundleCatalog(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static BundleCatalog* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<BundleCatalog>(qml);
    }

    void OnReady() override;

    bool    Loading() const { return loading_; }
    QString LoadingLabel() const;

    Q_INVOKABLE void Refresh(bool report_all_failed);
    Q_INVOKABLE bool RefuseWhileLoading();

    const std::vector<RemoteBundle>&     Bundles() const { return bundles_; }
    const RemoteBundle*                  Find(const QString& repo_url, const QString& name) const;
    const std::optional<DownloadPlaces>& Places() const { return places_; }
    std::vector<AbuseContact>            AbuseContacts() const;

signals:
    void loadingChanged();
    void refreshed();
    void message(const QString& title, const QString& text);
    void status(const QString& text);

private:
    struct RepoResult {
        QString                                url;
        RemoteManifest                         manifest;
        std::optional<ManifestVersionMismatch> mismatch;
        QString                                error;
        bool                                   ok = false;
        DownloadPlaces                         places;
        bool                                   places_ok = false;
    };
    struct Fetch {
        std::vector<RepoResult> repos;
        int                     pending           = 0;
        bool                    report_all_failed = false;
    };

    void FetchRepo(const std::shared_ptr<Fetch>& fetch, size_t index);
    void Settle(const std::shared_ptr<Fetch>& fetch);
    void Finish(const Fetch& fetch);
    void Apply(const Fetch& fetch);
    void RunPendingRefresh();
    void SetLoading(bool loading);

    bool                          loading_ = false;
    std::optional<bool>           pending_report_all_failed_;
    std::vector<RemoteBundle>     bundles_;
    std::vector<RepoError>        repo_errors_;
    QMap<QString, QString>        abuse_emails_;
    std::optional<DownloadPlaces> places_;
};
