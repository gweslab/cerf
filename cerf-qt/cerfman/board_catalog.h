#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/board_database.h>
#include <cerfcore/core/service.h>

#include <QObject>
#include <QSize>
#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

#include <optional>
#include <string_view>
#include <vector>

class BoardCatalog : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit BoardCatalog(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static BoardCatalog* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<BoardCatalog>(qml);
    }

    static int NameTier(const QString& board_name);

    const cerfcore::DbBoard*         Find(const QString& board_id) const;
    std::optional<QSize>             PanelSize(const QString& board_id) const;
    std::optional<cerfcore::CpuArch> Arch(const QString& board_id) const;
    QString                          ArchName(const QString& board_id) const;
    bool                             Runs(const QString& board_id) const;
    bool                             FeatureAllowed(const QString& board_id, std::string_view feature_id) const;
    QString                          MountPointDefault() const;
    QString                          FamilyName(const QString& board_id) const;
    QString                          SocLabel(const QString& board_id) const;
    QStringList                      Notes(const QString& board_id) const;
    QVariantMap                      GroupHardware(const QStringList& board_ids) const;
    bool                             ConfigurableScreen(const QString& board_id) const;
    int                              GaColorDepth(const QString& board_id) const;
    int                              DeviceYear(const QString& board_id) const;

    std::vector<const cerfcore::DbDeviceFeature*> UnsupportedFeatures(const QString& board_id) const;

    Q_INVOKABLE QString      DisplayName(const QString& board_id) const;
    Q_INVOKABLE QString      BoardLabel(const QString& board_id, const QString& empty_text) const;
    Q_INVOKABLE QVariantMap  SupportWarning(const QString& board_id) const;
    Q_INVOKABLE QString      FirstRunningBoard() const;
    Q_INVOKABLE QVariantList GroupedBoards(bool show_unsupported, bool show_unknown,
                                           const QString& query) const;

private:
    std::optional<bool> FeatureSupport(const QString& board_id, std::string_view feature_id) const;
};
