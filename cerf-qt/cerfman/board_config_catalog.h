#pragma once

#include "json_file.h"
#include "manager_qml_engine.h"

#include <cerfcore/core/board_database.h>
#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QVariant>
#include <QVariantList>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

#include <span>
#include <utility>
#include <vector>

class BoardConfigCatalog : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit BoardConfigCatalog(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static BoardConfigCatalog* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<BoardConfigCatalog>(qml);
    }

    Q_INVOKABLE QVariantList Params(const QString& board_id) const;
    Q_INVOKABLE QVariantMap  Values(const QString& board_id, const QVariantMap& set) const;
    Q_INVOKABLE QString      ValueLabel(const QString& board_id, const QString& param_id, const QVariant& value) const;

    Json                                     Diff(const QString& board_id, const QVariantMap& set,
                                                  const QVariantMap& base) const;
    std::vector<std::pair<QString, QString>> Rows(const QString& board_id, const QVariantMap& set) const;

private:
    std::span<const cerfcore::DbBoardConfigSetting> SettingsFor(const QString& board_id) const;
    const cerfcore::DbBoardConfigSetting*           Setting(const QString& board_id, const QString& param_id) const;
};
