#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/cpu_config_database.h>
#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QVariant>
#include <QVariantList>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

#include <utility>
#include <vector>

class CpuConfigCatalog : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit CpuConfigCatalog(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static CpuConfigCatalog* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<CpuConfigCatalog>(qml);
    }

    Q_INVOKABLE QVariantList Params(const QString& board_id) const;
    Q_INVOKABLE QVariantList PresetChoices(const QString& board_id) const;
    Q_INVOKABLE QString      PresetChoiceLabel(const QString& board_id, const QVariant& choice) const;
    Q_INVOKABLE QString      ValueLabel(const QString& param_id, const QVariant& value) const;
    Q_INVOKABLE QString      ParamValueLabel(const QString& param_id, const QVariant& default_value,
                                             const QVariant& override_value) const;
    Q_INVOKABLE QVariant     ParseText(const QString& param_id, const QString& text) const;
    Q_INVOKABLE QString      InvalidMessage(const QString& param_id) const;

    std::vector<const cerfcore::CpuConfigParam*> ParamsFor(const QString& board_id) const;
    QVariant    CurrentPreset(const QString& board_id, const QVariantMap& overrides) const;
    QString     PresetLabel(const QString& board_id, const QVariantMap& overrides) const;
    QVariantMap PresetValues(const QString& board_id, int index) const;

    std::vector<std::pair<QString, QString>> OverrideRows(const QString& board_id, const QVariantMap& overrides) const;

private:
    std::vector<const cerfcore::CpuConfigPreset*> PresetsFor(const QString& board_id) const;
    const cerfcore::CpuConfigParam*               Param(const QString& param_id) const;
    QString AutoPresetLabel(const QString& board_id) const;
    int     MatchingPreset(const QString& board_id, const QVariantMap& overrides) const;
    QVariant    ToVariant(const cerfcore::CpuConfigParam& param, const cerfcore::CpuConfigValue& value) const;
    QVariantMap ValuesOf(const QString& board_id, const cerfcore::CpuConfigValues& values) const;
    QVariantMap Defaults(const QString& board_id) const;
};
