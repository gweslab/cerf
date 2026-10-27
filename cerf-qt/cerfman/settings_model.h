#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QVariantList>
#include <QtQml/qqmlregistration.h>

#include <cstdint>
#include <vector>

class SettingsModel : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit SettingsModel(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static SettingsModel* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<SettingsModel>(qml);
    }

    Q_INVOKABLE QVariantList HostKeyVks() const;
    Q_INVOKABLE QVariantList ResetHostKeyVks() const;
    Q_INVOKABLE QString      UpdateChannel() const;
    Q_INVOKABLE int          DefaultScale() const;
    Q_INVOKABLE bool         DiscordRichPresence() const;
    Q_INVOKABLE QVariantList ChannelValues() const;
    Q_INVOKABLE QString      ChannelLabel(const QString& channel) const;
    Q_INVOKABLE QString      ChannelHint(const QString& channel) const;
    Q_INVOKABLE QVariantList ScaleValues() const;
    Q_INVOKABLE QString      ScaleLabel(int value) const;
    Q_INVOKABLE QString      Save(const QVariantList& host_key, const QString& channel, int scale,
                                  bool discord);

signals:
    void updateChannelChanged();

private:
    struct ChannelText {
        const char* label;
        const char* hint;
    };

    std::vector<uint8_t> ResetVks() const;
    ChannelText          TextOf(const QString& channel) const;
};
