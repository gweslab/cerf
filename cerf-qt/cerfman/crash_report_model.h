#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QtQml/qqmlregistration.h>

#include <string>

class CrashReportModel : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(QString logPath READ LogPath CONSTANT)

public:
    explicit CrashReportModel(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static CrashReportModel* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<CrashReportModel>(qml);
    }

    void Open(const std::string& crash_log_path);

    QString LogPath() const;

    Q_INVOKABLE QString DumpText(const QString& crash_log_path) const;
    Q_INVOKABLE QString SizeLabel(const QString& path) const;
    Q_INVOKABLE bool    Exists(const QString& path) const;
    Q_INVOKABLE QString ShowFile(const QString& path) const;
};
