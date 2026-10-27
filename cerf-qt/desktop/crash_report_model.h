#pragma once

#include "../cerfman/manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QtQml/qqmlregistration.h>

class CrashReportModel : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(QString logPath READ LogPath CONSTANT)
    Q_PROPERTY(QString crashLogPath READ CrashLogPath CONSTANT)

public:
    explicit CrashReportModel(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static CrashReportModel* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<CrashReportModel>(qml);
    }

    int Run(int argc, char** argv);

    QString LogPath() const;
    QString CrashLogPath() const;

    Q_INVOKABLE QString DumpText() const;
    Q_INVOKABLE QString SizeLabel(const QString& path) const;
    Q_INVOKABLE bool    Exists(const QString& path) const;
    Q_INVOKABLE QString ShowFile(const QString& path) const;

private:
    QString log_path_;
};
