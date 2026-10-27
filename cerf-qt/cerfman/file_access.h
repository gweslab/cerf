#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QUrl>
#include <QtQml/qqmlregistration.h>

class FileAccess : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit FileAccess(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static FileAccess* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<FileAccess>(qml);
    }

    Q_INVOKABLE QString LocalPath(const QUrl& url) const;
    Q_INVOKABLE QUrl    FileUrl(const QString& value, const QString& base_dir) const;
    Q_INVOKABLE QUrl    BrowseFolder(const QString& value, const QString& base_dir) const;
    Q_INVOKABLE QString PickedValue(const QString& path, const QString& base_dir) const;
    Q_INVOKABLE QString DisplayText(const QString& value) const;
};
