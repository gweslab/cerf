#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QUrl>
#include <QtQml/qqmlregistration.h>

class ShaderImport : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(bool folderImport READ FolderImport CONSTANT)

public:
    explicit ShaderImport(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static ShaderImport* create(QQmlEngine* qml, QJSEngine*) { return ManagerQmlEngine::Singleton<ShaderImport>(qml); }

    bool FolderImport() const;

    Q_INVOKABLE void ImportArchive(const QUrl& url);
    Q_INVOKABLE void ImportFolder(const QUrl& url);
};
