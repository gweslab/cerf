#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QtQml/qqmlregistration.h>

class DesktopShell : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit DesktopShell(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static DesktopShell* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<DesktopShell>(qml);
    }

    Q_INVOKABLE QString OpenPath(const QString& path) const;
    Q_INVOKABLE bool    OpenLink(const QString& link) const;
};
