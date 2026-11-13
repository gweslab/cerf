#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QHash>
#include <QObject>
#include <QPointer>
#include <QString>
#include <QWindow>
#include <QtQml/qqmlregistration.h>

class WindowRegistry : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit WindowRegistry(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static WindowRegistry* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<WindowRegistry>(qml);
    }

    Q_INVOKABLE QWindow* Raise(const QString& key);
    Q_INVOKABLE void     Track(const QString& key, QWindow* window);

private:
    QHash<QString, QPointer<QWindow>> windows_;
};
