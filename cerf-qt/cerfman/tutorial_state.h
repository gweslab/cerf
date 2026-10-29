#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QtQml/qqmlregistration.h>

class TutorialState : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(bool finished READ Finished NOTIFY changed)

public:
    explicit TutorialState(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static TutorialState* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<TutorialState>(qml);
    }

    bool Finished() const;

    Q_INVOKABLE QString Finish();

signals:
    void changed();
};
