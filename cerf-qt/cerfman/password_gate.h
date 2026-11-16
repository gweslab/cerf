#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QPointer>
#include <QString>
#include <QWindow>
#include <QtQml/qqmlregistration.h>

#include <functional>

class PasswordGate : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

public:
    explicit PasswordGate(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static PasswordGate* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<PasswordGate>(qml);
    }

    bool Locked() const;
    void GuardCerfman(std::function<void()> passed, std::function<void()> refused);

    Q_INVOKABLE QString LogoSource() const;
    Q_INVOKABLE bool    Submit(const QString& password);
    Q_INVOKABLE void    Closed();
    Q_INVOKABLE void    Relock(QWindow* cerfman);

private:
    void Open(bool dismissable);

    std::function<void()> passed_;
    std::function<void()> refused_;
    QPointer<QWindow>     window_;
};
