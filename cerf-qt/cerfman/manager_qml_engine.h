#pragma once

#include <cerfcore/core/cerf_emulator.h>

#include <QJSEngine>
#include <QQmlApplicationEngine>

class ManagerQmlEngine : public QQmlApplicationEngine {
    Q_OBJECT

public:
    explicit ManagerQmlEngine(cerfcore::CerfEmulator& emu) : emu_(emu) {}

    template <class T>
    static T* Singleton(QQmlEngine* engine) {
        T& service = EmulatorOf(engine).Get<T>();
        QJSEngine::setObjectOwnership(&service, QJSEngine::CppOwnership);
        return &service;
    }

private:
    static cerfcore::CerfEmulator& EmulatorOf(QQmlEngine* engine);

    cerfcore::CerfEmulator& emu_;
};
