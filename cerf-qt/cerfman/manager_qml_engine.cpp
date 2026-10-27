#include "manager_qml_engine.h"

cerfcore::CerfEmulator& ManagerQmlEngine::EmulatorOf(QQmlEngine* engine) {
    return static_cast<ManagerQmlEngine*>(engine)->emu_;
}
