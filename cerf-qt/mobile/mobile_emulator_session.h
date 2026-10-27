#pragma once

#include "../qt_emulator_run.h"

#include <cerfcore/core/cerf_config.h>

#include <QString>
#include <QStringList>

#include <functional>
#include <memory>
#include <string>
#include <vector>

class MobileEmulatorSession {
public:
    MobileEmulatorSession(QString device, const QStringList& args, std::function<void()> on_finished);

    MobileEmulatorSession(const MobileEmulatorSession&)            = delete;
    MobileEmulatorSession& operator=(const MobileEmulatorSession&) = delete;

    void Boot();
    void Raise();

private:
    void Finish();

    QString                        device_;
    std::function<void()>          on_finished_;
    std::vector<std::string>       arg_storage_;
    std::vector<char*>             argv_;
    cerfcore::CerfConfig           config_;
    std::unique_ptr<QtEmulatorRun> run_;
};
