#pragma once

#include "../qt_emulator_run.h"

#include <cerfcore/core/cerf_config.h>

#include <QString>
#include <QStringList>

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

class MobileEmulatorSession {
public:
    using FinishFn = std::function<void(std::optional<int> halt, const std::string& crash_log_path)>;

    MobileEmulatorSession(QString device, const QStringList& args, FinishFn on_finished);

    MobileEmulatorSession(const MobileEmulatorSession&)            = delete;
    MobileEmulatorSession& operator=(const MobileEmulatorSession&) = delete;

    void Boot();
    void Raise();

private:
    void Finish();
    void Abandon();

    QString                        device_;
    FinishFn                       on_finished_;
    std::vector<std::string>       arg_storage_;
    std::vector<char*>             argv_;
    std::string                    crash_log_path_;
    cerfcore::CerfConfig           config_;
    std::unique_ptr<QtEmulatorRun> run_;
};
