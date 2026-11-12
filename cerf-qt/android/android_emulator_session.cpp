#include "android_emulator_session.h"

#include "../qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/instance_gate.h>
#include <cerfcore/core/log.h>
#include "../executable_names_text.h"
#include "../main_config.h"

AndroidEmulatorSession::AndroidEmulatorSession(QString device, const QStringList& args, FinishFn on_finished)
    : device_(std::move(device)),
      on_finished_(std::move(on_finished)),
      crash_log_path_(cerfcore::GetDeviceDir(device_.toStdString()) + cerfcore::kCrashLogFileName) {
    arg_storage_.emplace_back(CERF_FRONTEND_NAME);
    for (const QString& arg : args) arg_storage_.push_back(arg.toStdString());
    for (std::string& arg : arg_storage_) argv_.push_back(arg.data());
    argv_.push_back(nullptr);
    cerffrontend::ParseCerfArgs(static_cast<int>(arg_storage_.size()), argv_.data(), config_);
    config_.crash_log_file = crash_log_path_.c_str();
}

void AndroidEmulatorSession::Boot() {
    LOG(Manager, "AndroidEmulatorSession: starting %s\n", qUtf8Printable(device_));
    run_ = std::make_unique<QtEmulatorRun>(
        config_, static_cast<int>(arg_storage_.size()), argv_.data(), [this] { Finish(); },
        [](cerfcore::CerfEmulator& emu) { emu.Get<QtEmulatorWindow>().OnTeardownWedged(); });
    run_->BootInBackground([this](cerfcore::CerfEmulator& emu) {
        emu.Get<QtEmulatorWindow>().SetWedgedHandler([this] { Abandon(); });
        emu.Get<QtEmulatorWindow>().OpenWindow();
    });
}

void AndroidEmulatorSession::Raise() {
    if (!run_) return;
    if (cerfcore::CerfEmulator* emu = run_->OpenEmulator())
        cerfcore::InstanceGate(*emu).Run([](cerfcore::CerfEmulator& device) { device.Get<QtEmulatorWindow>().Raise(); });
}

void AndroidEmulatorSession::Finish() {
    const std::optional<int> halt = run_->Halt();
    run_->Stop();
    LOG(Manager, "AndroidEmulatorSession: %s stopped\n", qUtf8Printable(device_));
    on_finished_(halt, crash_log_path_);
}

void AndroidEmulatorSession::Abandon() {
    const std::optional<int> halt = run_->Halt();
    run_->Abandon();
    static_cast<void>(run_.release());
    LOG(Manager, "AndroidEmulatorSession: %s did not stop; its threads stay allocated\n", qUtf8Printable(device_));
    on_finished_(halt, crash_log_path_);
}
