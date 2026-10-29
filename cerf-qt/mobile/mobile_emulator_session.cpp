#include "mobile_emulator_session.h"

#include "mobile_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/instance_gate.h>
#include <cerfcore/core/log.h>
#include "../executable_names_text.h"
#include "../main_config.h"

MobileEmulatorSession::MobileEmulatorSession(QString device, const QStringList& args, FinishFn on_finished)
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

void MobileEmulatorSession::Boot() {
    LOG(Manager, "MobileEmulatorSession: starting %s\n", qUtf8Printable(device_));
    run_ = std::make_unique<QtEmulatorRun>(
        config_, static_cast<int>(arg_storage_.size()), argv_.data(), [this] { Finish(); },
        [](cerfcore::CerfEmulator& emu) { emu.Get<MobileEmulatorWindow>().OnTeardownWedged(); });
    run_->BootInBackground([this](cerfcore::CerfEmulator& emu) {
        auto& window = emu.Get<MobileEmulatorWindow>();
        window.SetWedgedHandler([this] { Abandon(); });
        window.OpenWindow();
    });
}

void MobileEmulatorSession::Raise() {
    if (!run_) return;
    if (cerfcore::CerfEmulator* emu = run_->OpenEmulator())
        cerfcore::InstanceGate(*emu).Run([](cerfcore::CerfEmulator& device) { device.Get<MobileEmulatorWindow>().Raise(); });
}

void MobileEmulatorSession::Finish() {
    const std::optional<int> halt = run_->Halt();
    run_->Stop();
    LOG(Manager, "MobileEmulatorSession: %s stopped\n", qUtf8Printable(device_));
    on_finished_(halt, crash_log_path_);
}

void MobileEmulatorSession::Abandon() {
    const std::optional<int> halt = run_->Halt();
    run_->Abandon();
    static_cast<void>(run_.release());
    LOG(Manager, "MobileEmulatorSession: %s did not stop; its threads stay allocated\n", qUtf8Printable(device_));
    on_finished_(halt, crash_log_path_);
}
