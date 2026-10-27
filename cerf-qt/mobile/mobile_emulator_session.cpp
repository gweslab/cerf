#include "mobile_emulator_session.h"

#include "mobile_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>
#include "../executable_names_text.h"
#include "../main_config.h"

MobileEmulatorSession::MobileEmulatorSession(QString device, const QStringList& args,
                                             std::function<void()> on_finished)
    : device_(std::move(device)), on_finished_(std::move(on_finished)) {
    arg_storage_.emplace_back(CERF_FRONTEND_NAME);
    for (const QString& arg : args) arg_storage_.push_back(arg.toStdString());
    for (std::string& arg : arg_storage_) argv_.push_back(arg.data());
    argv_.push_back(nullptr);
    cerffrontend::ParseCerfArgs(static_cast<int>(arg_storage_.size()), argv_.data(), config_);
}

void MobileEmulatorSession::Boot() {
    LOG(Manager, "MobileEmulatorSession: starting %s\n", qUtf8Printable(device_));
    run_ = std::make_unique<QtEmulatorRun>(config_, static_cast<int>(arg_storage_.size()), argv_.data(),
                                           [this] { Finish(); });
    run_->BootInBackground([](cerfcore::CerfEmulator& emu) { emu.Get<MobileEmulatorWindow>().OpenWindow(); });
}

void MobileEmulatorSession::Raise() {
    if (!run_) return;
    if (cerfcore::CerfEmulator* emu = run_->OpenEmulator()) emu->Get<MobileEmulatorWindow>().Raise();
}

void MobileEmulatorSession::Finish() {
    run_->Stop();
    LOG(Manager, "MobileEmulatorSession: %s stopped\n", qUtf8Printable(device_));
    on_finished_();
}
