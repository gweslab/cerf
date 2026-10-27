#pragma once

#include "install_options.h"
#include "manager_qml_engine.h"
#include "upgrade_session.h"

#include <cerfcore/core/service.h>

#include <QString>

#include <optional>
#include <thread>

class InstallStageModel : public UpgradeSession, public cerfcore::Service {
    Q_OBJECT

public:
    explicit InstallStageModel(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}

    void OnShutdown() override;

    int                RunInstall(const InstallOptions& options);
    std::optional<int> RunPostUpgrade(const InstallOptions& options);

    void Close() override;

private:
    enum class InstallProgress { kNothingChanged, kCopying, kCopied };

    void Work();
    bool Install(QString& error, InstallProgress& progress);
    bool WaitForPid(QString& error) const;
    void Fail(const QString& title, const QString& message) const;

    InstallOptions options_;
    std::thread    worker_;
    int            exit_code_ = 0;
};
