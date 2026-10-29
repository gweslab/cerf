#include "../cerfman/emulator_launcher.h"

#include "../cerfman/crash_report_model.h"
#include "../cerfman/device_actions.h"
#include "../cerfman/flow_reply.h"
#include "mobile_emulator_session.h"

#include <cerfcore/core/cerf_config.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>

#include <QCoreApplication>
#include <QMetaObject>
#include <QObject>
#include <QPermissions>

#include <map>
#include <memory>

namespace {

class MobileEmulatorLauncher : public EmulatorLauncher {
public:
    using EmulatorLauncher::EmulatorLauncher;

    void OnShutdown() override { sessions_.clear(); }

    QVariantMap Launch(const QString& name, const QStringList& args, bool confirmed) override {
        if (const auto running = sessions_.find(name); running != sessions_.end()) {
            running->second->Raise();
            return {};
        }
        if (!sessions_.empty() && !confirmed) return Confirmation(name);
        QStringList session_args = args;
        session_args.append(QString::fromLatin1(cerfcore::kArgTab) + QString::fromLatin1(cerfcore::kTabBoot));
        sessions_.emplace(name, std::make_unique<MobileEmulatorSession>(name, session_args, FinishHandler(name)));
        const QMicrophonePermission microphone;
        if (qApp->checkPermission(microphone) == Qt::PermissionStatus::Undetermined)
            qApp->requestPermission(microphone, &context_, [this, name](const QPermission&) { Boot(name); });
        else
            Boot(name);
        return Started(name);
    }

private:
    MobileEmulatorSession::FinishFn FinishHandler(const QString& name) {
        return [this, name](std::optional<int> halt, const std::string& crash_log_path) {
            QMetaObject::invokeMethod(&context_, [this, name] { sessions_.erase(name); }, Qt::QueuedConnection);
            if (halt == cerfcore::CERF_FATAL_RUNTIME_ERROR) emu_.Get<CrashReportModel>().Open(crash_log_path);
        };
    }

    void Boot(const QString& name) {
        if (const auto session = sessions_.find(name); session != sessions_.end()) session->second->Boot();
    }

    QVariantMap Confirmation(const QString& name) {
        const QString message =
            QStringLiteral("You are already running one device. If the memory runs out or the app crashes - all "
                           "running devices will stop too.\nLaunch %1?")
                .arg(emu_.Get<DeviceActions>().DisplayName(name));
        return QVariantMap{
            {QStringLiteral("confirm"), FlowMessage(QStringLiteral("Device is running"), message)}};
    }

    QObject                                                   context_;
    std::map<QString, std::unique_ptr<MobileEmulatorSession>> sessions_;
};

}

REGISTER_SERVICE_AS(MobileEmulatorLauncher, EmulatorLauncher);
