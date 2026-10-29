#include "cerf_updates.h"

#include "cerf_release.h"
#include "cerf_upgrade_session.h"
#include "flow_reply.h"
#include "host_branch_table.h"
#include "http_client.h"
#include "manager_engine.h"
#include "object_url.h"
#include "process_watch.h"
#include "self_upgrade.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/fatal.h>
#include <cerfcore/core/instance_threads.h>
#include <cerfcore/core/log.h>
#include <cerfcore/platform/host_process.h>
#include "../frontend_config.h"
#include "../product_links.h"

#include <QUrl>
#include <QVariant>

REGISTER_SERVICE(CerfUpdates);

CerfUpdates::CerfUpdates(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}

CerfUpdates::~CerfUpdates() = default;

void CerfUpdates::OnShutdown() { session_.reset(); }

void CerfUpdates::SetStatus(const QString& status) {
    status_ = status;
    emit changed();
}

void CerfUpdates::Check() {
    const int generation = ++generation_;
    release_.reset();
    auto&             config  = emu_.Get<cerffrontend::FrontendConfig>();
    const std::string channel = config.UpdateChannel();
    if (channel == cerffrontend::FrontendConfig::kUpdateChannelDisabled) {
        SetStatus(QString());
        return;
    }
    const QString branch   = QString::fromStdString(config.HostBranch());
    const bool    unstable = channel == cerffrontend::FrontendConfig::kUpdateChannelUnstable;
    const QUrl    url(unstable ? ObjectUrl(QString::fromLatin1(host_branch_table::kCiBaseUrl),
                                           QString::fromLatin1(host_branch_table::kLatestName))
                               : QString::fromLatin1(cerffrontend::kStableReleaseApiUrl.text));
    const HttpClient::Headers headers = unstable ? HttpClient::Headers() : HttpClient::GitHubApiHeaders();
    SetStatus(QStringLiteral("Checking updates…"));
    emu_.Get<HttpClient>().Get(url, headers, this,
                               [this, generation, unstable, branch](const QByteArray& body, const QString& error) {
                                   if (generation != generation_) return;
                                   if (!error.isEmpty()) {
                                       LOG(Manager, "update check failed: %s\n", qUtf8Printable(error));
                                       SetStatus(QString());
                                       return;
                                   }
                                   QString parse_error;
                                   const std::optional<CerfRelease> release =
                                       unstable ? ParseCiBuild(body, branch, parse_error)
                                                : ParseStableRelease(body, branch, parse_error);
                                   if (!parse_error.isEmpty())
                                       LOG(Manager, "update check: %s\n", qUtf8Printable(parse_error));
                                   Apply(release);
                               });
}

void CerfUpdates::Apply(const std::optional<CerfRelease>& release) {
    if (!release || !IsNewerVersion(release->tag)) {
        SetStatus(QString());
        return;
    }
    release_ = release;
    SetStatus(QStringLiteral("CERF %1 is available").arg(release->tag));
    if (SelfUpgradeSupported()) emit offerReady();
}

QVariantMap CerfUpdates::Offer() const {
    const bool    upgradable = SelfUpgradeSupported();
    const QString product    = QString::fromUtf8(cerffrontend::kProductName);
    return QVariantMap{
        {QStringLiteral("title"), QStringLiteral("Update available - %1").arg(product)},
        {QStringLiteral("message"),
         upgradable ? QStringLiteral("%1 %2 is available. Would you like to upgrade?").arg(product, release_->tag)
                    : QStringLiteral("%1 %2 is available.").arg(product, release_->tag)},
        {QStringLiteral("upgradable"), upgradable},
        {QStringLiteral("tag"), release_->tag},
        {QStringLiteral("body"), release_->body},
        {QStringLiteral("htmlUrl"), release_->html_url},
        {QStringLiteral("warningUrl"), QString::fromUtf8(cerffrontend::kHibernationWarningUrl.text)}};
}

QVariantMap CerfUpdates::RunningCheck() const {
    const QString         self = QString::fromStdString(cerfcore::host_platform::ExecutablePath());
    std::vector<uint32_t> pids;
    QString               error;
    if (!ProcessesRunningImage(self, pids, error))
        return QVariantMap{{QStringLiteral("title"), QStringLiteral("Process check failed")},
                           {QStringLiteral("message"), error}};
    if (pids.empty()) return {};
    return QVariantMap{{QStringLiteral("title"), QStringLiteral("The emulator is running")},
                       {QStringLiteral("message"),
                        QStringLiteral("%1 is running and its files cannot be replaced while it is.\n\nClose every "
                                       "emulator window, then retry.")
                            .arg(QString::fromUtf8(cerffrontend::kProductName))}};
}

QVariantMap CerfUpdates::Upgrade() {
    if (!release_)
        return FlowError(QStringLiteral("Upgrade unavailable"),
                         QStringLiteral("The update check started again. Try again when it ends."));
    if (session_ && !session_->Closed())
        return FlowError(QStringLiteral("Upgrade in progress"),
                         QStringLiteral("An upgrade is already running. Wait until its window closes."));
    session_.reset();
    session_ = std::make_unique<CerfUpgradeSession>(*release_, emu_.Get<HttpClient>().UserAgent());
    emu_.Get<cerfcore::Fatal>().Guard([this] {
        emu_.Get<ManagerEngine>().Open(QString::fromLatin1(UpgradeSession::kWindowType), session_->WindowProperties());
        session_->Start(emu_.Get<cerfcore::InstanceThreads>());
    });
    return {};
}
