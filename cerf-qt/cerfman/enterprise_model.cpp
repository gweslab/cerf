#include "enterprise_model.h"

#include "json_file.h"

#include "../enterprise_config.h"
#include "../frontend_config.h"
#include "../shutdown_policy.h"
#include "../shutdown_prompt.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/product_name.h>

#include <QStringList>

#include <algorithm>
#include <string>
#include <vector>

REGISTER_SERVICE(EnterpriseModel);

namespace {

using cerffrontend::EnterpriseConfig;
using cerffrontend::FrontendConfig;
using cerffrontend::ShutdownAction;
using cerffrontend::ShutdownPolicy;

constexpr char kEnabledField[]  = "enabled";
constexpr char kPasswordField[] = "password";
constexpr char kDeviceField[]   = "device";
constexpr char kSplashField[]   = "splash";
constexpr char kLogoField[]     = "logoPath";
constexpr char kKioskField[]    = "kiosk";
constexpr char kShutdownField[] = "shutdown";
constexpr char kIdField[]       = "id";
constexpr char kLabelField[]    = "label";
constexpr char kCheckedField[]  = "checked";

std::vector<ShutdownAction> PickedActions(const QVariantMap& values) {
    const QStringList           ids = values.value(QLatin1String(kShutdownField)).toStringList();
    std::vector<ShutdownAction> actions;
    for (ShutdownAction action : ShutdownPolicy::AllActions())
        if (ids.contains(QLatin1String(ShutdownPolicy::Id(action)))) actions.push_back(action);
    return actions;
}

}

bool EnterpriseModel::Allowed() const { return emu_.Get<EnterpriseConfig>().Allowed(); }

bool EnterpriseModel::Enabled() const { return emu_.Get<EnterpriseConfig>().Enabled(); }

bool EnterpriseModel::Kiosk() const { return emu_.Get<EnterpriseConfig>().Kiosk(); }

QString EnterpriseModel::Password() const { return QString::fromStdString(emu_.Get<EnterpriseConfig>().Password()); }

int EnterpriseModel::MinPasswordLength() const { return static_cast<int>(EnterpriseConfig::kMinPasswordLength); }

QString EnterpriseModel::Device() const { return QString::fromStdString(emu_.Get<FrontendConfig>().Device()); }

QString EnterpriseModel::Splash() const { return QString::fromStdString(emu_.Get<EnterpriseConfig>().Splash()); }

QVariantList EnterpriseModel::SplashValues() const {
    QVariantList values;
    for (const char* value : EnterpriseConfig::SplashValues()) values.append(QString::fromLatin1(value));
    return values;
}

QString EnterpriseModel::SplashLabel(const QString& value) const {
    if (value == QLatin1String(EnterpriseConfig::kSplashEnterprise)) return QStringLiteral("Enterprise");
    if (value == QLatin1String(EnterpriseConfig::kSplashEnterpriseNoBadge))
        return QStringLiteral("Enterprise (no badge)");
    return QStringLiteral(CERF_PRODUCT_NAME);
}

QString EnterpriseModel::LogoPath() const { return QString::fromStdString(emu_.Get<EnterpriseConfig>().LogoPath()); }

QString EnterpriseModel::LogoFolder() const { return QString::fromStdString(cerfcore::GetCerfDir()); }

QVariantList EnterpriseModel::ShutdownActions() const {
    const std::vector<ShutdownAction> allowed = emu_.Get<ShutdownPolicy>().Actions();
    const auto&                       prompt  = emu_.Get<cerffrontend::ShutdownPrompt>();
    QVariantList                      rows;
    for (ShutdownAction action : ShutdownPolicy::AllActions())
        rows.append(QVariantMap{
            {QLatin1String(kIdField), QString::fromLatin1(ShutdownPolicy::Id(action))},
            {QLatin1String(kLabelField), QString::fromUtf8(prompt.ActionLabel(action))},
            {QLatin1String(kCheckedField), std::find(allowed.begin(), allowed.end(), action) != allowed.end()}});
    return rows;
}

QString EnterpriseModel::Problem(const QVariantMap& values) const {
    if (values.value(QLatin1String(kPasswordField)).toString().toUcs4().size() < MinPasswordLength())
        return QStringLiteral("The password must have at least %1 characters.").arg(MinPasswordLength());
    if (!ShutdownPolicy::Usable(PickedActions(values)))
        return QStringLiteral("The shutdown policy must allow at least one action.");
    return QString();
}

QString EnterpriseModel::Save(const QVariantMap& values) {
    const auto text = [&values](const char* field) {
        return values.value(QLatin1String(field)).toString().toStdString();
    };
    const auto  flag   = [&values](const char* field) { return values.value(QLatin1String(field)).toBool(); };
    auto&       config = emu_.Get<FrontendConfig>();
    std::string error;
    config.Write(
        [&](Json& root) {
            config.Assign(root, EnterpriseConfig::KeyOf(EnterpriseConfig::kEnabledKey), flag(kEnabledField));
            config.Assign(root, EnterpriseConfig::KeyOf(EnterpriseConfig::kPasswordKey), text(kPasswordField));
            config.Assign(root, EnterpriseConfig::KeyOf(EnterpriseConfig::kSplashKey), text(kSplashField));
            config.Assign(root, EnterpriseConfig::KeyOf(EnterpriseConfig::kLogoPathKey), text(kLogoField));
            config.Assign(root, EnterpriseConfig::KeyOf(EnterpriseConfig::kKioskKey), flag(kKioskField));
            config.Assign(root, FrontendConfig::Key() / FrontendConfig::kDeviceKey, text(kDeviceField));
            config.Assign(root, ShutdownPolicy::Key(), ShutdownPolicy::ToJson(PickedActions(values)));
        },
        error);
    return QString::fromStdString(error);
}
