#include "settings_model.h"

#include "host_key_list.h"
#include "installation_host_branch.h"
#include "json_file.h"

#include "../frontend_config.h"
#include "../host_key_binding.h"

#include <nlohmann/json.hpp>

#include <string>
#include <vector>

REGISTER_SERVICE(SettingsModel);

namespace {

using cerffrontend::FrontendConfig;
using cerffrontend::HostKeyBinding;

}

QVariantList SettingsModel::HostKeyVks() const {
    return HostKeyVariantList(HostKeyBinding::OrDefault(emu_.Get<FrontendConfig>().HostKeyVks()));
}

QVariantList SettingsModel::ResetHostKeyVks() const { return HostKeyVariantList(ResetVks()); }

std::vector<uint8_t> SettingsModel::ResetVks() const {
    return DefaultHostKeyVks(QString::fromStdString(emu_.Get<FrontendConfig>().HostBranch()));
}

QString SettingsModel::UpdateChannel() const {
    return QString::fromStdString(emu_.Get<FrontendConfig>().UpdateChannel());
}

int SettingsModel::DefaultScale() const { return emu_.Get<FrontendConfig>().DefaultScale(); }

bool SettingsModel::DiscordRichPresence() const {
    return emu_.Get<FrontendConfig>().DiscordRichPresence();
}

SettingsModel::ChannelText SettingsModel::TextOf(const QString& channel) const {
    const std::string value = channel.toStdString();
    if (value == FrontendConfig::kUpdateChannelDisabled) return {"Disable updates", "No update notifications."};
    if (value == FrontendConfig::kUpdateChannelStable) return {"Stable releases", "Offers each new release."};
    return {"Unstable releases", "Offers experimental builds. They can damage your installation or devices."};
}

QVariantList SettingsModel::ChannelValues() const {
    QVariantList out;
    for (const char* value : FrontendConfig::UpdateChannelValues()) out.append(QString::fromLatin1(value));
    return out;
}

QString SettingsModel::ChannelLabel(const QString& channel) const { return QString::fromLatin1(TextOf(channel).label); }

QString SettingsModel::ChannelHint(const QString& channel) const { return QString::fromLatin1(TextOf(channel).hint); }

QVariantList SettingsModel::ScaleValues() const {
    QVariantList out;
    for (int value : FrontendConfig::DefaultScaleValues()) out.append(value);
    return out;
}

QString SettingsModel::ScaleLabel(int value) const {
    if (value == FrontendConfig::kDynamicScale) return QStringLiteral("Dynamic");
    if (value == FrontendConfig::kOriginalScale) return QStringLiteral("Original view");
    return QStringLiteral("Integer scale %1x").arg(value);
}

QString SettingsModel::Save(const QVariantList& host_key, const QString& channel, int scale,
                            bool discord) {
    auto& config = emu_.Get<FrontendConfig>();
    const std::string previous_channel = config.UpdateChannel();

    const std::vector<uint8_t> vks = ::HostKeyVks(host_key);
    const std::vector<uint8_t> absent_default = HostKeyBinding::OrDefault({});
    const bool                 absent = vks == absent_default && ResetVks() == absent_default;

    std::string error;
    const bool  written = config.Write(
        [&](Json& j) {
            j[FrontendConfig::kDiscordRichPresenceKey] = discord;
            if (absent) j.erase(FrontendConfig::kHostKeyKey);
            else        j[FrontendConfig::kHostKeyKey] = vks;
            j[FrontendConfig::kDefaultScaleKey]  = scale;
            j[FrontendConfig::kUpdateChannelKey] = channel.toStdString();
        },
        error);
    if (!written) return QString::fromStdString(error);
    if (config.UpdateChannel() != previous_channel) emit updateChannelChanged();
    return QString();
}
