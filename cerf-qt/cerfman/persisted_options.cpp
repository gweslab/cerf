#include "persisted_options.h"

#include "emulation_speed.h"

#include <cerfcore/core/device_config.h>

#include <algorithm>

namespace {

constexpr std::array<const char*, 3> kExplicitKeys = {persist_field::kWidth, persist_field::kHeight,
                                                      persist_field::kBpp};

Json ValueOr(const Json& object, const char* key, const Json& fallback) {
    const auto it = object.find(key);
    return it != object.end() ? *it : fallback;
}

}

QString EffectiveMountPoint(const QString& configured, const QString& mount_default) {
    return configured.isEmpty() ? mount_default : configured;
}

Json ResolvePersistBaseline(const Json& base, const QString& mount_default) {
    using namespace persist_field;
    Json out                 = Json::object();
    out[kNetworkEnabled]     = ValueOr(base, kNetworkEnabled, cerfcore::kDefaultNetworkEnabled);
    out[kGuestAdditions]     = ValueOr(base, kGuestAdditions, cerfcore::kDefaultGuestAdditions);
    out[kColorScheme]        = ValueOr(base, kColorScheme, "");
    out[kFullScreen]         = ValueOr(base, kFullScreen, cerfcore::kDefaultStartFullscreen);
    out[cerfcore::config_key::kDoubleTapHelper] =
        ValueOr(base, cerfcore::config_key::kDoubleTapHelper, cerfcore::kDefaultDoubleTapHelper);
    out[kAllowUntrustedApps] = ValueOr(base, kAllowUntrustedApps, cerfcore::kDefaultAllowUntrustedApps);
    out[kMountPoint]         = EffectiveMountPoint(JsonText(base, kMountPoint), mount_default).toStdString();
    for (const char* key : kMultiplierKeys) out[key] = ValueOr(base, key, kDefaultMultiplier);
    for (const char* key : {kShareFolder, kDpi, kFontSize, kClearType, kHud})
        if (base.contains(key)) out[key] = base[key];
    return out;
}

PersistedValues ReadPersistedValues(const DeviceDirectory& device, const QString& mount_default) {
    const auto [base, user] = device.ReadPersistFields();
    PersistedValues out;
    out.baseline = ResolvePersistBaseline(base, mount_default);
    out.values   = out.baseline;
    for (const auto& [key, value] : user.items()) out.values[key] = value;
    return out;
}

bool PersistSubset(const DeviceDirectory& device, const Json& baseline,
                   std::span<const char* const> owned_keys, const Json& current, QString& error) {
    Json merged = device.ReadPersistFields().second;
    for (const char* key : owned_keys) {
        merged.erase(key);
        if (!current.contains(key)) continue;
        const bool is_explicit =
            std::any_of(kExplicitKeys.begin(), kExplicitKeys.end(),
                        [key](const char* k) { return std::string_view(k) == key; });
        if (is_explicit || current[key] != ValueOr(baseline, key, nullptr))
            merged[key] = current[key];
    }
    return device.WritePersistOverrides(merged, error);
}

QSize AutoResolution(std::optional<int> default_width, std::optional<int> default_height,
                     std::optional<QSize> panel) {
    const int width  = default_width ? *default_width
                       : panel       ? panel->width()
                                     : int(cerfcore::kDefaultConfigurableScreenWidth);
    const int height = default_height ? *default_height
                       : panel        ? panel->height()
                                      : int(cerfcore::kDefaultConfigurableScreenHeight);
    return QSize(width, height);
}
