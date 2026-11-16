#include "enterprise_config.h"

#include "frontend_config.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>

namespace cerffrontend {

REGISTER_SERVICE(EnterpriseConfig);

using json = nlohmann::ordered_json;

std::vector<const char*> EnterpriseConfig::SplashValues() {
    return {kSplashCerf, kSplashEnterprise, kSplashEnterpriseNoBadge};
}

json EnterpriseConfig::Section() const { return emu_.Get<FrontendConfig>().Read().at(kSectionKey); }

bool EnterpriseConfig::Allowed() const { return Section().at(kAllowedKey).get<bool>(); }

bool EnterpriseConfig::Enabled() const { return Section().at(kEnabledKey).get<bool>(); }

bool EnterpriseConfig::Kiosk() const { return Section().at(kKioskKey).get<bool>(); }

std::string EnterpriseConfig::Splash() const { return Section().at(kSplashKey).get<std::string>(); }

std::string EnterpriseConfig::Password() const { return Section().at(kPasswordKey).get<std::string>(); }

std::string EnterpriseConfig::LogoPath() const { return Section().at(kLogoPathKey).get<std::string>(); }

std::string EnterpriseConfig::LogoFile() const {
    return cerfcore::ResolveFileIn(cerfcore::GetCerfDir(), LogoPath());
}

FrontendConfig::Key EnterpriseConfig::KeyOf(const char* name) { return FrontendConfig::Key() / kSectionKey / name; }

bool EnterpriseConfig::SetKiosk(bool on, std::string& error) {
    auto& config = emu_.Get<FrontendConfig>();
    return config.Write([&](json& root) { config.Assign(root, KeyOf(kKioskKey), on); }, error);
}

}
