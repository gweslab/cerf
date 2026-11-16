#pragma once

#include "frontend_config.h"

#include <cerfcore/core/service.h>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <string>
#include <vector>

namespace cerffrontend {

class EnterpriseConfig : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr char kSectionKey[]             = "enterprise";
    static constexpr char kAllowedKey[]             = "allowed";
    static constexpr char kEnabledKey[]             = "enabled";
    static constexpr char kSplashKey[]              = "splash";
    static constexpr char kPasswordKey[]            = "password";
    static constexpr char kKioskKey[]               = "kiosk";
    static constexpr char kLogoPathKey[]            = "logo_path";
    static constexpr char kSplashCerf[]             = "cerf";
    static constexpr char kSplashEnterprise[]       = "enterprise";
    static constexpr char kSplashEnterpriseNoBadge[] = "enterprise_no_badge";
    static constexpr size_t kMinPasswordLength      = 16;

    static std::vector<const char*> SplashValues();
    static FrontendConfig::Key      KeyOf(const char* name);

    bool        Allowed() const;
    bool        Enabled() const;
    bool        Kiosk() const;
    std::string Splash() const;
    std::string Password() const;
    std::string LogoPath() const;
    std::string LogoFile() const;

    bool SetKiosk(bool on, std::string& error);

private:
    nlohmann::ordered_json Section() const;
};

}
