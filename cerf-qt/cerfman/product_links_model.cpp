#include "product_links_model.h"

#include "../link_target.h"

REGISTER_SERVICE(ProductLinksModel);

QString ProductLinksModel::ProductName() const { return QString::fromUtf8(cerffrontend::kProductName); }

QString ProductLinksModel::GuestAdditionsUrl() const {
    return QString::fromUtf8(cerffrontend::kGuestAdditionsUrl.text);
}

QString ProductLinksModel::WebsiteUrl() const { return QString::fromUtf8(cerffrontend::kWebsiteUrl); }

QString ProductLinksModel::DiscordUrl() const { return QString::fromUtf8(cerffrontend::kDiscordUrl); }

QString ProductLinksModel::DonateUrl() const { return QString::fromUtf8(cerffrontend::kDonateUrl.text); }

bool ProductLinksModel::DonateShown() const { return !LinkTarget(DonateUrl()).isEmpty(); }

QString ProductLinksModel::SlangShadersUrl() const { return QString::fromUtf8(cerffrontend::kSlangShadersUrl.text); }

QString ProductLinksModel::LibrashaderUrl() const { return QString::fromUtf8(cerffrontend::kLibrashaderUrl.text); }
