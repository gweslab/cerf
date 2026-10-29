#include "product_links_model.h"

REGISTER_SERVICE(ProductLinksModel);

QString ProductLinksModel::ProductName() const { return QString::fromUtf8(cerffrontend::kProductName); }

QString ProductLinksModel::GuestAdditionsUrl() const {
    return QString::fromUtf8(cerffrontend::kGuestAdditionsUrl.text);
}

QString ProductLinksModel::WebsiteUrl() const { return QString::fromUtf8(cerffrontend::kWebsiteUrl); }

QString ProductLinksModel::DiscordUrl() const { return QString::fromUtf8(cerffrontend::kDiscordUrl); }

QString ProductLinksModel::DonateUrl() const { return QString::fromUtf8(cerffrontend::kDonateUrl.text); }