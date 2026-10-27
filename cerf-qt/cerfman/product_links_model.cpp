#include "product_links_model.h"

REGISTER_SERVICE(ProductLinksModel);

QString ProductLinksModel::ProductName() const { return QString::fromUtf8(cerffrontend::kProductName); }

QString ProductLinksModel::GuestAdditionsUrl() const {
    return QString::fromUtf8(cerffrontend::kGuestAdditionsUrl.text);
}