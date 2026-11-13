#include "self_upgrade.h"

#include "../play_store_copy.h"
#include "../product_links.h"

bool SelfUpgradeSupported() { return false; }

const char* ManualDownloadUrl() {
    return PlayStoreCopy() ? cerffrontend::kPlayStoreUrl.text : cerffrontend::kAndroidDownloadUrl.text;
}
