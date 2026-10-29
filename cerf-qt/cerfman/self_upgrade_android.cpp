#include "self_upgrade.h"

#include "../product_links.h"

bool SelfUpgradeSupported() { return false; }

const char* ManualDownloadUrl() { return cerffrontend::kAndroidDownloadUrl.text; }
