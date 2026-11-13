#include "self_upgrade.h"

#include "../product_links.h"

bool SelfUpgradeSupported() { return true; }

const char* ManualDownloadUrl() { return cerffrontend::kDownloadUrl.text; }
