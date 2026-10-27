#include "host_error_text.h"

#include <cerfcore/platform/host_error.h>

QString HostErrorText(uint32_t code) { return QString::fromStdString(cerfcore::host_platform::ErrorText(code)); }
