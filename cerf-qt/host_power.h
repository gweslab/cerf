#pragma once

#include <cstdint>

namespace cerffrontend::host_power {

using SuspendCall = bool (*)(uint32_t& error_code);

SuspendCall Suspend();

}
