#pragma once

#include "host_key_names.h"

#include <span>

std::span<const HostKeyName> PlatformHostKeyNames();
