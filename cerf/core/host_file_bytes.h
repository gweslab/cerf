#pragma once

#include <cstdint>
#include <string>
#include <vector>

std::vector<uint8_t> ReadHostFileBytes(const std::string& path);

bool HostFileNonEmpty(const std::string& path);
