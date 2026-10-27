#pragma once

#include <filesystem>
#include <system_error>

std::error_code RemovePathTree(const std::filesystem::path& path);
