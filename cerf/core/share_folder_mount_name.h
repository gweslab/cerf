#pragma once

#include <cstddef>
#include <string>

constexpr size_t kShareFolderMountNameMaxWchars = 63;

bool IsValidShareFolderMountName(const std::string& utf8);
