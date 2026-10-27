#pragma once

#include <cstdint>
#include <optional>
#include <string>

inline constexpr char     kWaitForPidArg[]     = "--wait-for-pid=";
inline constexpr uint32_t kWaitForPidTimeoutMs = 30000;

std::string WaitForPidArgument(uint32_t pid);
bool        ParseWaitForPidArg(const char* arg, std::optional<uint32_t>& pid);
bool ParseWaitForPidArg(const wchar_t* arg, std::optional<uint32_t>& pid);
