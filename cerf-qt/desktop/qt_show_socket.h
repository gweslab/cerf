#pragma once

#include <cstdint>
#include <string_view>

inline constexpr std::string_view kShowRequest = "show";

int  OpenShowSocket(uint32_t pid, int& error);
void CloseShowSocket(int fd, uint32_t pid);
bool SendShowRequest(uint32_t pid);
