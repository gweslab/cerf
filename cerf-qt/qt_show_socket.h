#pragma once

#include <cstdint>

int  OpenShowSocket(uint32_t pid, int& error);
void CloseShowSocket(int fd, uint32_t pid);
