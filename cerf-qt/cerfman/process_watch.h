#pragma once

#include <QString>

#include <cstdint>
#include <vector>

bool WaitForProcessExit(uint32_t pid, int timeout_ms, QString& error);
bool ProcessesRunningImage(const QString& executable_path, std::vector<uint32_t>& pids, QString& error);
