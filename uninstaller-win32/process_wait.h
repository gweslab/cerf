#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace process_wait {

bool WaitForPidExit(uint32_t pid, uint32_t timeout_ms, std::wstring& error);
bool ProcessesRunningImage(const std::wstring& executable_path, std::vector<uint32_t>& pids, std::wstring& error);
bool ProcessesRunningFrom(const std::wstring& directory, std::vector<uint32_t>& pids, std::wstring& error);

}
