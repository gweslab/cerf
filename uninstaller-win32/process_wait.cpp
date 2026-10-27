#include "process_wait.h"

#include "shell_integration_windows.h"

#include <cerfcore/core/path_split.h>

#include <string>

#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>

namespace process_wait {

namespace {

bool ImagePath(DWORD pid, std::wstring& out) {
    const HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == nullptr) return false;
    std::wstring buffer(32768, L'\0');
    DWORD        size = DWORD(buffer.size());
    const BOOL   ok   = QueryFullProcessImageNameW(process, 0, buffer.data(), &size);
    CloseHandle(process);
    if (!ok) return false;
    buffer.resize(size);
    out = buffer;
    return true;
}

template <typename Match>
bool CollectProcesses(const Match& match, std::vector<uint32_t>& pids, std::wstring& error) {
    pids.clear();
    const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        error = L"cannot enumerate running processes (" + shell_integration::ErrorText(GetLastError()) + L")";
        return false;
    }
    PROCESSENTRY32W entry = {};
    entry.dwSize          = sizeof(entry);
    const DWORD self      = GetCurrentProcessId();
    for (BOOL more = Process32FirstW(snapshot, &entry); more; more = Process32NextW(snapshot, &entry))
        if (entry.th32ProcessID != self && match(entry)) pids.push_back(entry.th32ProcessID);
    CloseHandle(snapshot);
    return true;
}

}

bool WaitForPidExit(uint32_t pid, uint32_t timeout_ms, std::wstring& error) {
    const HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, pid);
    if (process == nullptr) {
        const DWORD code = GetLastError();
        if (code != ERROR_ACCESS_DENIED) return true;
        error = L"cannot wait for process " + std::to_wstring(pid) + L" (" + shell_integration::ErrorText(code) + L")";
        return false;
    }
    const DWORD result = WaitForSingleObject(process, timeout_ms);
    const DWORD code   = GetLastError();
    CloseHandle(process);
    if (result == WAIT_OBJECT_0) return true;
    if (result != WAIT_TIMEOUT)
        error = L"cannot wait for process " + std::to_wstring(pid) + L" (" + shell_integration::ErrorText(code) + L")";
    return false;
}

bool ProcessesRunningImage(const std::wstring& executable_path, std::vector<uint32_t>& pids, std::wstring& error) {
    const std::wstring name = executable_path.substr(cerfcore::PathNameOffset(
        executable_path.data(), executable_path.size(), cerfcore::kWindowsPathSeparators<wchar_t>));
    return CollectProcesses(
        [&](const PROCESSENTRY32W& entry) {
            if (CompareStringOrdinal(entry.szExeFile, -1, name.c_str(), -1, TRUE) != CSTR_EQUAL) return false;
            std::wstring image;
            return !ImagePath(entry.th32ProcessID, image) || shell_integration::SamePath(image, executable_path);
        },
        pids, error);
}

bool ProcessesRunningFrom(const std::wstring& directory, std::vector<uint32_t>& pids, std::wstring& error) {
    return CollectProcesses(
        [&](const PROCESSENTRY32W& entry) {
            std::wstring image;
            return ImagePath(entry.th32ProcessID, image) && shell_integration::InsideDirectory(image, directory);
        },
        pids, error);
}

}
