#include "uninstall_removal.h"

#include "shell_integration_windows.h"

#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/platform/wide_text_win32.h>
#include "../cerf-qt/cerfman/path_removal.h"
#include "../cerf-qt/cerfman/retry_attempt.h"
#include "../cerf-qt/install_root_files.h"

#define NOMINMAX
#include <windows.h>

#include <algorithm>
#include <filesystem>
#include <system_error>

namespace {

constexpr const char* kUserData[] = {cerffrontend::kGlobalConfigFileName, cerfcore::kDevicesDirName,
                                     cerffrontend::kScreenshotsDirName,   cerfcore::kDefaultCfImageName,
                                     cerfcore::kLogFileName,              cerfcore::kCrashLogFileName,
                                     cerffrontend::kManagerLogFileName};

bool IsUserData(const std::wstring& name) {
    for (const char* kept : kUserData)
        if (CompareStringOrdinal(name.c_str(), -1, cerfcore::Utf8ToWide(kept).c_str(), -1, TRUE) == CSTR_EQUAL)
            return true;
    return false;
}

DWORD RemovePath(const std::wstring& path) { return static_cast<DWORD>(RemovePathTree(path).value()); }

void LogNotRemoved(const std::wstring& what, const std::wstring& failure, const RemovalHost& host) {
    host.log(L"  " + what + L" not removed (" + failure + L")");
}

bool Attempt(const std::wstring& what, const std::function<DWORD()>& action, const RemovalHost& host) {
    std::wstring failure;
    const bool   done = RetryAttempt(
        [&](std::wstring& text) {
            const DWORD code = action();
            if (code == ERROR_SUCCESS) return true;
            text = shell_integration::ErrorText(code);
            return false;
        },
        [&](const std::wstring& text) {
            return host.ask_retry(L"Remove failed", L"Removing " + what + L" failed:\n" + text + L"\n\nRetry?");
        },
        failure);
    if (!done) LogNotRemoved(what, failure, host);
    return done;
}

void LogRemoving(const std::wstring& what, const RemovalHost& host) { host.log(L"Removing " + what); }

void RemoveResolved(const std::wstring& what, bool (*resolve)(std::wstring&, std::wstring&),
                    const RemovalHost& host, std::vector<std::wstring>& left) {
    LogRemoving(what, host);
    std::wstring path;
    std::wstring error;
    if (!resolve(path, error)) {
        LogNotRemoved(what, error, host);
        left.push_back(what);
        return;
    }
    if (!Attempt(what, [&] { return RemovePath(path); }, host)) left.push_back(what);
}

std::vector<std::wstring> SortedEntries(const std::wstring& directory, DWORD& failure) {
    std::vector<std::wstring> names;
    std::error_code           ec;
    for (std::filesystem::directory_iterator it(directory, ec), end; !ec && it != end; it.increment(ec))
        names.push_back(it->path().filename().wstring());
    failure = static_cast<DWORD>(ec.value());
    std::sort(names.begin(), names.end());
    return names;
}

}

OwnedIntegration FindOwnedIntegration(const std::wstring& install_dir) {
    OwnedIntegration owned;
    owned.desktop_shortcut = shell_integration::OwnsDesktopShortcut(install_dir);
    owned.start_menu       = shell_integration::OwnsStartMenuEntries(install_dir);
    owned.uninstall_entry  = shell_integration::OwnsUninstallEntry(install_dir);
    return owned;
}

std::vector<std::wstring> RemoveInstallation(const std::wstring& install_dir, bool delete_user_data,
                                             const RemovalHost& host) {
    std::vector<std::wstring> left;
    DWORD                     failure = ERROR_SUCCESS;
    const std::vector<std::wstring> entries = SortedEntries(install_dir, failure);
    if (failure != ERROR_SUCCESS) {
        host.log(L"  " + install_dir + L" not read (" + shell_integration::ErrorText(failure) + L")");
        left.push_back(install_dir);
        return left;
    }
    for (const std::wstring& name : entries) {
        if (!delete_user_data && IsUserData(name)) continue;
        host.log(L"  " + name);
        const std::wstring path = shell_integration::JoinPath(install_dir, name);
        if (!Attempt(name, [&] { return RemovePath(path); }, host)) left.push_back(name);
    }
    if (delete_user_data && left.empty()) {
        const std::wstring what = L"the installation directory";
        if (!Attempt(what, [&] { return RemovePath(install_dir); }, host)) left.push_back(what);
    }
    return left;
}

std::vector<std::wstring> RemoveShellIntegration(const OwnedIntegration& owned, const RemovalHost& host) {
    std::vector<std::wstring> left;
    if (owned.start_menu) RemoveResolved(L"the Start menu entries", shell_integration::StartMenuFolder, host, left);
    if (owned.desktop_shortcut)
        RemoveResolved(L"the desktop shortcut", shell_integration::DesktopShortcutPath, host, left);
    if (owned.uninstall_entry) {
        const std::wstring what = L"the Programs and Features entry";
        LogRemoving(what, host);
        if (!Attempt(what,
                     [] {
                         const LONG code = RegDeleteKeyW(HKEY_CURRENT_USER, shell_integration::kUninstallKey);
                         return code == ERROR_FILE_NOT_FOUND ? DWORD(ERROR_SUCCESS) : DWORD(code);
                     },
                     host))
            left.push_back(what);
    }
    return left;
}
