#include "shell_integration_windows.h"
#include "uninstall_name_text.h"

#include <cerfcore/core/path_split.h>
#include <cerfcore/platform/host_error.h>
#include <cerfcore/platform/host_process.h>
#include <cerfcore/platform/wide_text_win32.h>
#include "../cerf-qt/product_links.h"

#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <shlobj.h>

#include <cwchar>
#include <vector>

namespace shell_integration {

namespace {

std::wstring HresultText(HRESULT hr) {
    wchar_t text[32] = {};
    std::swprintf(text, 32, L"HRESULT 0x%08lX", static_cast<unsigned long>(hr));
    return text;
}

std::wstring WithoutTrailingSeparator(std::wstring path) {
    cerfcore::TrimTrailingSeparators(path, cerfcore::kWindowsPathSeparators<wchar_t>, 3);
    return path;
}

bool KnownFolder(int csidl, const wchar_t* name, std::wstring& out, std::wstring& error) {
    wchar_t       path[MAX_PATH] = {};
    const HRESULT hr             = SHGetFolderPathW(nullptr, csidl, nullptr, SHGFP_TYPE_CURRENT, path);
    if (hr != S_OK || path[0] == L'\0') {
        error = std::wstring(L"the ") + name + L" folder could not be located (" + HresultText(hr) + L")";
        return false;
    }
    out = path;
    return true;
}

class ComScope {
public:
    ComScope() {
        const HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        initialized_     = hr == S_OK || hr == S_FALSE;
    }
    ~ComScope() {
        if (initialized_) CoUninitialize();
    }
    ComScope(const ComScope&)            = delete;
    ComScope& operator=(const ComScope&) = delete;

private:
    bool initialized_ = false;
};

}

std::wstring ProductName() { return cerfcore::Utf8ToWide(cerffrontend::kProductName); }

std::wstring ErrorText(unsigned long code) {
    return cerfcore::Utf8ToWide(cerfcore::host_platform::ErrorText(uint32_t(code)).c_str());
}

std::wstring ExecutablePath() { return cerfcore::Utf8ToWide(cerfcore::host_platform::ExecutablePath().c_str()); }

std::wstring UninstallName() { return cerfcore::Utf8ToWide(CERF_UNINSTALL_NAME); }

std::wstring JoinPath(const std::wstring& directory, const std::wstring& name) {
    return cerfcore::AppendPathName(directory, name, cerfcore::kWindowsPathSeparators<wchar_t>);
}

std::wstring DirectoryOf(const std::wstring& path) {
    const size_t offset = cerfcore::PathNameOffset(path.data(), path.size(), cerfcore::kWindowsPathSeparators<wchar_t>);
    return path.substr(0, offset == 0 ? 0 : offset - 1);
}

std::wstring FullPath(const std::wstring& path) {
    const DWORD size = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
    if (size == 0) return path;
    std::vector<wchar_t> buffer(size);
    const DWORD          written = GetFullPathNameW(path.c_str(), size, buffer.data(), nullptr);
    if (written == 0 || written >= size) return path;
    return std::wstring(buffer.data(), written);
}

bool InsideDirectory(const std::wstring& path, const std::wstring& directory) {
    if (path.empty() || directory.empty()) return false;
    const std::wstring root = WithoutTrailingSeparator(FullPath(directory)) + L"\\";
    const std::wstring full = FullPath(path);
    return full.size() > root.size() &&
           CompareStringOrdinal(full.c_str(), int(root.size()), root.c_str(), int(root.size()), TRUE) == CSTR_EQUAL;
}

bool SamePath(const std::wstring& a, const std::wstring& b) {
    if (a.empty() || b.empty()) return false;
    const std::wstring left  = WithoutTrailingSeparator(FullPath(a));
    const std::wstring right = WithoutTrailingSeparator(FullPath(b));
    return CompareStringOrdinal(left.c_str(), int(left.size()), right.c_str(), int(right.size()), TRUE) ==
           CSTR_EQUAL;
}

std::wstring ShortcutPath(const std::wstring& folder, const std::wstring& title) {
    return JoinPath(folder, title + L".lnk");
}

bool DesktopShortcutPath(std::wstring& out, std::wstring& error) {
    std::wstring desktop;
    if (!KnownFolder(CSIDL_DESKTOPDIRECTORY, L"desktop", desktop, error)) return false;
    out = ShortcutPath(desktop, ProductName());
    return true;
}

bool StartMenuFolder(std::wstring& out, std::wstring& error) {
    std::wstring programs;
    if (!KnownFolder(CSIDL_PROGRAMS, L"Start menu", programs, error)) return false;
    out = JoinPath(programs, ProductName());
    return true;
}

bool WriteShortcut(const std::wstring& link_path, const std::wstring& target, const std::wstring& description,
                   std::wstring& error) {
    const ComScope     com;
    const std::wstring absolute = FullPath(target);
    IShellLinkW*       link     = nullptr;
    IPersistFile*      persist  = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                  reinterpret_cast<void**>(&link));
    if (SUCCEEDED(hr)) {
        link->SetPath(absolute.c_str());
        link->SetWorkingDirectory(DirectoryOf(absolute).c_str());
        link->SetDescription(description.c_str());
        hr = link->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&persist));
    }
    if (SUCCEEDED(hr)) {
        const std::wstring link_full = FullPath(link_path);
        const int          made      = SHCreateDirectoryExW(nullptr, DirectoryOf(link_full).c_str(), nullptr);
        if (made != ERROR_SUCCESS && made != ERROR_ALREADY_EXISTS && made != ERROR_FILE_EXISTS)
            hr = HRESULT_FROM_WIN32(DWORD(made));
        else
            hr = persist->Save(link_full.c_str(), TRUE);
    }
    if (persist) persist->Release();
    if (link) link->Release();
    if (FAILED(hr)) {
        error = L"cannot write " + link_path + L" (" + HresultText(hr) + L")";
        return false;
    }
    return true;
}

std::wstring ShortcutTarget(const std::wstring& link_path) {
    const ComScope com;
    IShellLinkW*   link             = nullptr;
    IPersistFile*  persist          = nullptr;
    wchar_t        target[MAX_PATH] = {};
    HRESULT hr = CoCreateInstance(CLSID_ShellLink, nullptr, CLSCTX_INPROC_SERVER, IID_IShellLinkW,
                                  reinterpret_cast<void**>(&link));
    if (SUCCEEDED(hr)) hr = link->QueryInterface(IID_IPersistFile, reinterpret_cast<void**>(&persist));
    if (SUCCEEDED(hr)) hr = persist->Load(FullPath(link_path).c_str(), STGM_READ);
    if (SUCCEEDED(hr)) hr = link->GetPath(target, MAX_PATH, nullptr, 0);
    if (persist) persist->Release();
    if (link) link->Release();
    return hr == S_OK ? std::wstring(target) : std::wstring();
}

bool OwnsDesktopShortcut(const std::wstring& install_dir) {
    std::wstring path;
    std::wstring error;
    return DesktopShortcutPath(path, error) && InsideDirectory(ShortcutTarget(path), install_dir);
}

bool OwnsStartMenuEntries(const std::wstring& install_dir) {
    std::wstring folder;
    std::wstring error;
    return StartMenuFolder(folder, error) &&
           InsideDirectory(ShortcutTarget(ShortcutPath(folder, ProductName())), install_dir);
}

bool OwnsUninstallEntry(const std::wstring& install_dir) {
    wchar_t value[MAX_PATH] = {};
    DWORD   size            = sizeof(value) - sizeof(wchar_t);
    if (RegGetValueW(HKEY_CURRENT_USER, kUninstallKey, kInstallLocationValue, RRF_RT_REG_SZ, nullptr, value, &size) !=
        ERROR_SUCCESS)
        return false;
    return SamePath(value, install_dir);
}

}
