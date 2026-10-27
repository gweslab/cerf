#pragma once

#include <string>

namespace shell_integration {

inline constexpr wchar_t kUninstallKey[] = L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\CERuntimeFoundation";
inline constexpr wchar_t kInstallLocationValue[] = L"InstallLocation";

std::wstring ProductName();
std::wstring ErrorText(unsigned long code);
std::wstring ExecutablePath();
std::wstring UninstallName();
std::wstring JoinPath(const std::wstring& directory, const std::wstring& name);
std::wstring DirectoryOf(const std::wstring& path);
std::wstring FullPath(const std::wstring& path);
bool         InsideDirectory(const std::wstring& path, const std::wstring& directory);
bool         SamePath(const std::wstring& a, const std::wstring& b);

std::wstring ShortcutPath(const std::wstring& folder, const std::wstring& title);
bool         DesktopShortcutPath(std::wstring& out, std::wstring& error);
bool StartMenuFolder(std::wstring& out, std::wstring& error);
bool WriteShortcut(const std::wstring& link_path, const std::wstring& target, const std::wstring& description,
                   std::wstring& error);
std::wstring ShortcutTarget(const std::wstring& link_path);

bool OwnsDesktopShortcut(const std::wstring& install_dir);
bool OwnsStartMenuEntries(const std::wstring& install_dir);
bool OwnsUninstallEntry(const std::wstring& install_dir);

}
