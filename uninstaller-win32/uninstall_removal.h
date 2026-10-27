#pragma once

#include <functional>
#include <string>
#include <vector>

struct RemovalHost {
    std::function<void(const std::wstring&)>                            log;
    std::function<bool(const std::wstring&, const std::wstring&)> ask_retry;
};

struct OwnedIntegration {
    bool desktop_shortcut = false;
    bool start_menu       = false;
    bool uninstall_entry  = false;
};

OwnedIntegration          FindOwnedIntegration(const std::wstring& install_dir);
std::vector<std::wstring> RemoveInstallation(const std::wstring& install_dir, bool delete_user_data,
                                             const RemovalHost& host);
std::vector<std::wstring> RemoveShellIntegration(const OwnedIntegration& owned, const RemovalHost& host);
