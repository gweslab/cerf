#include "folder_share_config.h"
#include "board_database.h"
#include "cerf_paths.h"
#include "device_config_refresh.h"
#include "log.h"

#define NOMINMAX
#include <windows.h>

REGISTER_SERVICE(FolderShareConfig);

void FolderShareConfig::OnReady() {
    ApplyFromConfig();
    emu_.Get<DeviceConfigRefresh>().RegisterListener(
        [this] { ApplyFromConfig(); });
}

void FolderShareConfig::ApplyFromConfig() {
    const auto& cfg = emu_.Get<DeviceConfig>();
    const std::string& name = cfg.share_folder_mount_point.empty()
        ? emu_.Get<BoardDatabase>().GaSharedFolderMountPoint()
        : cfg.share_folder_mount_point;
    std::wstring mount = Utf8ToWide(name.c_str());

    const std::string& p = cfg.share_folder;
    std::wstring wp = Utf8ToWide(p.c_str());
    if (wp.empty()) {
        Set(false, L"", std::move(mount));
        return;
    }

    if (!IsAbsoluteHostPath(p))
        wp = Utf8ToWide(GetCerfDir().c_str()) + wp;

    const DWORD attrs = GetFileAttributesW(wp.c_str());
    const DWORD gle   = attrs == INVALID_FILE_ATTRIBUTES ? GetLastError() : 0;
    LOG(GuestAdditions, "[FolderShare] host root '%s' attrs=0x%lX gle=%lu mount '%s'\n",
        WideToUtf8(wp).c_str(), attrs, gle, name.c_str());

    Set(true, std::move(wp), std::move(mount));
}
