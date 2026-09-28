#define NOMINMAX
#include "share_folder_mount_name.h"

#include "string_utils.h"

#include <string_view>

/* smartbook_g138_ce4_2 filesys.exe 0x127D4: the RegisterAFSName name check. */
bool IsValidShareFolderMountName(const std::string& utf8) {
    const std::wstring name = Utf8ToWide(utf8.c_str());
    if (name.empty() || name.size() > kShareFolderMountNameMaxWchars)
        return false;
    constexpr std::wstring_view kInvalid = L"\\/:*?\"<>|";
    for (wchar_t c : name) {
        if (c < 0x20 || kInvalid.find(c) != std::wstring_view::npos)
            return false;
    }
    return true;
}
