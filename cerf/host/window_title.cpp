#define NOMINMAX

#include "window_title.h"

#include "../core/board_database.h"
#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/device_meta_label.h"
#include "../core/string_utils.h"
#include "../version.h"

#include <vector>

REGISTER_SERVICE(WindowTitle);

std::wstring WindowTitle::Compose() const {
    const DeviceConfig& cfg = emu_.Get<DeviceConfig>();
    const DeviceMeta& meta = cfg.meta;

    std::vector<std::wstring> parts;
    if (!meta.name.empty())
        parts.push_back(Utf8ToWide(meta.name.c_str()));
    else if (!meta.device_name.empty())
        parts.push_back(Utf8ToWide(meta.device_name.c_str()));
    else if (const DbDevice* board =
                 emu_.Get<BoardDatabase>().FindDevice(cfg.board_id))
        parts.push_back(Utf8ToWide(board->name.c_str()));
    const std::string os = OsDisplayLabel(meta);
    if (!os.empty())
        parts.push_back(Utf8ToWide(os.c_str()));
    parts.push_back(L"CERF " CERF_VERSION_DISPLAY_WSTR);

    std::wstring title;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) title += L" • ";   /* bullet separator */
        title += parts[i];
    }
    return title;
}
