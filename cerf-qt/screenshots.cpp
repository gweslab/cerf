#include "screenshots.h"

#include "frontend_window.h"
#include "image_exporter.h"
#include "screenshot_store.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/log.h>
#include <cerfcore/platform/host_local_time.h>

#include <cstdio>
#include <ctime>

namespace cerffrontend {

REGISTER_SERVICE(Screenshots);

namespace {

std::string SanitizeForFilename(std::string name) {
    if (name.empty()) name = "device";
    for (char& c : name) {
        if (c == '\\' || c == '/' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' ||
            c == '>' || c == '|')
            c = '_';
    }
    return name;
}

std::string TimestampNow() {
    std::tm local{};
    cerfcore::host_platform::LocalCalendarTime(std::time(nullptr), local);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d%02d%02d_%02d%02d%02d", local.tm_year + 1900,
                  local.tm_mon + 1, local.tm_mday, local.tm_hour, local.tm_min, local.tm_sec);
    return buf;
}

}

bool Screenshots::Save() {
    std::vector<uint32_t> px;
    uint32_t              w = 0, h = 0;
    if (!emu_.Get<FrontendWindow>().CaptureGuestSurface(px, w, h)) {
        LOG(Lcd, "Screenshots::Save: no guest frame to capture\n");
        return false;
    }
    return SavePixels(px, w, h, emu_.Get<cerfcore::DeviceConfig>().device_name);
}

void Screenshots::Copy() {
    std::vector<uint32_t> px;
    uint32_t              w = 0, h = 0;
    if (!emu_.Get<FrontendWindow>().CaptureGuestSurface(px, w, h)) {
        LOG(Lcd, "Screenshots::Copy: no guest frame to capture\n");
        return;
    }
    CopyPixels(px, w, h);
}

void Screenshots::CopyPixels(const std::vector<uint32_t>& pixels, uint32_t w, uint32_t h) {
    if (emu_.Get<ImageExporter>().CopyToClipboard(pixels, w, h))
        LOG(Lcd, "Screenshots::CopyPixels: copied %ux%u image\n", w, h);
}

void Screenshots::SaveGuestSurfaceTo(const std::string& path) {
    std::vector<uint32_t> px;
    uint32_t              w = 0, h = 0;
    if (!emu_.Get<FrontendWindow>().CaptureGuestSurface(px, w, h)) {
        LOG(Lcd, "Screenshots::SaveGuestSurfaceTo: no guest frame to capture\n");
        return;
    }
    if (emu_.Get<ImageExporter>().WritePng(px, w, h, path))
        LOG(Lcd, "Screenshots::SaveGuestSurfaceTo: wrote %ux%u\n", w, h);
}

bool Screenshots::SavePixels(const std::vector<uint32_t>& pixels, uint32_t w, uint32_t h,
                             const std::string& name_hint) {
    std::vector<uint8_t> png;
    if (!emu_.Get<ImageExporter>().EncodePng(pixels, w, h, png)) return false;
    const std::string file_name = SanitizeForFilename(name_hint) + "_" + TimestampNow() + ".png";
    if (!emu_.Get<ScreenshotStore>().Store(png, file_name)) return false;
    LOG(Lcd, "Screenshots::SavePixels: stored %ux%u screenshot %s\n", w, h, file_name.c_str());
    return true;
}

}
