#include "screenshots.h"

#include "frontend_window.h"
#include "image_exporter.h"
#include "screenshot_store.h"
#include "shader_selection.h"

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

void Screenshots::Save(std::function<void(bool saved)> done) {
    CaptureShown([this, done = std::move(done)](const std::vector<uint32_t>* pixels, uint32_t w, uint32_t h) {
        if (pixels == nullptr) LOG(Lcd, "Screenshots::Save: no guest frame to capture\n");
        const bool saved =
            pixels != nullptr && SavePixels(*pixels, w, h, emu_.Get<cerfcore::DeviceConfig>().device_name);
        if (done) done(saved);
    });
}

void Screenshots::Copy() {
    CaptureShown([this](const std::vector<uint32_t>* pixels, uint32_t w, uint32_t h) {
        if (pixels == nullptr) {
            LOG(Lcd, "Screenshots::Copy: no guest frame to capture\n");
            return;
        }
        CopyPixels(*pixels, w, h);
    });
}

void Screenshots::CaptureShown(Shot shot) {
    if (!emu_.Get<cerfcore::DeviceConfig>().shader_screenshots || emu_.Get<ShaderSelection>().Spec().presets.empty() ||
        !emu_.Get<FrontendWindow>().RequestShadedCapture()) {
        CaptureUnshaded(shot);
        return;
    }
    waiting_.push_back(std::move(shot));
}

void Screenshots::ShadedCaptured(const ShadedFrame* frame) {
    std::vector<Shot> waiting = std::move(waiting_);
    waiting_.clear();
    if (frame == nullptr) LOG(Lcd, "Screenshots: the frame is not shaded, taking the guest surface\n");
    for (const Shot& shot : waiting) {
        if (frame != nullptr) shot(&frame->pixels, frame->width, frame->height);
        else                  CaptureUnshaded(shot);
    }
}

void Screenshots::CaptureUnshaded(const Shot& shot) {
    std::vector<uint32_t> px;
    uint32_t              w = 0, h = 0;
    if (emu_.Get<FrontendWindow>().CaptureGuestSurface(px, w, h)) shot(&px, w, h);
    else                                                          shot(nullptr, 0, 0);
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
