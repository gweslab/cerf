#include "../screenshot_store.h"

#include "../cerfman/filesystem_path.h"
#include "../image_exporter.h"
#include "../install_root_files.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/log.h>
#include <cerfcore/core/utf16.h>

#include <filesystem>

namespace {

class ScreenshotFolderStore : public cerffrontend::ScreenshotStore {
public:
    using cerffrontend::ScreenshotStore::ScreenshotStore;

    bool Store(const std::vector<uint8_t>& png, const std::string& file_name) override {
        const std::filesystem::path dir = std::filesystem::path(cerfcore::Utf8ToUtf16(cerfcore::GetCerfDir())) /
                                          cerfcore::Utf8ToUtf16(cerffrontend::kScreenshotsDirName);
        QString error;
        if (!MakeDirectory(PathText(dir), error)) {
            LOG(Lcd, "ScreenshotFolderStore: %s\n", qUtf8Printable(error));
            return false;
        }
        return emu_.Get<cerffrontend::ImageExporter>().WriteEncodedPng(
            png, PathText(dir / cerfcore::Utf8ToUtf16(file_name)).toStdString());
    }
};

}

REGISTER_SERVICE_AS(ScreenshotFolderStore, cerffrontend::ScreenshotStore);
