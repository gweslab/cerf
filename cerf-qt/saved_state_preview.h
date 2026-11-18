#pragma once

#include <cerfcore/core/service.h>

#include <string>

namespace cerffrontend {

inline constexpr char kSavedStatePreviewFile[] = "saved_state.png";

class SavedStatePreview : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override;

private:
    std::string DeviceFile(const char* name) const;
    void        SaveCrashPreview();
};

}
