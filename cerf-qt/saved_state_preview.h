#pragma once

#include <cerfcore/core/service.h>

namespace cerffrontend {

inline constexpr char kSavedStatePreviewFile[] = "saved_state.png";

class SavedStatePreview : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override;
};

}
