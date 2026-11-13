#pragma once

#include "shader_capture.h"

#include <cerfcore/core/service.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace cerffrontend {

class Screenshots : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void Save(std::function<void(bool saved)> done);
    void Copy();
    void SaveGuestSurfaceTo(const std::string& path);
    bool SavePixels(const std::vector<uint32_t>& pixels, uint32_t w, uint32_t h,
                    const std::string& name_hint);
    void CopyPixels(const std::vector<uint32_t>& pixels, uint32_t w, uint32_t h);
    void ShadedCaptured(const ShadedFrame* frame);

private:
    using Shot = std::function<void(const std::vector<uint32_t>* pixels, uint32_t w, uint32_t h)>;

    void CaptureShown(Shot shot);
    void CaptureUnshaded(const Shot& shot);

    std::vector<Shot> waiting_;
};

}
