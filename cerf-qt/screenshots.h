#pragma once

#include <cerfcore/core/service.h>

#include <cstdint>
#include <string>
#include <vector>

namespace cerffrontend {

class Screenshots : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void Save();
    void Copy();
    void SaveGuestSurfaceTo(const std::string& path);
    void SavePixels(const std::vector<uint32_t>& pixels, uint32_t w, uint32_t h,
                    const std::string& name_hint);
    void CopyPixels(const std::vector<uint32_t>& pixels, uint32_t w, uint32_t h);
};

}
