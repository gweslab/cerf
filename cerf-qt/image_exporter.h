#pragma once

#include <cerfcore/core/service.h>

#include <cstdint>
#include <string>
#include <vector>

namespace cerffrontend {

class ImageExporter : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    virtual bool EncodePng(const std::vector<uint32_t>& pixels, uint32_t w, uint32_t h,
                           std::vector<uint8_t>& png) = 0;
    virtual bool WritePng(const std::vector<uint32_t>& pixels, uint32_t w, uint32_t h,
                          const std::string& path) = 0;
    virtual bool WriteEncodedPng(const std::vector<uint8_t>& png, const std::string& path) = 0;
    virtual bool CopyToClipboard(const std::vector<uint32_t>& pixels, uint32_t w, uint32_t h) = 0;
};

}
