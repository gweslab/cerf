#pragma once

#include <cstdint>

enum class PanelPixelFormat : uint8_t {
    kGray2Msb,
    kRgb565Le,
};

struct PanelSurface {
    const uint8_t* fb     = nullptr;
    uint32_t       stride = 0u;
    uint32_t       width  = 0u;
    uint32_t       height = 0u;
};

class PanelScanout {
public:
    explicit PanelScanout(PanelPixelFormat format) : format_(format) {}

    void Blit(const PanelSurface& src, uint32_t* dib,
              uint32_t host_w, uint32_t host_h) const;

private:
    PanelPixelFormat format_;
};
