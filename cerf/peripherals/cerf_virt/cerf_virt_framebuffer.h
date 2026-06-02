#pragma once

#include "../../core/service.h"

#include <cstdint>
#include <vector>

/* Shared state for the CERF virtual framebuffer. Resolution comes from
   DeviceConfig (board_configurable_screen_width/height); bpp pinned to
   32 (BGRA, host-native). The regs / mem peripherals and the renderer
   all reach this single service to read state. */

class CerfVirtFramebuffer : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t Width()    const { return width_;  }
    uint32_t Height()   const { return height_; }
    uint32_t Bpp()      const { return bpp_;    }
    uint32_t Stride()   const { return width_ * (bpp_ >> 3u); }
    uint32_t SizeBytes()const { return height_ * Stride();    }
    bool     HasContent() const { return any_write_; }

    /* Total host-backed region: primary surface + offscreen video-memory tail
       the driver carves DDraw surfaces from. Single source of truth for the
       backing vector, the mem peripheral's MmioSize, the kFbRegMemSizeTotal
       register, and the GPE-cmd blitter bounds. Computed once in OnReady. */
    uint32_t RegionBytes() const { return region_bytes_; }

    uint8_t*       Bytes()       { return bytes_.data(); }
    const uint8_t* Bytes() const { return bytes_.data(); }
    uint32_t       Capacity() const { return uint32_t(bytes_.size()); }

    void MarkDirty() { any_write_ = true; }

private:
    uint32_t ComputeRegionBytes() const;

    std::vector<uint8_t> bytes_;
    uint32_t width_       = 800;
    uint32_t height_      = 600;
    uint32_t bpp_         = 32;
    uint32_t region_bytes_= 0;
    bool     any_write_   = false;
};
