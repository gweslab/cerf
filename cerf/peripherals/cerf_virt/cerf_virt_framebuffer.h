#pragma once

#include "../../core/service.h"

#include <cstdint>
#include <vector>

class StateWriter;
class StateReader;

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

    uint32_t RegionBytes() const { return region_bytes_; }

    uint32_t MemBasePa() const;

    uint32_t PrimaryReserveBytes() const { return primary_reserve_; }

    uint8_t*       Bytes()       { return bytes_.data(); }
    const uint8_t* Bytes() const { return bytes_.data(); }
    uint32_t       Capacity() const { return uint32_t(bytes_.size()); }

    void     SetPaletteEntry(uint32_t idx, uint32_t rgb) { if (idx < 256u) palette_[idx] = rgb; }
    uint32_t PaletteEntry(uint32_t idx) const { return idx < 256u ? palette_[idx] : 0u; }
    const uint32_t* Palette() const { return palette_; }

    void MarkDirty() { any_write_ = true; }

    void ClearContentEdge() { any_write_ = false; }

    void ClearContent();

    void ApplyGuestMode(uint32_t w, uint32_t h);

    void ReapplyConfiguredDepth();

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);

private:
    uint32_t MaxPrimaryBytes() const;
    uint64_t PrimaryBytesAt(uint32_t bpp) const;
    uint32_t ComputeRegionBytes() const;
    void     ReservePrimary();

    std::vector<uint8_t> bytes_;
    uint32_t palette_[256] = { 0 };
    uint32_t width_       = 800;
    uint32_t height_      = 600;
    uint32_t bpp_         = 32;
    uint32_t region_bytes_= 0;
    uint32_t primary_reserve_ = 0;
    bool     any_write_   = false;
};
