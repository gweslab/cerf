#pragma once

#include "cerf_virt_blt_descriptor.h"
#include "cerf_virt_grad_descriptor.h"
#include "../../core/service.h"

#include <cstdint>
#include <vector>

class CerfVirtFramebuffer;
class ArmMmu;

namespace CerfVirt {

class CerfVirtBlitter : public Service {
public:
    using Service::Service;
    bool ShouldRegister() override;
    void OnReady() override;

    bool Execute(const CerfBltDescriptor& d);
    bool ExecuteGradient(const CerfGradDescriptor& g);

private:
    /* One surface resolved for a blit: where its pixels live and how to address
       them. host_base is non-null only for an FB-region PA surface (contiguous
       host backing); a guest-VA surface resolves per-segment through the MMU. */
    struct Surface {
        const CerfBltSurface* desc;
        uint32_t bpp;
        bool     is_va;
        uint8_t* host_base;   /* FB-PA: host pointer to surface byte 0; VA: null */
    };

    bool ResolveSurface(const CerfBltSurface& s, uint32_t bpp, Surface* out);
    uint8_t* PixelPtr(const Surface& s, int32_t x, int32_t y, uint32_t run_bytes,
                      uint32_t* run);
    uint8_t* RotatedPixelPtr(const Surface& s, int32_t x, int32_t y);
    /* Read/write one bpp-byte pixel byte-by-byte when it straddles a 4KB page
       (guest VA is contiguous but the host pages backing it are not). */
    uint32_t ReadStraddlePixel(const Surface& s, int32_t x, int32_t y, uint32_t bpp);
    void     WriteStraddlePixel(const Surface& s, int32_t x, int32_t y,
                                uint32_t bpp, uint32_t value);

    CerfVirtFramebuffer* fb_ = nullptr;
    ArmMmu*              mmu_ = nullptr;
    std::vector<int32_t> sx_lut_;   /* per-dst-col source offset (BLT_STRETCH) */
    std::vector<int32_t> sy_lut_;   /* per-dst-row source offset (BLT_STRETCH) */
};

}  /* namespace CerfVirt */
