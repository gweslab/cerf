#pragma once

#include "../core/service.h"

#include <cstdint>
#include <optional>
#include <utility>

/* RenderInto MUST fill every byte of dib_bgra32[0..w*h-1] — the canvas
   does not pre-clear it and it still holds the renderer's previous frame.
   w/h are the native presented-surface size (HostSizeFor's result), the
   guest-surface DIB — NOT the host window size. */

class FrameRenderer : public Service {
public:
    using Service::Service;
    ~FrameRenderer() override = default;

    virtual bool HasFrame() = 0;

    virtual void RenderInto(uint32_t* dib_bgra32,
                            uint32_t  width,
                            uint32_t  height) = 0;

    /* Translate guest-FB dimensions to the host-window dimensions
       the renderer expects to draw into. Identity by default;
       rotating renderers (e.g. Sa1110LcdRenderer) override to swap. */
    virtual std::pair<uint32_t, uint32_t>
    HostSizeFor(uint32_t fb_w, uint32_t fb_h) const {
        return {fb_w, fb_h};
    }

    /* Optional framebuffer locator for the dev MemoryVisualizer's
       jump-to-framebuffer bookmark. Default nullopt: a renderer that doesn't
       advertise one is simply not bookmarkable; nothing else depends on it. */
    struct FbLayout {
        uint32_t pa;
        uint32_t stride_bytes;
        uint32_t bpp_bits;
        bool     rgb565;
    };
    virtual std::optional<FbLayout> GetFbLayout() { return std::nullopt; }
};
