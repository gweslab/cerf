#pragma once

#include "dpi_scale.h"
#include "painter.h"

#include <cerfcore/core/service.h>

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace cerffrontend {

class HwScreenRenderer : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void RenderInto(uint32_t* dib_bgra32, uint32_t width, uint32_t height, int dpi);
    void SetTextInsets(int left, int top, int right, int bottom);

private:
    void DrawLog(Painter& p, uint32_t width, uint32_t height,
                 const std::vector<std::string>& snapshot);

    std::unique_ptr<OffscreenSurface> bg_;
    uint64_t                          bg_gen_   = ~0ull;
    bool                              bg_valid_ = false;
    int                               dpi_      = kDefaultDpi;
    int                               inset_l_  = 0;
    int                               inset_t_  = 0;
    int                               inset_r_  = 0;
    int                               inset_b_  = 0;
};

}
