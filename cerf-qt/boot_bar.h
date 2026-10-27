#pragma once

#include <cerfcore/core/service.h>

#include <cstdint>

namespace cerffrontend {

class BootBar : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static int Height(int dpi);
    void       RenderInto(uint32_t* dib_bgra32, uint32_t width, uint32_t height, int dpi);

private:
    static int Factor(int dpi);
};

}
